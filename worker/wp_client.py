"""WordPress REST client for the RavakWP build engine worker.

Implements the worker→WP protocol from BUILD-ENGINE-SPEC §1/§3:

* every request carries the HMAC envelope headers
  ``X-RVK-Worker`` / ``X-RVK-Timestamp`` / ``X-RVK-Signature`` where the
  signature is ``hex(HMAC-SHA256(hmac_key, timestamp + "." + raw_body))``.
* for ``multipart/form-data`` uploads (deliver) the signature covers the
  JSON meta document (the ``meta`` form field), which is the canonical
  request body for HMAC purposes; flat duplicates of the meta fields are
  also sent for reader convenience.
* TLS verification is ALWAYS on (spec §5). Retries (3, exponential
  backoff) apply to network errors and 5xx responses.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if __package__:  # dual-mode import: package (tests) or script (container)
    from . import common
else:  # pragma: no cover
    import common

__all__ = ["WPClient"]

_SAFE_REF_RE = re.compile(r"[^A-Za-z0-9._-]")


class WPClient:
    """Signed REST client bound to one build's tenant (store)."""

    def __init__(
        self,
        payload: common.BuildPayload,
        *,
        fallback_hmac_key: str = "",
        timeout: float = 60.0,
    ) -> None:
        self.payload = payload
        self.rest_url = payload.wp_rest_url.rstrip("/")
        self.store_key = payload.store_key
        self.hmac_key = payload.hmac_key or fallback_hmac_key
        if not self.hmac_key:
            raise ValueError(
                "کلید HMAC برای این ساخت یافت نشد (payload.hmac_key یا WP_HMAC_KEY) "
                "/ no HMAC key for this build"
            )
        self.timeout = timeout

        # --- session with retry/backoff on 5xx + network errors -----------
        self.session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=8)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.verify = True  # TLS verification ON, always (spec §5)
        self.session.headers["User-Agent"] = (
            f"ravakwp-build-engine/{common.ENGINE_VERSION}"
        )

    # ------------------------------------------------------------------
    # Envelope plumbing
    # ------------------------------------------------------------------

    def _envelope_headers(self, body: bytes) -> dict[str, str]:
        ts = str(int(time.time()))
        return {
            "X-RVK-Worker": self.store_key,
            "X-RVK-Timestamp": ts,
            "X-RVK-Signature": common.envelope_sign(self.hmac_key, ts, body),
        }

    def _url(self, path: str) -> str:
        return f"{self.rest_url}/{str(path).lstrip('/')}"

    # ------------------------------------------------------------------
    # Signed POST helpers
    # ------------------------------------------------------------------

    def _signed_post_json(self, path: str, body_obj: Mapping[str, Any]) -> requests.Response:
        body = json.dumps(dict(body_obj), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = self._envelope_headers(body)
        headers["Content-Type"] = "application/json; charset=utf-8"
        resp = self.session.post(self._url(path), data=body, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        return resp

    def _signed_post_multipart(
        self,
        path: str,
        meta: Mapping[str, Any],
        files: dict[str, Any],
        flat: Mapping[str, str] | None = None,
    ) -> requests.Response:
        meta_json = json.dumps(dict(meta), ensure_ascii=False, separators=(",", ":"))
        body = meta_json.encode("utf-8")  # canonical body covered by HMAC
        headers = self._envelope_headers(body)
        data: dict[str, str] = {"meta": meta_json}
        if flat:
            data.update(flat)
        resp = self.session.post(
            self._url(path), data=data, files=files, headers=headers, timeout=max(self.timeout, 300)
        )
        resp.raise_for_status()
        return resp

    def _signed_get(self, url: str, *, stream: bool = False, timeout: float | None = None) -> requests.Response:
        headers = self._envelope_headers(b"")  # GET: signature over empty body
        resp = self.session.get(url, headers=headers, stream=stream, timeout=timeout or self.timeout)
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # Protocol endpoints (spec §3)
    # ------------------------------------------------------------------

    def poll(self, worker_id: str) -> dict[str, Any] | None:
        """Claim one pending build from the table queue.

        Returns the job payload dict, or ``None`` when the queue is empty
        (HTTP 204 / empty body / non-JSON body are all treated as empty).
        """
        try:
            resp = self._signed_post_json(common.POLL_PATH, {"claim": 1, "worker_id": worker_id})
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            if code in (204, 404):
                return None
            raise
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            job = resp.json()
        except ValueError:
            return None
        return job if isinstance(job, dict) and job else None

    def progress(
        self,
        build_id: int,
        status: str,
        stage_detail: str,
        progress_pct: int,
        log_chunk: str = "",
        error: str | None = None,
    ) -> bool:
        """Best-effort progress webhook — a failed callback never crashes a build."""
        body = {
            "build_id": int(build_id),
            "status": status,
            "stage_detail": str(stage_detail)[:120],
            "progress": max(0, min(100, int(progress_pct))),
        }
        if log_chunk:
            body["log"] = log_chunk
        if error:
            body["error"] = error
        try:
            self._signed_post_json(self.payload.callback_path("progress"), body)
            return True
        except Exception as exc:  # noqa: BLE001 — progress must never fail a build
            print(f"[wp_client] progress callback failed: {exc}", flush=True)
            return False

    def deliver(
        self,
        build_id: int,
        files: Mapping[str, Path],
        certs: Mapping[str, str],
        sizes: Mapping[str, int],
        checksums: Mapping[str, str],
        gradle_version: str,
        status: str = "completed",
    ) -> dict[str, Any]:
        """Upload artifacts (multipart) to ``internal/build-callback``."""
        file_handles: dict[str, Any] = {}
        try:
            for key in ("apk", "aab"):
                path = files.get(key)
                if not path or not Path(path).exists():
                    continue
                mime = (
                    "application/vnd.android.package-archive"
                    if key == "apk"
                    else "application/octet-stream"
                )
                fh = open(path, "rb")
                file_handles[key] = (Path(path).name, fh, mime)
            if not file_handles:
                raise ValueError(
                    "هیچ فایل خروجی (APK/AAB) برای ارسال وجود ندارد / no artifacts to deliver"
                )
            meta = {
                "build_id": int(build_id),
                "status": status,
                "certs": dict(certs),
                "sizes": {k: int(v) for k, v in sizes.items()},
                "checksums": dict(checksums),
                "gradle_version": gradle_version,
                "worker": f"{os.uname().nodename}",
            }
            flat = {
                "build_id": str(int(build_id)),
                "status": status,
                "certs": json.dumps(dict(certs)),
                "gradle_version": gradle_version,
            }
            resp = self._signed_post_multipart(self.payload.callback_path("deliver"), meta, file_handles, flat)
            try:
                return resp.json()
            except ValueError:
                return {}
        finally:
            for handle in file_handles.values():
                try:
                    handle[1].close()
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------
    # Signed GET fetchers
    # ------------------------------------------------------------------

    def fetch_config(self) -> dict[str, Any]:
        """Download the full app-config.json (no secrets, spec §1)."""
        url = self.payload.config_url
        if not url:
            raise ValueError(
                "آدرس config_url در payload موجود نیست / payload.config_url is empty"
            )
        resp = self._signed_get(url)
        try:
            cfg = resp.json()
        except ValueError as exc:
            raise ValueError(
                f"پاسخ config_url معتبر JSON نیست / config_url returned non-JSON ({url})"
            ) from exc
        if not isinstance(cfg, dict):
            raise ValueError("config_url باید یک شی JSON باشد / config_url must be a JSON object")
        return cfg

    def fetch_keystore(self) -> bytes:
        """Fetch the keystore file from an HMAC-protected endpoint."""
        fetch_path = str((self.payload.keystore or {}).get("fetch") or "").strip()
        if not fetch_path:
            raise ValueError(
                "keystore.fetch در payload موجود نیست / payload.keystore.fetch is empty"
            )
        url = fetch_path if fetch_path.startswith("http") else self._url(fetch_path)
        data = self._signed_get(url).content
        if len(data) < 64 or not data.startswith(b"\x30\x82"):
            raise ValueError(
                "فایل دریافتی شبیه PKCS12 نیست / fetched keystore is not PKCS12 (bad magic)"
            )
        return data

    def fetch_firebase(self) -> bytes | None:
        """Fetch google-services.json; ``None`` when the store has none."""
        url = self._url("internal/firebase")
        try:
            resp = self._signed_get(url)
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return None
            raise
        if not resp.content:
            return None
        return resp.content

    def download_assets(self, assets: Mapping[str, str]) -> dict[str, bytes]:
        """Download brand asset images (icon/splash/logo/adaptive_*)."""
        out: dict[str, bytes] = {}
        for key, url in assets.items():
            if not url or not str(url).strip():
                continue
            url = str(url).strip()
            try:
                resp = self.session.get(url, timeout=120, stream=False)
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise ValueError(
                    f"دانلود فایل {key} ناموفق بود / asset download failed for '{key}': {exc}"
                ) from exc
            ctype = resp.headers.get("Content-Type", "")
            if ctype and not ctype.startswith(("image/", "application/octet-stream")):
                raise ValueError(
                    f"محتوای {key} تصویر نیست ({ctype}) / asset '{key}' is not an image"
                )
            out[key] = resp.content
        return out

    # ------------------------------------------------------------------
    # Template fetch with cross-process cache (spec §1 template_ref)
    # ------------------------------------------------------------------

    _TPL_LOCK = threading.Lock()  # in-process lock (threads share the cache)

    def fetch_template(self, cache_dir: str | os.PathLike[str] | None = None) -> Path:
        """Return a cached template zip path for ``payload.template_ref``.

        Source priority:
          1. ``TEMPLATE_ZIP`` env — pre-packaged zip on the worker host
          2. ``TEMPLATE_DIR``  env — a checkout of the android-app project
             (zipped on the fly into the cache)
          3. ``payload.template_url`` — signed GET from the WP plugin
             (``internal/template``)

        The zip is cached under ``{cache_dir}/{template_ref}.zip``; both a
        threading lock and an flock protect against concurrent builds.
        """
        ref = _SAFE_REF_RE.sub("-", self.payload.template_ref or "default") or "default"
        cache = Path(cache_dir or os.environ.get("RVK_CACHE_DIR", "/var/lib/ravakwp/templates"))
        target = cache / f"{ref}.zip"

        with WPClient._TPL_LOCK:
            cache.mkdir(parents=True, exist_ok=True)
            lock_path = cache / f".{ref}.lock"
            with open(lock_path, "w") as lockfh:
                fcntl.flock(lockfh.fileno(), fcntl.LOCK_EX)
                try:
                    if self._cache_valid(target):
                        return target
                    tmp = cache / f"{ref}.zip.{os.getpid()}.tmp"
                    source_used = self._materialize_template(tmp)
                    if tmp.stat().st_size < 512:
                        tmp.unlink(missing_ok=True)
                        raise ValueError(
                            f"قالب دریافتی از «{source_used}» خالی است / template from "
                            f"'{source_used}' is empty"
                        )
                    os.replace(tmp, target)  # atomic on same filesystem
                    return target
                finally:
                    fcntl.flock(lockfh.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _cache_valid(target: Path) -> bool:
        try:
            return target.is_file() and target.stat().st_size > 512 and zipfile.is_zipfile(target)
        except OSError:
            return False

    def _materialize_template(self, tmp: Path) -> str:
        env_zip = os.environ.get("TEMPLATE_ZIP", "").strip()
        env_dir = os.environ.get("TEMPLATE_DIR", "").strip()
        if env_zip:
            src = Path(env_zip)
            if not src.is_file():
                raise ValueError(f"TEMPLATE_ZIP وجود ندارد / TEMPLATE_ZIP not found: {src}")
            shutil.copyfile(src, tmp)
            return str(src)
        if env_dir:
            src = Path(env_dir)
            if not src.is_dir():
                raise ValueError(f"TEMPLATE_DIR وجود ندارد / TEMPLATE_DIR not found: {src}")
            _zip_directory(src, tmp)
            return str(src)
        if self.payload.template_url:
            resp = self._signed_get(self.payload.template_url, stream=True, timeout=300)
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        fh.write(chunk)
            return self.payload.template_url
        raise ValueError(
            "منبع قالب یافت نشد — TEMPLATE_ZIP/TEMPLATE_DIR یا payload.template_url لازم است "
            "/ no template source (set TEMPLATE_ZIP, TEMPLATE_DIR or payload.template_url)"
        )


def _zip_directory(src: Path, dst_zip: Path) -> None:
    """Zip the *contents* of a directory (template checkout) into dst_zip."""
    with zipfile.ZipFile(dst_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(src).as_posix()
            if any(part in (".gradle", "build") for part in path.parts) or rel.endswith(
                (".iml", "local.properties")
            ):
                continue  # keep the template clean of local artifacts
            zf.write(path, arcname=rel)
