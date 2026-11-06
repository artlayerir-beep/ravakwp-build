"""Build pipeline — stages exactly per BUILD-ENGINE-SPEC §2.

    prepare   0-10%   workspace, template, brand assets → Android resources
    inject   10-20%   app-config.json, gradle -P props, google-services.json,
                      strings.xml (fa/en) + keystore materialization (*)
    compile  20-60%   gradle :app:assembleRelease :app:bundleRelease --no-daemon
    sign     60-80%   zipalign + apksigner for the APK
    verify   80-90%   apksigner verify --print-certs, zip/aab magic, sizes
    deliver  90-100%  multipart upload + sha256 checksums + keystore shred

(*) Deviation note (documented, binding): the spec table puts keystore
    handling in the sign stage, but the Android template contract signs the
    AAB at gradle time through the RVK_KS_PATH / RVK_KS_PASS / RVK_KEY_ALIAS
    / RVK_KEY_PASS environment variables — so the keystore MUST exist before
    the compile stage starts. ensure_keystore therefore runs at the end of
    `inject` (same 10-20% window); the sign stage only zipaligns + signs the
    APK with apksigner.

Every stage is wrapped: any exception becomes a typed common.BuildError
(fa human message + en technical detail + log tail) and the failure
callback (status=failed, error + tail 80) is sent before returning.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

if __package__:  # dual-mode import: package (tests) or script (container)
    from . import common, injector, signer, wp_client
else:  # pragma: no cover
    import common
    import injector
    import signer
    import wp_client

__all__ = ["PipelineConfig", "BuildPipeline", "gradle_failure_summary"]

_MIN_GRADLE_LOG_PROGRESS = 15.0          # seconds between progress callbacks
_COMPILE_DURATION_ESTIMATE = 1800.0      # used only to interpolate 20→58%


@dataclass
class PipelineConfig:
    android_home: str = ""
    gradle_bin: str = "gradle"
    workspaces_root: Path = Path("/var/lib/ravakwp/workspaces")
    cache_dir: Path = Path("/var/lib/ravakwp/templates")
    gradle_home: Path = Path("/var/lib/ravakwp/gradle-home")
    on_heartbeat: Callable[[], None] | None = None


class BuildPipeline:
    """Runs one build end-to-end; returns a result dict, never raises."""

    def __init__(
        self,
        payload: common.BuildPayload,
        client: wp_client.WPClient,
        config: PipelineConfig,
        *,
        log: Any | None = None,       # object with append/tail/chunk/all_text
        scrubber: common.LogScrubber | None = None,
    ) -> None:
        self.payload = payload
        self.client = client
        self.config = config
        self.scrubber = scrubber or common.LogScrubber()
        self.scrubber.register(payload.hmac_key)
        self.log = log or _NullLog()
        self.gradle_version = "unknown"
        self.workspace: injector.WorkspacePaths | None = None
        self.src: Path | None = None
        self.gradle_props: dict[str, str] = {}
        self.keystore: signer.KeystoreInfo | None = None
        self.certs: dict[str, str] = {}
        self.artifacts: dict[str, Path] = {}
        self.started_at = time.time()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "build_id": self.payload.build_id,
            "status": "completed",
            "artifacts": {},
            "certs": {},
            "checksums": {},
            "sizes": {},
            "gradle_version": self.gradle_version,
            "error": None,
        }
        stage = common.STAGES[0]
        try:
            for stage in common.STAGES:
                self._set_stage(stage)
                getattr(self, f"_stage_{stage}")()
                self.log.append(f"✔ stage {stage} finished")
        except common.BuildError as exc:
            result["status"] = "failed"
            result["error"] = exc.human()
            self._fail(exc)
        except Exception as exc:  # noqa: BLE001 — last-resort wrapper
            wrapped = common.BuildError(
                stage,
                f"خطای غیرمنتظره در مرحله {stage} رخ داد",
                f"{type(exc).__name__}: {exc}",
                self.log.tail(80) if hasattr(self.log, "tail") else "",
            )
            result["status"] = "failed"
            result["error"] = wrapped.human()
            self._fail(wrapped)
        finally:
            result["gradle_version"] = self.gradle_version
            result["certs"] = dict(self.certs)
            result["artifacts"] = {k: str(v) for k, v in self.artifacts.items()}
            for key in ("apk", "aab"):
                path = self.artifacts.get(key)
                if path and Path(path).exists():
                    result["sizes"][key] = Path(path).stat().st_size
                    result["checksums"][f"{key}_sha256"] = common.sha256_file(path)
            self._write_meta(result)
            self._cleanup_secrets()
        return result

    # ------------------------------------------------------------------
    # Stage: prepare (0-10%)
    # ------------------------------------------------------------------

    def _stage_prepare(self) -> None:
        p = self.payload
        self._report("prepare", 0.02, "ایجاد فضای کاری")
        self.workspace = injector.prepare_workspace(
            self.config.workspaces_root, p.store_key, p.build_id
        )
        self.log.append(f"workspace: {self.workspace.root}")

        self._report("prepare", 0.04, "دریافت قالب اندروید")
        template_zip = self.client.fetch_template(self.config.cache_dir)
        self.log.append(f"template zip: {template_zip} (ref={p.template_ref})")

        self._report("prepare", 0.06, "باز کردن قالب")
        self.src = injector.extract_template(template_zip, self.workspace.tmp / "template")
        self.workspace.src = self.src
        self.log.append(f"template extracted: {self.src}")

        self._report("prepare", 0.07, "دانلود فایل‌های گرافیکی")
        assets = self.client.download_assets(p.assets)
        self.log.append(f"assets downloaded: {sorted(assets)}")

        self._report("prepare", 0.09, "ساخت آیکون‌ها و اسپلش")
        written = injector.generate_icons(assets, self.src, p)
        self.log.append(f"resources generated: {len(written)} files")

    # ------------------------------------------------------------------
    # Stage: inject (10-20%)
    # ------------------------------------------------------------------

    def _stage_inject(self) -> None:
        p = self.payload
        self._report("inject", 0.12, "دریافت و نوشتن app-config.json")
        raw_config: dict[str, Any] = {}
        if p.config_url:
            raw_config = self.client.fetch_config()
        cfg = injector.build_app_config(p, raw_config)
        written_cfg = injector.inject_config(self.src, cfg)  # type: ignore[arg-type]
        self.log.append(f"app-config.json written: {written_cfg}")

        self._report("inject", 0.15, "تزریق پارامترهای گریدل")
        extra = {"rvkStyleId": p.style_id} if p.style_id else None
        self.gradle_props = injector.gradle_props(self.src, p, extra)  # type: ignore[arg-type]
        self.log.append("gradle.properties: " + ", ".join(self.gradle_props))

        self._report("inject", 0.17, "بررسی پیکربندی Firebase")
        firebase = self.client.fetch_firebase()
        if firebase:
            fb_path = injector.place_firebase(self.src, firebase)  # type: ignore[arg-type]
            self.log.append(f"google-services.json placed: {fb_path}")
        else:
            self.log.append("no firebase config for this store — FCM disabled in this build")

        self._report("inject", 0.18, "بومی‌سازی نام اپلیکیشن")
        values, values_en = injector.localize_app_name(
            self.src, p.app_name, str(cfg.get("app_name_en") or "")  # type: ignore[arg-type]
        )
        self.log.append(f"app_name localized: {values} + {values_en}")

        # keystore BEFORE compile: the template signs the AAB at gradle time
        # via RVK_* env vars (see module docstring deviation note).
        self._report("inject", 0.19, "آماده‌سازی کی‌استور امضا")
        ks_dir = self.workspace.tmp / "keystore" if self.workspace else self.payload.store_key
        self.keystore = signer.ensure_keystore(ks_dir, p, self.client)
        self.scrubber.register(self.keystore.store_pass)
        self.scrubber.register(self.keystore.key_pass)
        self.log.append(
            f"keystore ready (mode={self.keystore.mode}, alias={self.keystore.alias})"
        )

    # ------------------------------------------------------------------
    # Stage: compile (20-60%)
    # ------------------------------------------------------------------

    def _stage_compile(self) -> None:
        p = self.payload
        self._detect_gradle_version()
        gradle_bin = shutil.which(self.config.gradle_bin) or self.config.gradle_bin
        tasks = [f":app:{t}" for t in p.gradle_tasks]
        prop_args = [f"-P{k}={v}" for k, v in self.gradle_props.items()]
        argv = [gradle_bin, "--no-daemon", "--stacktrace", *prop_args, *tasks]
        self.log.append(signer.mask_cmd(argv, *self.scrubber._secrets))

        env = dict(os.environ)
        env.setdefault("JAVA_HOME", signer._java_home())
        env["ANDROID_HOME"] = self.config.android_home or env.get("ANDROID_HOME", "/opt/android-sdk")
        env["ANDROID_SDK_ROOT"] = env["ANDROID_HOME"]
        env["GRADLE_USER_HOME"] = str(self.config.gradle_home)
        if self.keystore:
            env.update(signer.env_for_gradle(self.keystore))

        self._report("compile", 0.0, "اجرای Gradle")
        started = time.time()
        proc = subprocess.Popen(
            argv, cwd=str(self.src), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", env=env, bufsize=1,
        )
        stop = threading.Event()
        timer = threading.Thread(target=self._compile_timer, args=(proc, stop, started), daemon=True)
        timer.start()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                self.log.append(line)
        finally:
            stop.set()
            timer.join(timeout=3)
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:  # pragma: no cover
                proc.kill()
                proc.wait()
        elapsed = time.time() - started
        self.log.append(f"gradle exit code {proc.returncode} after {elapsed:.0f}s")

        if proc.returncode != 0:
            full = self.log.all_text() if hasattr(self.log, "all_text") else ""
            raise common.BuildError(
                "compile",
                "کامپایل Gradle ناموفق بود — جزئیات در لاگ ساخت",
                f"gradle exit code {proc.returncode}",
                gradle_failure_summary(full),
            )

    def _compile_timer(self, proc: subprocess.Popen, stop: threading.Event, started: float) -> None:
        """Every 15s: interpolated progress + log chunk callback (spec §2)."""
        while not stop.wait(_MIN_GRADLE_LOG_PROGRESS):
            if self.config.on_heartbeat:
                self.config.on_heartbeat()
            if proc.poll() is not None:
                return
            fraction = min(1.0, (time.time() - started) / _COMPILE_DURATION_ESTIMATE)
            try:
                chunk = self.log.chunk() if hasattr(self.log, "chunk") else ""
            except Exception:  # noqa: BLE001
                chunk = ""
            self._report("compile", 0.98 * fraction, "کامپایل در جریان است…", log_chunk=chunk)

    def _detect_gradle_version(self) -> None:
        gradle_bin = shutil.which(self.config.gradle_bin) or self.config.gradle_bin
        try:
            proc = subprocess.run([gradle_bin, "--version"], capture_output=True,
                                  text=True, timeout=60)
            m = re.search(r"^Gradle (\d+[.\d]*)", proc.stdout or "", re.MULTILINE)
            if m:
                self.gradle_version = m.group(1)
        except Exception:  # noqa: BLE001 — version is informational
            pass
        self.log.append(f"gradle version: {self.gradle_version}")

    # ------------------------------------------------------------------
    # Stage: sign (60-80%)
    # ------------------------------------------------------------------

    def _stage_sign(self) -> None:
        p = self.payload
        assert self.src is not None and self.workspace is not None
        apk = _find_apk(self.src)
        aab = _find_aab(self.src)

        if apk is None and "assembleRelease" in p.gradle_tasks:
            raise common.BuildError(
                "sign",
                "فایل APK خروجی یافت نشد — کامپایل خروجی مورد انتظار تولید نکرد",
                "no APK under app/build/outputs/apk/release",
                self.log.tail(40),
            )
        if apk is None and aab is None:
            raise common.BuildError(
                "sign", "هیچ خروجی کامپایل (APK/AAB) یافت نشد",
                "no APK or AAB artifacts found", self.log.tail(40),
            )

        if apk is not None:
            self._report("sign", 0.1, "هم‌ترازسازی و امضای APK")
            out_apk = self.workspace.root / "app-release-signed.apk"
            signer.sign_apk(self.config.android_home, apk, self.keystore, out_apk)  # type: ignore[arg-type]
            self.artifacts["apk"] = out_apk
            self.log.append(f"APK signed: {out_apk}")
        else:
            self.log.append("no assembleRelease task — skipping APK signing")

        if aab is not None:
            self._report("sign", 0.7, "کپی AAB امضاشده توسط Gradle")
            out_aab = self.workspace.root / "app-release.aab"
            shutil.copyfile(aab, out_aab)
            self.artifacts["aab"] = out_aab
            self.log.append(f"AAB (gradle-signed via RVK_* env): {out_aab}")

    # ------------------------------------------------------------------
    # Stage: verify (80-90%)
    # ------------------------------------------------------------------

    def _stage_verify(self) -> None:
        self._report("verify", 0.1, "بررسی امضای دیجیتال")
        apk = self.artifacts.get("apk")
        aab = self.artifacts.get("aab")

        if apk is not None:
            if not signer.zip_magic(apk):
                raise common.BuildError(
                    "verify", "فایل APK معتبر نیست (امضای PKZIP یافت نشد)",
                    "bad zip magic on signed APK", self.log.tail(40),
                )
            self.certs = signer.verify_apk(self.config.android_home, apk)  # type: ignore[arg-type]
            self.log.append(
                "apk certs: sha1=" + self.certs.get("sha1", "?")[:8] + "… sha256="
                + self.certs.get("sha256", "?")[:12] + "…"
            )

        if aab is not None:
            if not signer.zip_magic(aab):
                raise common.BuildError(
                    "verify", "فایل AAB معتبر نیست (امضای PKZIP یافت نشد)",
                    "bad zip magic on AAB", self.log.tail(40),
                )
            if not signer.check_aab(aab):
                raise common.BuildError(
                    "verify", "ساختار AAB نامعتبر است (base/manifest یافت نشد)",
                    "AAB missing base/manifest/AndroidManifest.xml", self.log.tail(40),
                )
            self.log.append("AAB structure verified (base/manifest present)")

        warnings = signer.size_sanity(apk, aab)
        for warning in warnings:
            self.log.append("WARN: " + warning)

    # ------------------------------------------------------------------
    # Stage: deliver (90-100%)
    # ------------------------------------------------------------------

    def _stage_deliver(self) -> None:
        self._report("deliver", 0.1, "محاسبه checksum و ارسال به وردپرس")
        sizes = {k: Path(v).stat().st_size for k, v in self.artifacts.items()}
        checksums = {f"{k}_sha256": common.sha256_file(v) for k, v in self.artifacts.items()}
        self.client.deliver(
            self.payload.build_id,
            files=self.artifacts,
            certs=self.certs,
            sizes=sizes,
            checksums=checksums,
            gradle_version=self.gradle_version,
            status="completed",
        )
        self.log.append(
            "delivered: " + ", ".join(
                f"{k}={sizes[k]/(1024*1024):.1f}MB" for k in sorted(sizes)
            )
        )
        self._report("deliver", 1.0, "ساخت کامل شد", status="completed")

    # ------------------------------------------------------------------
    # Progress / failure plumbing
    # ------------------------------------------------------------------

    def _set_stage(self, stage: str) -> None:
        self._current_stage = stage

    def _pct(self, stage: str, fraction: float) -> int:
        lo, hi = common.STAGE_WINDOWS[stage]
        fraction = max(0.0, min(1.0, fraction))
        return int(lo + (hi - lo) * fraction)

    def _report(
        self,
        stage: str,
        fraction: float,
        detail: str,
        *,
        log_chunk: str = "",
        status: str | None = None,
    ) -> None:
        if self.config.on_heartbeat:
            self.config.on_heartbeat()
        pct = self._pct(stage, fraction)
        status = status or common.STAGE_STATUS.get(stage, "preparing")
        self.log.append(f"[{stage} {pct}%] {detail}")
        self.client.progress(
            self.payload.build_id, status, detail, pct,
            log_chunk=log_chunk or (self.log.chunk() if hasattr(self.log, "chunk") else ""),
        )

    def _fail(self, exc: common.BuildError) -> None:
        self.log.append(f"✖ FAILURE in {exc.stage}: {exc.message_fa} / {exc.message_en}")
        window_start = common.STAGE_WINDOWS.get(exc.stage, (0, 0))[0]
        self.client.progress(
            self.payload.build_id,
            "failed",
            exc.stage,
            window_start,
            log_chunk=common.tail(exc.log_tail, 80) or self.log.tail(80),
            error=exc.with_tail(80),
        )

    def _write_meta(self, result: Mapping[str, Any]) -> None:
        if self.workspace is None:
            return
        meta = {
            "build_id": self.payload.build_id,
            "store_key": self.payload.store_key,
            "package_name": self.payload.package_name,
            "version_name": self.payload.version_name,
            "version_code": self.payload.version_code,
            "template_ref": self.payload.template_ref,
            "status": result.get("status"),
            "error": result.get("error"),
            "certs": result.get("certs", {}),
            "sizes": result.get("sizes", {}),
            "checksums": result.get("checksums", {}),
            "gradle_version": self.gradle_version,
            "engine_version": common.ENGINE_VERSION,
            "started_at": common.utc_iso(self.started_at),
            "finished_at": common.utc_iso(),
            "workspace": str(self.workspace.root),
        }
        try:
            (self.workspace.root / "meta.json").write_text(
                json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
        except OSError as exc:  # pragma: no cover
            self.log.append(f"WARN: meta.json write failed: {exc}")

    def _cleanup_secrets(self) -> None:
        """Shred transient keystore material (spec §2/§5) — runs on success
        AND failure; the rest of the workspace is kept for 24h debugging."""
        candidates: list[Path] = []
        if self.keystore is not None:
            candidates.append(self.keystore.path)
        if self.workspace is not None:
            ks_dir = self.workspace.tmp / "keystore"
            if ks_dir.is_dir():
                candidates.extend(ks_dir.iterdir())
        for path in candidates:
            if path and path.exists():
                signer.shred_file(path)
                self.log.append(f"shredded: {path.name}")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _find_apk(src: Path) -> Path | None:
    apk_dir = Path(src) / "app" / "build" / "outputs" / "apk" / "release"
    if not apk_dir.is_dir():
        return None
    preferred = ["app-release-unsigned.apk", "app-release.apk"]
    for name in preferred:
        if (apk_dir / name).exists():
            return apk_dir / name
    apks = sorted(apk_dir.glob("*.apk"), key=lambda p: p.stat().st_mtime, reverse=True)
    return apks[0] if apks else None


def _find_aab(src: Path) -> Path | None:
    aab_dir = Path(src) / "app" / "build" / "outputs" / "bundle" / "release"
    if not aab_dir.is_dir():
        return None
    aabs = sorted(aab_dir.glob("*.aab"), key=lambda p: p.stat().st_mtime, reverse=True)
    return aabs[0] if aabs else None


def gradle_failure_summary(text: str, max_lines: int = 15, tail_lines: int = 120) -> str:
    """Extract the ``FAILURE: Build failed`` block; fallback to last N lines."""
    lines = (text or "").splitlines()
    for idx, line in enumerate(lines):
        if line.strip().startswith("FAILURE: Build failed"):
            return "\n".join(lines[idx : idx + max_lines])
    return "\n".join(lines[-tail_lines:])


class _NullLog:
    """Silent log backend when the worker does not provide one."""

    def append(self, line: str) -> None:
        pass

    def tail(self, n: int = 80) -> str:
        return ""

    def chunk(self, max_chars: int = 8000) -> str:
        return ""

    def all_text(self) -> str:
        return ""
