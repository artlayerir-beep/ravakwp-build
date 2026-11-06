"""Shared primitives for the RavakWP build-engine worker.

Everything here is pure Python 3.10+ stdlib so it can be unit-tested
offline (no SDK, no requests, no Pillow):

* HMAC request/job envelope              — BUILD-ENGINE-SPEC §1
* log scrubber (secrets/base64 masking)  — spec §5 security invariants
* typed BuildError (fa human + en tech)  — spec §2 failure contract
* normalized BuildPayload (job envelope) — spec §1 payload schema
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

__all__ = [
    "ENGINE_VERSION",
    "STAGE_WINDOWS",
    "STAGES",
    "QUEUE_KEY",
    "DEAD_KEY",
    "POLL_PATH",
    "envelope_sign",
    "envelope_verify",
    "sign_job",
    "verify_job",
    "LogScrubber",
    "BuildError",
    "BuildPayload",
    "BuildLog",
    "sha256_file",
    "sha256_bytes",
    "tail",
    "utc_iso",
]

ENGINE_VERSION = "1.0.0"

# Pipeline stages and their progress windows — BUILD-ENGINE-SPEC §2.
STAGE_WINDOWS: dict[str, tuple[int, int]] = {
    "prepare": (0, 10),
    "inject": (10, 20),
    "compile": (20, 60),
    "sign": (60, 80),
    "verify": (80, 90),
    "deliver": (90, 100),
}
STAGES: tuple[str, ...] = tuple(STAGE_WINDOWS)

# WP build-row status for every engine stage (rvk_builds.status column).
STAGE_STATUS: dict[str, str] = {
    "prepare": "preparing",
    "inject": "preparing",
    "compile": "compiling",
    "sign": "signing",
    "verify": "verifying",
    "deliver": "packaging",
}

QUEUE_KEY = "rvk:builds"      # Redis list; jobs consumed with BRPOP
DEAD_KEY = "rvk:builds:dead"  # unparsable/unverifiable jobs land here
POLL_PATH = "internal/poll"   # REST table-queue fallback endpoint


# --------------------------------------------------------------------------
# HMAC envelope (spec §1) — EVERY worker→WP request:
#   X-RVK-Worker: {store_key}
#   X-RVK-Timestamp: unix seconds (server enforces ±5min)
#   X-RVK-Signature: hex(HMAC-SHA256(hmac_key, timestamp + "." + raw_body))
# --------------------------------------------------------------------------

def envelope_sign(hmac_key: str, timestamp: str, body: bytes) -> str:
    """Return the hex signature for *timestamp* over *body*."""
    if not hmac_key:
        raise ValueError("کلید HMAC خالی است / hmac_key must not be empty")
    mac = hmac.new(
        hmac_key.encode("utf-8"),
        timestamp.encode("utf-8") + b"." + (body or b""),
        hashlib.sha256,
    )
    return mac.hexdigest()


def envelope_verify(
    hmac_key: str,
    timestamp: str,
    body: bytes,
    signature: str,
    max_skew: int = 300,
) -> bool:
    """Timing-safe verify with a ±5min window (mirrors WP side)."""
    if not hmac_key or not timestamp or not signature:
        return False
    try:
        ts = int(str(timestamp).strip())
    except ValueError:
        return False
    if abs(time.time() - ts) > max_skew:
        return False
    try:
        expected = envelope_sign(hmac_key, str(timestamp).strip(), body or b"")
    except ValueError:
        return False
    return hmac.compare_digest(expected, str(signature).strip().lower())


def _canonical_job_bytes(job: Mapping[str, Any]) -> bytes:
    return json.dumps(
        job, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_job(job: dict[str, Any], hmac_key: str) -> dict[str, Any]:
    """Attach the transport envelope (``_ts``/``_sig``) to a job payload.

    Used when jobs travel over Redis (the WP BuildDispatcher signs, the
    worker verifies).  REST-polled jobs are protected by the HMAC on the
    poll response transport instead.
    """
    core = {k: v for k, v in job.items() if k not in ("_ts", "_sig")}
    ts = str(int(time.time()))
    signed = dict(core)
    signed["_ts"] = ts
    signed["_sig"] = envelope_sign(hmac_key, ts, _canonical_job_bytes(core))
    return signed


def verify_job(job: Mapping[str, Any], hmac_key: str) -> tuple[bool, str]:
    """Verify a job envelope produced by :func:`sign_job`.

    Returns ``(ok, reason)`` — reason is a human-readable fa message.
    """
    sig = job.get("_sig")
    ts = job.get("_ts")
    if not sig or not ts:
        return False, "پاکت امضا فاقد _ts/_sig است / envelope missing _ts or _sig"
    core = {k: v for k, v in job.items() if k not in ("_ts", "_sig")}
    ok = envelope_verify(hmac_key, str(ts), _canonical_job_bytes(core), str(sig))
    if not ok:
        return False, "امضای payload نامعتبر است / job HMAC signature invalid"
    return True, ""


# --------------------------------------------------------------------------
# Log scrubber (spec §5): masks pass: values, base64 blobs and any secret
# explicitly registered with it, on EVERY log line before callbacks.
# --------------------------------------------------------------------------

_PASS_COLON_RE = re.compile(r"(?i)\bpass\s*:\s*[^\s'\"]+")
_PASS_KV_RE = re.compile(
    r"(?i)\b((?:[\w-]*pass(?:word)?|pwd)\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
# Bearer/JWT-style authority tokens (eyJ…..…)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


class LogScrubber:
    """Stateful scrubber holding the runtime secrets of one build."""

    def __init__(self, extra_secrets: Iterable[str] = ()) -> None:
        self._secrets: list[str] = []
        for secret in extra_secrets:
            self.register(secret)

    def register(self, secret: str | None) -> None:
        """Register one secret value to be replaced with *** everywhere."""
        if secret and len(secret) >= 4 and secret not in self._secrets:
            self._secrets.append(secret)

    def scrub(self, line: str) -> str:
        for secret in self._secrets:
            line = line.replace(secret, "***")
        line = _JWT_RE.sub("***", line)
        line = _PASS_COLON_RE.sub("pass:***", line)
        line = _PASS_KV_RE.sub(lambda m: m.group(1) + "***", line)
        line = _B64_RE.sub("***", line)
        return line

    def scrub_text(self, text: str) -> str:
        return "\n".join(self.scrub(line) for line in (text or "").splitlines())


# --------------------------------------------------------------------------
# Typed error (spec §2): human fa message + en technical detail + log tail
# --------------------------------------------------------------------------

@dataclass
class BuildError(Exception):
    stage: str
    message_fa: str
    message_en: str = ""
    log_tail: str = ""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.human()

    def human(self) -> str:
        head = f"[{self.stage}] {self.message_fa}"
        if self.message_en:
            head += f" — {self.message_en}"
        return head

    def with_tail(self, max_lines: int = 80) -> str:
        body = self.human()
        if self.log_tail:
            body += "\n--- tail " + f"({max_lines} lines max) ---\n" + tail(
                self.log_tail, max_lines
            )
        return body


# --------------------------------------------------------------------------
# Normalized job payload (spec §1)
# --------------------------------------------------------------------------

_ASSET_KEYS = ("app_icon", "splash", "logo", "adaptive_fg", "adaptive_bg")
_TEMPLATE_REF_RE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class BuildPayload:
    build_id: int
    store_key: str
    site_url: str
    wp_rest_url: str
    version_name: str
    version_code: int
    package_name: str
    app_name: str
    min_sdk: int = 24
    target_sdk: int = 34
    style_id: str = "modern_minimal"
    template_ref: str = "android-app-template-v1"
    template_url: str = ""
    assets: dict[str, str] = field(default_factory=dict)
    config_url: str = ""
    keystore: dict[str, Any] = field(default_factory=dict)
    signing: dict[str, str] = field(default_factory=dict)
    gradle_tasks: list[str] = field(
        default_factory=lambda: ["assembleRelease", "bundleRelease"]
    )
    hmac_key: str = ""
    callbacks: dict[str, str] = field(
        default_factory=lambda: {
            "progress": "internal/progress",
            "deliver": "internal/build-callback",
        }
    )
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BuildPayload":
        required = (
            "build_id",
            "store_key",
            "wp_rest_url",
            "package_name",
            "app_name",
        )
        missing = [k for k in required if not str(data.get(k) or "").strip()
                   and not isinstance(data.get(k), int)]
        if missing:
            raise ValueError(
                "فیلدهای الزامی payload موجود نیست: "
                + ", ".join(missing)
                + " / missing required payload fields"
            )
        try:
            build_id = int(data["build_id"])
            version_code = int(data.get("version_code") or 1)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "build_id/version_code باید عدد باشند / must be integers"
            ) from exc

        keystore = dict(data.get("keystore") or {})
        keystore.setdefault("mode", "generate")
        keystore.setdefault("alias", "ravakwp")
        keystore.setdefault("fetch", "")
        if keystore["mode"] not in ("generate", "existing"):
            raise ValueError(
                "keystore.mode فقط generate یا existing / invalid keystore.mode"
            )

        tasks_raw = data.get("gradle") or {}
        tasks = tasks_raw.get("tasks") if isinstance(tasks_raw, dict) else None
        if not tasks:
            tasks = ["assembleRelease", "bundleRelease"]
        gradle_tasks = []
        for task in tasks:
            task = str(task).strip().lstrip(":")
            if task.startswith("app:"):
                task = task[4:]
            if task:
                gradle_tasks.append(task)

        assets_in = data.get("assets") or {}
        assets = {k: str(assets_in.get(k) or "") for k in _ASSET_KEYS}
        # unknown extra asset keys are preserved (worker passes them through)
        for key, value in assets_in.items():
            if key not in assets:
                assets[str(key)] = str(value or "")

        callbacks_in = data.get("callbacks") or {}
        callbacks = {
            "progress": str(callbacks_in.get("progress") or "internal/progress"),
            "deliver": str(callbacks_in.get("deliver") or "internal/build-callback"),
        }

        signing = data.get("signing") or {}
        signing = {
            "ks_pass_b64": str(signing.get("ks_pass_b64") or ""),
            "key_pass_b64": str(signing.get("key_pass_b64") or ""),
        }

        return cls(
            build_id=build_id,
            store_key=str(data["store_key"]).strip(),
            site_url=str(data.get("site_url") or "").strip(),
            wp_rest_url=str(data["wp_rest_url"]).strip().rstrip("/"),
            version_name=str(data.get("version_name") or "1.0.0"),
            version_code=version_code,
            package_name=str(data["package_name"]).strip(),
            app_name=str(data["app_name"]).strip(),
            min_sdk=int(data.get("min_sdk") or 24),
            target_sdk=int(data.get("target_sdk") or 34),
            style_id=str(data.get("style_id") or "modern_minimal"),
            template_ref=_TEMPLATE_REF_RE.sub(
                "-", str(data.get("template_ref") or "android-app-template-v1")
            ),
            template_url=str(data.get("template_url") or "").strip(),
            assets=assets,
            config_url=str(data.get("config_url") or "").strip(),
            keystore=keystore,
            signing=signing,
            gradle_tasks=gradle_tasks,
            hmac_key=str(data.get("hmac_key") or ""),
            callbacks=callbacks,
            raw=dict(data),
        )

    # -- secrets ------------------------------------------------------------

    @staticmethod
    def _b64(value: str, label: str) -> str:
        if not value:
            return ""
        try:
            return base64.b64decode(value, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(
                f"مقدار base64 فیلد {label} نامعتبر است / invalid base64 in {label}"
            ) from exc

    @property
    def ks_pass(self) -> str:
        return self._b64(self.signing.get("ks_pass_b64", ""), "signing.ks_pass_b64")

    @property
    def key_pass(self) -> str:
        return self._b64(self.signing.get("key_pass_b64", ""), "signing.key_pass_b64")

    def callback_path(self, kind: str) -> str:
        return (self.callbacks.get(kind) or "").strip().lstrip("/")


# --------------------------------------------------------------------------
# Build log collector (scrubbed, bounded, chunked for progress callbacks)
# --------------------------------------------------------------------------

class BuildLog:
    """Thread-safe, size-capped, scrubbed log for one build."""

    def __init__(
        self,
        scrubber: LogScrubber,
        *,
        max_lines: int = 2000,
        tee_path: Path | None = None,
    ) -> None:
        self._scrubber = scrubber
        self._lines: deque[str] = deque(maxlen=max_lines)
        self._lock = __import__("threading").Lock()
        self._mark = 0  # index (mod deque) of the last chunk sent
        self._tee_path = tee_path
        if tee_path is not None:
            tee_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, line: str) -> None:
        line = line.rstrip("\r\n")
        with self._lock:
            self._lines.append(self._scrubber.scrub(line))
        if self._tee_path is not None:
            try:
                with open(self._tee_path, "a", encoding="utf-8") as fh:
                    fh.write(self._scrubber.scrub(line) + "\n")
            except OSError:
                pass  # never crash a build on a log write

    def tail(self, n: int = 80) -> str:
        with self._lock:
            return "\n".join(list(self._lines)[-n:])

    def chunk(self, max_chars: int = 8000) -> str:
        """Lines appended since the previous chunk() call (bounded)."""
        with self._lock:
            chunked = list(self._lines)[self._mark:]
            self._mark = len(self._lines)
        text = "\n".join(chunked)
        return text[-max_chars:]

    def all_text(self) -> str:
        with self._lock:
            return "\n".join(self._lines)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 512), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tail(text: str, n: int = 80) -> str:
    lines = (text or "").splitlines()
    return "\n".join(lines[-n:])


def utc_iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))
