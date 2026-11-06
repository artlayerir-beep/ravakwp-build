"""Signing + verification stage helpers (BUILD-ENGINE-SPEC §2 sign/verify).

Secrets handling (spec §5 invariants):

* keystore passwords exist ONLY in the memory of the build process and in
  transient, 0700 files under the build workspace tmp dir.
* ``keytool`` gets its arguments through an ``@argfile`` (passwords never
  appear in ``ps`` output); the argfile is shredded after use.
* ``apksigner`` reads passes through ``--ks-pass env:VAR`` references so
  the secrets stay in the process environment, never in argv.
* every command line is logged through the mask helper before it reaches
  the build log, and the log scrubber re-masks anything that slips through.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

if __package__:  # dual-mode import: package (tests) or script (container)
    from . import common
else:  # pragma: no cover
    import common

__all__ = [
    "KeystoreInfo",
    "ensure_keystore",
    "env_for_gradle",
    "find_build_tools",
    "zipalign",
    "sign_apk",
    "verify_apk",
    "zip_magic",
    "check_aab",
    "size_sanity",
    "shred_file",
    "mask_cmd",
]

_KEYTOOL_TIMEOUT = 120
_APKSIGNER_TIMEOUT = 300


@dataclass
class KeystoreInfo:
    path: Path
    alias: str
    store_pass: str
    key_pass: str
    mode: str  # generate | existing


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _java_home() -> str:
    return os.environ.get("JAVA_HOME") or "/opt/java/openjdk"


def _tool(name: str, extra_dirs: Sequence[Path] = ()) -> Path | None:
    for directory in extra_dirs:
        candidate = Path(directory) / name
        if candidate.is_file():
            return candidate
    found = shutil.which(name)
    return Path(found) if found else None


def find_build_tools(android_home: str | None = None) -> Path | None:
    """Locate the newest ``build-tools/<ver>`` directory (apksigner/zipalign)."""
    roots = [android_home or "", os.environ.get("ANDROID_HOME", ""),
             os.environ.get("ANDROID_SDK_ROOT", ""), "/opt/android-sdk"]
    for root in roots:
        if not root:
            continue
        bt_dir = Path(root) / "build-tools"
        if not bt_dir.is_dir():
            continue
        versions = sorted(
            (p for p in bt_dir.iterdir() if p.is_dir()),
            key=lambda p: [int(x) if x.isdigit() else 0 for x in p.name.split(".")],
            reverse=True,
        )
        if versions:
            return versions[0]
    return None


def mask_cmd(argv: Sequence[str], *secrets: str) -> str:
    """Human-safe rendering of a command line for logs."""
    text = " ".join(str(a) for a in argv)
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***")
    return text


def _run(argv: Sequence[str], *, env: Mapping[str, str] | None = None,
         timeout: int = _KEYTOOL_TIMEOUT) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout,
            env=dict(env) if env is not None else None,
        )
    except FileNotFoundError as exc:
        raise ValueError(
            f"ابزار «{argv[0]}» یافت نشد — تصویر داکر استاندارد را اجرا کنید "
            f"/ tool '{argv[0]}' not found (use the standard Docker image)"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(
            f"اجرای «{argv[0]}» بیش از حد طول کشید / '{argv[0]}' timed out"
        ) from exc


# ---------------------------------------------------------------------------
# Keystore: generate (keytool) or import (fetched from WP)
# ---------------------------------------------------------------------------

def _keytool() -> Path:
    tool = _tool("keytool", extra_dirs=[Path(_java_home()) / "bin"])
    if tool is None:
        raise ValueError(
            "keytool یافت نشد — JDK 17 لازم است / keytool not found; JDK 17 required"
        )
    return tool


def _write_argfile(tmp_dir: Path, options: list[str]) -> Path:
    argfile = tmp_dir / f"keytool-{os.getpid()}-{os.urandom(3).hex()}.args"
    argfile.write_text("\n".join(options) + "\n", encoding="utf-8")
    os.chmod(argfile, 0o600)
    return argfile


def _validate_keystore(ks_path: Path, store_pass: str) -> str:
    """``keytool -list`` — fails early on wrong password / corrupt file."""
    tool = _keytool()
    argfile = _write_argfile(ks_path.parent, [
        "-list", "-v", "-keystore", str(ks_path), "-storepass", store_pass,
    ])
    try:
        proc = _run([str(tool), f"@{argfile}"])
    finally:
        shred_file(argfile)
    if proc.returncode != 0:
        raise ValueError(
            "کی‌استور معتبر نیست یا رمز نادرست است / keystore invalid or wrong password: "
            + mask_cmd(proc.stderr.splitlines()[-1:] or [""], store_pass)
        )
    return proc.stdout


def ensure_keystore(
    tmp_dir: Path,
    payload: common.BuildPayload,
    wp_client: object | None = None,
) -> KeystoreInfo:
    """Materialize the release keystore under the build tmp dir (0700).

    ``mode=generate`` → ``keytool -genkeypair`` PKCS12/RSA-2048/30y validity.
    ``mode=existing`` → bytes fetched from the HMAC-protected WP endpoint.
    """
    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(tmp_dir, 0o700)
    except OSError:
        pass

    store_pass = payload.ks_pass
    key_pass = payload.key_pass or store_pass
    if not store_pass:
        raise ValueError(
            "رمز کی‌استور در payload موجود نیست (signing.ks_pass_b64) "
            "/ signing.ks_pass_b64 missing from payload"
        )
    alias = str(payload.keystore.get("alias") or "ravakwp")
    mode = str(payload.keystore.get("mode") or "generate")
    ks_path = tmp_dir / "release.keystore"

    if mode == "existing":
        if wp_client is None:
            raise ValueError("برای keystore موجود، wp_client لازم است / wp_client required")
        data = wp_client.fetch_keystore()  # type: ignore[attr-defined]
        ks_path.write_bytes(data)
        os.chmod(ks_path, 0o600)
    else:
        dname_name = (payload.app_name or payload.package_name).replace('"', "").strip()
        dname = f"CN={dname_name}, OU=RavakWP, O={payload.store_key}, L=Tehran, C=IR"
        tool = _keytool()
        options = [
            "-genkeypair",
            "-storetype", "PKCS12",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10950",           # 30 years (Google Play min 2033+)
            "-alias", alias,
            "-dname", dname,
            "-keystore", str(ks_path),
            "-storepass", store_pass,
            "-keypass", key_pass,
        ]
        argfile = _write_argfile(tmp_dir, options)  # passwords stay out of argv
        try:
            proc = _run([str(tool), f"@{argfile}"], timeout=_KEYTOOL_TIMEOUT)
        finally:
            shred_file(argfile)
        if proc.returncode != 0 or not ks_path.exists():
            detail = (proc.stderr.strip() or proc.stdout.strip() or "(no output)").splitlines()[-1]
            raise ValueError(
                "ساخت کی‌استور ناموفق بود / keytool -genkeypair failed: "
                + mask_cmd(detail, store_pass)
            )
        os.chmod(ks_path, 0o600)

    _validate_keystore(ks_path, store_pass)
    return KeystoreInfo(path=ks_path, alias=alias, store_pass=store_pass,
                        key_pass=key_pass, mode=mode)


def env_for_gradle(ks: KeystoreInfo) -> dict[str, str]:
    """RVK_* environment consumed by the template's signingConfig (AAB)."""
    return {
        "RVK_KS_PATH": str(ks.path),
        "RVK_KS_PASS": ks.store_pass,
        "RVK_KEY_ALIAS": ks.alias,
        "RVK_KEY_PASS": ks.key_pass,
    }


# ---------------------------------------------------------------------------
# APK: zipalign → apksigner sign
# ---------------------------------------------------------------------------

def zipalign(android_home: str | None, apk_in: Path, apk_out: Path) -> bool:
    """zipalign -f -p 4; returns True when aligned, False when copied as-is."""
    bt = find_build_tools(android_home)
    tool = bt / "zipalign" if bt else _tool("zipalign")
    if tool is None:
        shutil.copyfile(apk_in, apk_out)
        return False
    proc = _run([str(tool), "-f", "-p", "4", str(apk_in), str(apk_out)],
                timeout=_APKSIGNER_TIMEOUT)
    if proc.returncode != 0:
        raise ValueError(
            "zipalign ناموفق بود / zipalign failed: " + (proc.stderr.strip() or proc.stdout.strip())
        )
    return True


def sign_apk(android_home: str | None, apk_in: Path, ks: KeystoreInfo,
             out_path: Path) -> Path:
    """zipalign then ``apksigner sign`` (v1+v2+v3) into *out_path*."""
    aligned = out_path.parent / (out_path.stem + ".aligned.apk")
    aligned.parent.mkdir(parents=True, exist_ok=True)
    was_aligned = zipalign(android_home, apk_in, aligned)

    bt = find_build_tools(android_home)
    tool = (bt / "apksigner") if bt else _tool("apksigner")
    if tool is None:
        raise ValueError(
            "apksigner یافت نشد — build-tools لازم است / apksigner not found "
            "(install Android build-tools 34.0.0)"
        )
    env = dict(os.environ)
    env.update(env_for_gradle(ks))
    argv = [
        str(tool), "sign",
        "--ks", str(ks.path),
        "--ks-key-alias", ks.alias,
        "--ks-pass", "env:RVK_KS_PASS",   # secrets via env reference, not argv
        "--key-pass", "env:RVK_KEY_PASS",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--out", str(out_path),
        str(aligned),
    ]
    proc = _run(argv, env=env, timeout=_APKSIGNER_TIMEOUT)
    aligned.unlink(missing_ok=True)
    if proc.returncode != 0 or not out_path.exists():
        detail = proc.stderr.strip() or proc.stdout.strip() or "apksigner exited non-zero"
        raise ValueError(
            "امضای APK ناموفق بود / apksigner sign failed: " + " ".join(detail.splitlines()[-3:])
        )
    _ = was_aligned  # logged by the pipeline via the return of zipalign()
    return out_path


# ---------------------------------------------------------------------------
# Verification (spec §2 verify stage)
# ---------------------------------------------------------------------------

_APKSIGNER_SHA256_RE = re.compile(r"SHA-256 digest:\s*([0-9a-fA-F]{32,})")
_APKSIGNER_SHA1_RE = re.compile(r"SHA-1 digest:\s*([0-9a-fA-F]{24,})")
_KEYTOOL_SHA256_RE = re.compile(r"SHA256:\s*([0-9a-fA-F]{32,})")
_KEYTOOL_SHA1_RE = re.compile(r"SHA1:\s*([0-9a-fA-F]{24,})")


def verify_apk(android_home: str | None, apk_path: Path) -> dict[str, str]:
    """``apksigner verify --print-certs`` → {'sha1', 'sha256', 'subject'}.

    Falls back to ``keytool -printcert -jarfile`` when apksigner is absent.
    Raises ValueError when no verifier is available at all.
    """
    bt = find_build_tools(android_home)
    tool = (bt / "apksigner") if bt else _tool("apksigner")
    if tool is not None:
        proc = _run([str(tool), "verify", "--print-certs", "--verbose", str(apk_path)],
                    timeout=_APKSIGNER_TIMEOUT)
        if proc.returncode != 0:
            raise ValueError(
                "تأیید امضای APK ناموفق بود / apksigner verify failed: "
                + (proc.stderr.strip() or proc.stdout.strip())[:400]
            )
        out = proc.stdout
        sha256 = _APKSIGNER_SHA256_RE.search(out)
        sha1 = _APKSIGNER_SHA1_RE.search(out)
        subject = ""
        m = re.search(r"DN:\s*(.+)", out)
        if m:
            subject = m.group(1).strip()
        if sha256:
            return {
                "sha256": sha256.group(1).lower(),
                "sha1": sha1.group(1).lower() if sha1 else "",
                "subject": subject,
            }

    # --- fallback: keytool -printcert -jarfile -----------------------------
    tool = _keytool()
    proc = _run([str(tool), "-printcert", "-jarfile", str(apk_path)])
    if proc.returncode == 0 and proc.stdout:
        sha256 = _KEYTOOL_SHA256_RE.search(proc.stdout)
        sha1 = _KEYTOOL_SHA1_RE.search(proc.stdout)
        if sha256:
            return {
                "sha256": sha256.group(1).lower(),
                "sha1": sha1.group(1).lower() if sha1 else "",
                "subject": "",
            }
    raise ValueError(
        "استخراج گواهی امضا ممکن نشد / could not extract signing certificates"
    )


# ---------------------------------------------------------------------------
# Zip magic + AAB sanity (spec §2 verify + §3 WP-side checks)
# ---------------------------------------------------------------------------

def zip_magic(path: Path) -> bool:
    """True when the file starts with the PKZIP local-file-header magic."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def check_aab(path: Path) -> bool:
    """An AAB is a zip containing ``base/manifest/AndroidManifest.xml``."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
        return "base/manifest/AndroidManifest.xml" in names
    except (OSError, zipfile.BadZipFile):
        return False


def size_sanity(apk: Path | None, aab: Path | None) -> list[str]:
    """Size checks per spec: <1MB fail, >5MB warn. Returns warnings."""
    warnings: list[str] = []
    for label, path in (("APK", apk), ("AAB", aab)):
        if path is None or not Path(path).exists():
            continue
        size_mb = Path(path).stat().st_size / (1024 * 1024)
        if size_mb < 1.0:
            raise ValueError(
                f"حجم فایل {label} مشکوک است ({size_mb:.2f}MB < 1MB) "
                f"/ {label} is suspiciously small"
            )
        if size_mb > 5.0:
            warnings.append(
                f"حجم {label} بیشتر از ۵ مگابایت است ({size_mb:.1f}MB) / {label} > 5MB"
            )
    return warnings


# ---------------------------------------------------------------------------
# Secure wipe (spec §2 deliver cleanup)
# ---------------------------------------------------------------------------

def shred_file(path: str | Path) -> None:
    """Overwrite with zeros, fsync, then unlink — for keystore/argfile temps."""
    path = Path(path)
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            remaining = size
            while remaining > 0:
                block = b"\x00" * min(remaining, 1024 * 64)
                fh.write(block)
                remaining -= len(block)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass  # read-only fs — unlink below is still attempted
    path.unlink(missing_ok=True)
