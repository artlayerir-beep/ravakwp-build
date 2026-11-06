"""Workspace + injection stage helpers for the RavakWP build engine.

Used by :mod:`pipeline` (spec §2 stage ``prepare`` and ``inject``):

* workspace sandbox layout: ``WORKSPACES/{store_key}/builds/{build_id}/``
  (ARCHITECTURE §3 tenancy), permissions 0700.
* safe template zip extraction (zip-slip protected)
* ``app/src/main/assets/app-config.json`` injection (ANDROID-SPEC §2)
* brand icon generation with Pillow: launcher mipmaps 48/72/96/144/192,
  adaptive fg/bg, splash 1080x1920, notification small icon
* strings.xml localization for fa (values/) and en (values-en/)
* google-services.json placement (plugin auto-applies when present)
* gradle.properties merge of the ``rvk*`` -P properties
"""

from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from xml.sax.saxutils import escape

if __package__:  # dual-mode import: package (tests) or script (container)
    from . import common
else:  # pragma: no cover
    import common

__all__ = [
    "WorkspacePaths",
    "prepare_workspace",
    "extract_template",
    "resolve_src_root",
    "build_app_config",
    "inject_config",
    "generate_icons",
    "localize_app_name",
    "place_firebase",
    "gradle_props",
]

from PIL import Image, ImageDraw, ImageOps  # Pillow — bundled dependency (spec §2 decision)

# dpi-name → launcher icon px (48dp bucket) — spec §2 prepare stage
MIPMAP_SIZES: dict[str, int] = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
# adaptive icon layers are 108dp buckets — spec §2 adaptive fg/bg
ADAPTIVE_SIZES: dict[str, int] = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
# notification small icon is 24dp bucket (must be alpha-only white)
NOTIF_SIZES: dict[str, int] = {"mdpi": 24, "hdpi": 36, "xhdpi": 48, "xxhdpi": 72, "xxxhdpi": 96}
SPLASH_SIZE = (1080, 1920)
MAX_LOGO_EDGE = 512
_ADAPTIVE_SAFE_ZONE = 0.66  # 66dp of the 108dp adaptive canvas is the safe zone

_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_STRING_NAME_RE = re.compile(r'(<string name="app_name">)(.*?)(</string>)', re.DOTALL)


@dataclass
class WorkspacePaths:
    """Sandbox layout of a single build (ARCHITECTURE §3.2)."""

    root: Path          # WORKSPACES/{store_key}/builds/{build_id}
    tmp: Path           # transient files (keystore, template extraction)
    artifacts: Path     # final APK/AAB copies kept for 24h debugging
    src: Path | None = None          # extracted template (set by extract_template)
    keystore: Path | None = None     # transient keystore (shredded after deliver)
    meta: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Workspace + template
# ---------------------------------------------------------------------------

def prepare_workspace(workspaces_root: Path, store_key: str, build_id: int) -> WorkspacePaths:
    """Create ``{root}/{store_key}/builds/{build_id}`` with 0700 permissions."""
    if not store_key or "/" in store_key or store_key.startswith("."):
        raise ValueError(
            f"store_key نامعتبر است: «{store_key}» / invalid store_key for filesystem"
        )
    root = Path(workspaces_root) / store_key / "builds" / str(int(build_id))
    tmp = root / "tmp"
    artifacts = root / "artifacts"
    for path in (root, tmp, artifacts):
        path.mkdir(parents=True, exist_ok=True)
    try:  # best-effort hardening; FAT/odd mounts may refuse chmod
        os.chmod(root, 0o700)
        os.chmod(tmp, 0o700)
    except OSError:
        pass
    return WorkspacePaths(root=root, tmp=tmp, artifacts=artifacts)


def extract_template(zip_path: Path, dest: Path) -> Path:
    """Safely extract the template zip; returns the project root inside it.

    Handles both layouts: entries at archive root, or one top-level folder.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            name = member.filename
            if not name or name.startswith(("/", "\\")) or ".." in Path(name).parts:
                continue  # zip-slip guard
            target = (dest / name)
            if not str(target.resolve()).startswith(str(resolved_dest)):
                continue
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as srcfh, open(target, "wb") as dstfh:
                while True:
                    block = srcfh.read(1024 * 256)
                    if not block:
                        break
                    dstfh.write(block)
    return resolve_src_root(dest)


def resolve_src_root(dest: Path) -> Path:
    """If the archive had exactly one top-level folder, descend into it."""
    entries = [p for p in dest.iterdir() if not p.name.startswith(".")]
    dirs = [p for p in entries if p.is_dir()]
    if len(entries) == 1 and len(dirs) == 1:
        return dirs[0]
    return dest


# ---------------------------------------------------------------------------
# app-config.json (ANDROID-SPEC §2)
# ---------------------------------------------------------------------------

def build_app_config(
    payload: common.BuildPayload, config: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Merge the downloaded config with payload basics (payload fills gaps)."""
    cfg = dict(config or {})

    cfg.setdefault("store_key", payload.store_key)
    cfg["app_name"] = str(cfg.get("app_name") or payload.app_name)
    cfg.setdefault("app_name_en", "")
    cfg["package_name"] = str(cfg.get("package_name") or payload.package_name)
    cfg["api_base_url"] = str(cfg.get("api_base_url") or payload.wp_rest_url)
    cfg.setdefault("style_id", payload.style_id)
    cfg.setdefault("default_locale", "fa")
    cfg.setdefault("locales", ["fa", "en"])
    cfg["version_name"] = payload.version_name
    cfg["version_code"] = payload.version_code
    cfg.setdefault("min_sdk", payload.min_sdk)
    cfg.setdefault("target_sdk", payload.target_sdk)

    brand = dict(cfg.get("brand") or {})
    brand.setdefault("logo_url", payload.assets.get("logo", ""))
    brand.setdefault("splash_url", payload.assets.get("splash", ""))
    brand.setdefault("about", "")
    cfg["brand"] = brand

    payment = dict(cfg.get("payment") or {})
    payment.setdefault("allow_wallet", False)
    cfg["payment"] = payment

    features = dict(cfg.get("features") or {})
    features.setdefault("wishlist", True)
    features.setdefault("reviews", True)
    features.setdefault("onboarding", True)
    cfg["features"] = features

    if not str(cfg.get("api_base_url") or "").startswith(("http://", "https://")):
        raise ValueError(
            "api_base_url نامعتبر است / app-config api_base_url must be an absolute URL"
        )
    return cfg


def inject_config(src: Path, config: Mapping[str, Any]) -> Path:
    """Write ``app/src/main/assets/app-config.json`` (UTF-8, unescaped fa)."""
    assets_dir = Path(src) / "app" / "src" / "main" / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    target = assets_dir / "app-config.json"
    target.write_text(
        json.dumps(dict(config), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return target


# ---------------------------------------------------------------------------
# Brand assets → Android resources (Pillow)
# ---------------------------------------------------------------------------

def _load_image(data: bytes, label: str) -> Image.Image:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:  # noqa: BLE001 — Pillow raises many types
        raise ValueError(
            f"تصویر «{label}» قابل خواندن نیست / asset '{label}' is not a readable image"
        ) from exc
    if img.mode not in ("RGBA", "RGB", "LA"):
        img = img.convert("RGBA")
    return img


def _resize_cover(img: Image.Image, size: tuple[int, int]) -> Image.Image:
    """Center-crop + resize (cover) — used for the splash."""
    return ImageOps.fit(img, size, method=Image.LANCZOS, centering=(0.5, 0.5))


def _hex_to_rgb(value: str, fallback: tuple[int, int, int] = (255, 255, 255)) -> tuple[int, ...]:
    m = _HEX_COLOR_RE.match(value or "")
    if not m:
        return fallback
    hexval = m.group(0).lstrip("#")
    if len(hexval) == 3:
        hexval = "".join(ch * 2 for ch in hexval)
    if len(hexval) == 8:  # ARGB from Android (#AARRGGBB)
        hexval = hexval[2:]
    return tuple(int(hexval[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def _round_mask(size: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, size - 1, size - 1), fill=255)
    return mask


def _write_adaptive_xml(src: Path) -> None:
    """Write mipmap-anydpi-v26/ic_launcher.xml if the template lacks it."""
    anydpi = Path(src) / "app" / "src" / "main" / "res" / "mipmap-anydpi-v26"
    anydpi.mkdir(parents=True, exist_ok=True)
    tpl = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<adaptive-icon xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
        '    <background android:drawable="@mipmap/ic_launcher_background"/>\n'
        '    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>\n'
        "</adaptive-icon>\n"
    )
    for name in ("ic_launcher.xml", "ic_launcher_round.xml"):
        target = anydpi / name
        if not target.exists():
            target.write_text(tpl, encoding="utf-8")


def generate_icons(
    assets: Mapping[str, bytes], src: Path, payload: common.BuildPayload
) -> list[Path]:
    """Generate the full launcher/adaptive/splash/notification resource set.

    Returns the list of written files (for the build log).
    """
    icon_bytes = assets.get("app_icon") or b""
    if not icon_bytes:
        raise ValueError(
            "آیکون اپلیکیشن (assets.app_icon) در payload موجود نیست "
            "/ assets.app_icon is required to generate launcher icons"
        )
    icon = _load_image(icon_bytes, "app_icon").convert("RGBA")
    res = Path(src) / "app" / "src" / "main" / "res"
    written: list[Path] = []

    # ---- classic launcher mipmaps (48/72/96/144/192) ----------------------
    for dpi, size in MIPMAP_SIZES.items():
        folder = res / f"mipmap-{dpi}"
        folder.mkdir(parents=True, exist_ok=True)
        square = icon.resize((size, size), Image.LANCZOS)
        p1 = folder / "ic_launcher.png"
        square.save(p1, "PNG")
        written.append(p1)
        round_icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        round_icon.paste(square, (0, 0), _round_mask(size))
        p2 = folder / "ic_launcher_round.png"
        round_icon.save(p2, "PNG")
        written.append(p2)

    # ---- adaptive fg/bg layers (108dp buckets) ----------------------------
    fg_source = icon
    fg_bytes = assets.get("adaptive_fg") or b""
    if fg_bytes:
        fg_source = _load_image(fg_bytes, "adaptive_fg").convert("RGBA")
    bg_value = payload.assets.get("adaptive_bg", "")
    bg_image: Image.Image | None = None
    if bg_bytes := assets.get("adaptive_bg"):
        bg_image = _load_image(bg_bytes, "adaptive_bg").convert("RGBA")
    bg_color = _hex_to_rgb(bg_value) if _HEX_COLOR_RE.match(bg_value or "") else None

    for dpi, size in ADAPTIVE_SIZES.items():
        folder = res / f"mipmap-{dpi}"
        folder.mkdir(parents=True, exist_ok=True)
        # foreground: source scaled into the 66% adaptive safe zone
        fg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        inner = int(size * _ADAPTIVE_SAFE_ZONE)
        fg.paste(fg_source.resize((inner, inner), Image.LANCZOS), ((size - inner) // 2,) * 2)
        pfg = folder / "ic_launcher_foreground.png"
        fg.save(pfg, "PNG")
        written.append(pfg)
        # background: image asset > hex color > full-bleed icon
        bg = Image.new("RGBA", (size, size), (*bg_color, 255) if bg_color else (0, 0, 0, 0))
        if bg_image is not None:
            bg = _resize_cover(bg_image, (size, size)).convert("RGBA")
        elif bg_color is None:
            bg = icon.resize((size, size), Image.LANCZOS)
        pbg = folder / "ic_launcher_background.png"
        bg.convert("RGBA").save(pbg, "PNG")
        written.append(pbg)
    _write_adaptive_xml(src)

    # ---- splash 1080x1920 --------------------------------------------------
    splash_bytes = assets.get("splash") or b""
    if splash_bytes:
        splash = _resize_cover(_load_image(splash_bytes, "splash").convert("RGBA"), SPLASH_SIZE)
    else:  # derive from the icon on a white canvas (still a real asset render)
        splash = Image.new("RGBA", SPLASH_SIZE, (255, 255, 255, 255))
        side = 420
        splash.paste(icon.resize((side, side), Image.LANCZOS),
                     ((SPLASH_SIZE[0] - side) // 2, (SPLASH_SIZE[1] - side) // 2))
    nodpi = res / "drawable-nodpi"
    nodpi.mkdir(parents=True, exist_ok=True)
    p3 = nodpi / "splash_image.png"
    splash.save(p3, "PNG")
    written.append(p3)

    # ---- notification small icon (white silhouette, alpha-only) -----------
    alpha = icon.getchannel("A")
    for dpi, size in NOTIF_SIZES.items():
        folder = res / f"drawable-{dpi}"
        folder.mkdir(parents=True, exist_ok=True)
        white = Image.new("RGBA", icon.size, (255, 255, 255, 0))
        white.putalpha(alpha)
        small = white.resize((size, size), Image.LANCZOS)
        p4 = folder / "ic_notification.png"
        small.save(p4, "PNG")
        written.append(p4)

    # ---- brand logo ---------------------------------------------------------
    logo_bytes = assets.get("logo") or b""
    if logo_bytes:
        logo = _load_image(logo_bytes, "logo").convert("RGBA")
        logo.thumbnail((MAX_LOGO_EDGE, MAX_LOGO_EDGE), Image.LANCZOS)
        p5 = nodpi / "brand_logo.png"
        logo.save(p5, "PNG")
        written.append(p5)

    return written


# ---------------------------------------------------------------------------
# Localization (strings.xml for fa default + values-en)
# ---------------------------------------------------------------------------

_MINIMAL_STRINGS = (
    '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
    '    <string name="app_name">{name}</string>\n</resources>\n'
)


def _patch_app_name(strings_path: Path, app_name: str) -> Path:
    strings_path.parent.mkdir(parents=True, exist_ok=True)
    escaped = escape(app_name)
    if strings_path.exists():
        text = strings_path.read_text(encoding="utf-8")
        if _STRING_NAME_RE.search(text):
            text = _STRING_NAME_RE.sub(lambda m: m.group(1) + escaped + m.group(3), text, count=1)
        else:
            text = text.replace("</resources>", f'    <string name="app_name">{escaped}</string>\n</resources>')
        strings_path.write_text(text, encoding="utf-8")
    else:
        strings_path.write_text(_MINIMAL_STRINGS.format(name=escaped), encoding="utf-8")
    return strings_path


def localize_app_name(src: Path, app_name: str, app_name_en: str | None) -> tuple[Path, Path]:
    """values/strings.xml ← fa name (default locale), values-en/ ← en name."""
    if not app_name:
        raise ValueError("app_name در payload خالی است / payload.app_name is empty")
    en = (app_name_en or "").strip() or app_name
    values = _patch_app_name(Path(src) / "app" / "src" / "main" / "res" / "values" / "strings.xml", app_name)
    values_en = _patch_app_name(Path(src) / "app" / "src" / "main" / "res" / "values-en" / "strings.xml", en)
    return values, values_en


# ---------------------------------------------------------------------------
# Firebase config placement
# ---------------------------------------------------------------------------

_FIREBASE_REQUIRED = ("project_id", "mobilesdk_app_id", "api_key")


def place_firebase(src: Path, firebase_bytes: bytes) -> Path:
    """Validate + write ``app/google-services.json`` (plugin auto-applies)."""
    try:
        cfg = json.loads(firebase_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(
            "فایل firebase معتبر JSON نیست / fetched firebase config is not valid JSON"
        ) from exc
    if not isinstance(cfg, dict):
        raise ValueError("google-services.json باید شی JSON باشد / must be a JSON object")
    client = ((cfg.get("client") or [{}])[0]) if isinstance(cfg.get("client"), list) else {}
    missing = [k for k in _FIREBASE_REQUIRED
               if not cfg.get(k) and not (client.get("client_info", {}) or {}).get(k)
               and not any(p.get(k) for p in (client.get("api_key") or [{}]))]
    if missing:
        raise ValueError(
            "google-services.json فاقد کلیدهای الزامی است: "
            + ", ".join(missing)
            + " / missing required firebase keys"
        )
    target = Path(src) / "app" / "google-services.json"
    target.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# gradle.properties merge (spec: -P props, NOT sed of source files)
# ---------------------------------------------------------------------------

def gradle_props(
    src: Path, payload: common.BuildPayload, extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Merge ``rvk*`` build props into the workspace ``gradle.properties``.

    The Android template reads these as ``-P`` Gradle properties (see
    ANDROID-SPEC §2): rvkPackageName / rvkAppName / rvkVersionCode /
    rvkVersionName / rvkMinSdk / rvkTargetSdk.  Signing secrets are NEVER
    written here — they travel through RVK_* environment variables only.
    """
    props: dict[str, str] = {
        "rvkPackageName": payload.package_name,
        "rvkAppName": payload.app_name.replace("\n", " ").strip(),
        "rvkVersionCode": str(payload.version_code),
        "rvkVersionName": payload.version_name,
        "rvkMinSdk": str(payload.min_sdk),
        "rvkTargetSdk": str(payload.target_sdk),
    }
    if extra:
        props.update({k: str(v) for k, v in extra.items() if k and not k.startswith("rvkSign")})

    path = Path(src) / "gradle.properties"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    kept: list[str] = []
    for line in existing.splitlines():
        key = line.split("=", 1)[0].strip()
        if key in props or key == "org.gradle.jvmargs" and "org.gradle.jvmargs" in props:
            continue  # replaced below
        if key.startswith("rvk"):
            continue  # stale engine props from a previous build
        kept.append(line)

    block = ["", "# ---- RavakWP build engine (injected; do not edit) ----"]
    block += [f"{k}={v}" for k, v in props.items()]
    if os.environ.get("RVK_GRADLE_JVMARGS"):
        block += [f"org.gradle.jvmargs={os.environ['RVK_GRADLE_JVMARGS']}"]
    path.write_text("\n".join(kept + block).rstrip() + "\n", encoding="utf-8")
    return props
