#!/usr/bin/env python3
"""Offline smoke tests for the RavakWP build-engine worker.

No Android SDK, no network, no pytest — plain asserts + ``main()``.
Run:  python3 tests/test_pipeline.py
"""

from __future__ import annotations

import base64
import io
import json
import sys
import tempfile
import traceback
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker import common, injector, pipeline, signer  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_payload(**overrides) -> common.BuildPayload:
    base = dict(
        build_id=42,
        store_key="rvk_ab12cd34ef56aa00",
        site_url="https://shop.example.com",
        wp_rest_url="https://shop.example.com/wp-json/ravakwp/v1",
        version_name="1.2.3",
        version_code=7,
        package_name="com.brand.store",
        app_name="فروشگاه نمونه",
        min_sdk=24,
        target_sdk=34,
        style_id="modern_minimal",
        template_ref="android-app-template-v1",
        config_url="https://shop.example.com/rvk-appconfig-42.json",
        hmac_key="unit-test-hmac-key-0123456789abcdef",
    )
    base.update(overrides)
    return common.BuildPayload(**base)


def make_png(size: int = 1024, color=(30, 144, 255, 255)) -> bytes:
    from PIL import Image, ImageDraw

    buf = io.BytesIO()
    img = Image.new("RGBA", (size, size), color)
    draw = ImageDraw.Draw(img)
    draw.ellipse(
        (size // 5, size // 5, size - size // 5, size - size // 5),
        fill=(255, 255, 255, 230),
    )
    img.save(buf, "PNG")
    return buf.getvalue()


def png_dimensions(data: bytes) -> tuple[int, int]:
    from PIL import Image

    img = Image.open(io.BytesIO(data))
    return img.size


# ---------------------------------------------------------------------------
# 1) HMAC envelope sign/verify round-trip (spec §1)
# ---------------------------------------------------------------------------

def test_envelope_roundtrip() -> None:
    import time as _t

    key = "unit-hmac-key"
    body = b'{"build_id":42}'
    now = str(int(_t.time()))  # current timestamp → inside the ±5min window
    sig = common.envelope_sign(key, now, body)
    assert len(sig) == 64 and all(c in "0123456789abcdef" for c in sig)
    assert common.envelope_verify(key, now, body, sig)
    assert not common.envelope_verify(key, now, body + b"x", sig), "body tamper must fail"
    assert not common.envelope_verify("other-key", now, body, sig), "wrong key must fail"
    stale = str(int(_t.time()) - 601)  # > 5 minutes old → rejected
    stale_sig = common.envelope_sign(key, stale, body)
    assert not common.envelope_verify(key, stale, body, stale_sig), "outside ±5min window"

    # job-level envelope (Redis transport)
    job = {"build_id": 42, "store_key": "rvk_ab12cd34ef56aa00", "app_name": "فروشگاه"}
    signed = common.sign_job(job, key)
    ok, reason = common.verify_job(signed, key)
    assert ok, reason
    tampered = dict(signed, build_id=43)
    ok, _ = common.verify_job(tampered, key)
    assert not ok, "tampered job envelope must be rejected"
    print("  PASS envelope sign/verify round-trip + tamper/window rejection")


# ---------------------------------------------------------------------------
# 2) BuildPayload normalization + secret decoding
# ---------------------------------------------------------------------------

def test_build_payload() -> None:
    # production path: from_dict performs normalization (tasks, keystore, b64)
    payload = common.BuildPayload.from_dict({
        "build_id": 42,
        "store_key": "rvk_ab12cd34ef56aa00",
        "site_url": "https://shop.example.com",
        "wp_rest_url": "https://shop.example.com/wp-json/ravakwp/v1",
        "version_name": "1.2.3",
        "version_code": 7,
        "package_name": "com.brand.store",
        "app_name": "فروشگاه نمونه",
        "min_sdk": 24,
        "target_sdk": 34,
        "hmac_key": "unit-test-hmac-key-0123456789abcdef",
        "signing": {"ks_pass_b64": base64.b64encode(b"s3cret-pass").decode(), "key_pass_b64": ""},
        "keystore": {"mode": "existing", "alias": "brand", "fetch": "internal/keystore/9"},
        "gradle": {"tasks": [":app:assembleRelease", "bundleRelease"]},
    })
    assert payload.version_code == 7 and payload.min_sdk == 24
    assert payload.gradle_tasks == ["assembleRelease", "bundleRelease"]
    assert payload.ks_pass == "s3cret-pass"
    assert payload.key_pass == "", "empty key_pass_b64 → empty (signer falls back to ks_pass)"
    assert payload.keystore["fetch"] == "internal/keystore/9"
    assert payload.callback_path("progress") == "internal/progress"

    try:
        common.BuildPayload.from_dict({"build_id": 1, "store_key": "rvk_x"})
        raise AssertionError("missing fields must raise")
    except ValueError:
        pass
    print("  PASS BuildPayload normalization + base64 password decode")


# ---------------------------------------------------------------------------
# 3) app-config.json injection (inject stage)
# ---------------------------------------------------------------------------

def test_inject_config() -> None:
    payload = make_payload()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "template"
        (src / "app" / "src" / "main").mkdir(parents=True)

        downloaded = {
            "api_base_url": "https://shop.example.com/wp-json/ravakwp/v1",
            "default_locale": "fa",
            "locales": ["fa", "en"],
            "features": {"wishlist": False},
            "brand": {"about": "درباره ما"},
        }
        cfg = injector.build_app_config(payload, downloaded)
        target = injector.inject_config(src, cfg)
        assert target == src / "app" / "src" / "main" / "assets" / "app-config.json"
        written = json.loads(target.read_text(encoding="utf-8"))
        assert written["store_key"] == payload.store_key
        assert written["package_name"] == "com.brand.store"
        assert written["app_name"] == "فروشگاه نمونه"
        assert written["version_code"] == 7 and written["version_name"] == "1.2.3"
        assert written["features"]["wishlist"] is False  # downloaded config wins
        assert written["payment"] == {"allow_wallet": False}  # schema defaults
        assert written["api_base_url"].startswith("https://")
        assert "فروشگاه" in target.read_text(encoding="utf-8")  # fa kept unescaped

        # empty config → payload fills everything, api_base_url derived
        cfg2 = injector.build_app_config(payload, None)
        assert cfg2["api_base_url"] == payload.wp_rest_url

        # invalid api_base_url is rejected
        try:
            injector.build_app_config(make_payload(wp_rest_url="not-a-url"), None)
            raise AssertionError("invalid api_base_url must raise")
        except ValueError:
            pass
    print("  PASS inject_config writes expected app-config.json (fa kept unescaped)")


# ---------------------------------------------------------------------------
# 4) gradle.properties merge (no sed of source files — spec injector contract)
# ---------------------------------------------------------------------------

def test_gradle_props() -> None:
    payload = make_payload()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td)
        (src / "gradle.properties").write_text(
            "# template defaults\n"
            "org.gradle.jvmargs=-Xmx3072m -Dfile.encoding=UTF-8\n"
            "android.useAndroidX=true\n"
            "rvkPackageName=com.ravakwp.template\n"
            "rvkVersionName=0.0.1\n",
            encoding="utf-8",
        )
        props = injector.gradle_props(src, payload, extra={"rvkStyleId": "modern_minimal"})
        assert props["rvkPackageName"] == "com.brand.store"
        assert props["rvkVersionName"] == "1.2.3"
        assert props["rvkVersionCode"] == "7"
        assert props["rvkStyleId"] == "modern_minimal"

        text = (src / "gradle.properties").read_text(encoding="utf-8")
        assert "org.gradle.jvmargs=-Xmx3072m -Dfile.encoding=UTF-8" in text, "template props kept"
        assert "android.useAndroidX=true" in text
        assert "rvkPackageName=com.brand.store" in text
        assert "com.ravakwp.template" not in text, "stale rvk props replaced"
        assert "rvkVersionName=1.2.3" in text
        assert "rvkStorePassword" not in text, "secrets must never land in gradle.properties"

        # idempotent second run
        injector.gradle_props(src, payload)
        text2 = (src / "gradle.properties").read_text(encoding="utf-8")
        assert text2.count("rvkPackageName=") == 1
    print("  PASS gradle_props merge (stale rvk* replaced, secrets excluded, idempotent)")


# ---------------------------------------------------------------------------
# 5) Pillow icon pipeline: all mipmap sizes from a 1024×1024 PNG
# ---------------------------------------------------------------------------

def test_generate_icons() -> None:
    payload = make_payload(assets={"app_icon": "", "splash": "", "logo": "",
                                   "adaptive_fg": "", "adaptive_bg": "#FF00AA"})
    icon_bytes = make_png(1024)
    assets = {"app_icon": icon_bytes, "adaptive_bg": b"", "adaptive_fg": b"",
              "splash": icon_bytes, "logo": make_png(800)}
    with tempfile.TemporaryDirectory() as td:
        src = Path(td)
        (src / "app" / "src" / "main" / "res").mkdir(parents=True)
        written = injector.generate_icons(assets, src, payload)

        res = src / "app" / "src" / "main" / "res"
        expected = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
        for dpi, size in expected.items():
            launcher = res / f"mipmap-{dpi}" / "ic_launcher.png"
            assert launcher.exists(), f"missing {launcher}"
            assert png_dimensions(launcher.read_bytes()) == (size, size)
            assert (res / f"mipmap-{dpi}" / "ic_launcher_round.png").exists()
        assert png_dimensions(
            (res / "mipmap-xxxhdpi" / "ic_launcher_foreground.png").read_bytes()
        ) == (432, 432)
        assert png_dimensions(
            (res / "mipmap-mdpi" / "ic_launcher_foreground.png").read_bytes()
        ) == (108, 108)
        assert (res / "mipmap-anydpi-v26" / "ic_launcher.xml").exists()
        assert png_dimensions(
            (res / "drawable-nodpi" / "splash_image.png").read_bytes()
        ) == (1080, 1920)
        assert png_dimensions(
            (res / "drawable-xxxhdpi" / "ic_notification.png").read_bytes()
        ) == (96, 96)
        assert (res / "drawable-nodpi" / "brand_logo.png").exists()
        assert len(written) >= 17  # 2×5 launcher + 2×5 adaptive + 5 notif + splash + logo

        # missing icon must fail loudly (no placeholder logic)
        with tempfile.TemporaryDirectory() as td2:
            src2 = Path(td2)
            (src2 / "app" / "src" / "main" / "res").mkdir(parents=True)
            try:
                injector.generate_icons({"app_icon": b""}, src2, payload)
                raise AssertionError("missing app_icon must raise")
            except ValueError:
                pass
    print("  PASS generate_icons: 48/72/96/144/192 mipmaps + adaptive fg/bg + 1080x1920 splash + notif icon")


# ---------------------------------------------------------------------------
# 6) localization (values/ fa default + values-en/)
# ---------------------------------------------------------------------------

def test_localize_app_name() -> None:
    with tempfile.TemporaryDirectory() as td:
        src = Path(td)
        res = src / "app" / "src" / "main" / "res"
        (res / "values").mkdir(parents=True)
        (res / "values" / "strings.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
            "    <string name=\"app_name\">Template</string>\n"
            "    <string name=\"other\">keep me</string>\n</resources>\n",
            encoding="utf-8",
        )
        values, values_en = injector.localize_app_name(src, "فروشگاه نمونه", "Sample Shop")
        text = values.read_text(encoding="utf-8")
        assert "فروشگاه نمونه" in text and "keep me" in text and "Template" not in text
        assert "Sample Shop" in values_en.read_text(encoding="utf-8")

        # no en name → falls back to fa
        _, values_en2 = injector.localize_app_name(src, "برند من", "")
        assert "برند من" in values_en2.read_text(encoding="utf-8")

        # missing strings.xml files are created from scratch
        with tempfile.TemporaryDirectory() as td2:
            values_new, values_en_new = injector.localize_app_name(Path(td2), "اپ من", "My App")
            assert "اپ من" in values_new.read_text(encoding="utf-8")
            assert "My App" in values_en_new.read_text(encoding="utf-8")
    print("  PASS localize_app_name: values/ (fa) + values-en/ patched/created")


# ---------------------------------------------------------------------------
# 7) log scrubber (spec §5): pass: strings + base64 blobs + secrets
# ---------------------------------------------------------------------------

def test_log_scrubber() -> None:
    scrubber = common.LogScrubber(["super-secret-passphrase"])
    line1 = "apksigner sign --ks-pass pass:Hunter2hunt --key-pass pass:abc123xyz --out a.apk"
    out1 = scrubber.scrub(line1)
    assert "Hunter2hunt" not in out1 and "abc123xyz" not in out1
    assert "pass:***" in out1

    line2 = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
    out2 = scrubber.scrub(line2)
    assert "eyJhbGciOiJIUzI1NiJ9" not in out2

    b64 = base64.b64encode(b"a" * 40).decode()
    out3 = scrubber.scrub(f"payload={b64} done")
    assert b64 not in out3 and "***" in out3

    out4 = scrubber.scrub("storePassword=hunter2 ls -la")
    assert "hunter2" not in out4

    out5 = scrubber.scrub("secret=super-secret-passphrase end")
    assert "super-secret-passphrase" not in out5 and "secret=***" in out5

    # normal content survives
    out6 = scrubber.scrub("gradle exit code 0 after 512s [compile 45%] /var/lib/ravakwp")
    assert "gradle exit code 0" in out6 and "/var/lib/ravakwp" in out6

    # BuildLog chunks are scrubbed too
    log = common.BuildLog(scrubber)
    log.append(f"keystore pass: {b64}")
    assert b64 not in log.tail(5)
    print("  PASS log scrubber masks pass: values, base64 blobs, JWTs, registered secrets")


# ---------------------------------------------------------------------------
# 8) zip magic / AAB structure / size sanity (verify stage)
# ---------------------------------------------------------------------------

def test_zip_checks() -> None:
    with tempfile.TemporaryDirectory() as td:
        apk = Path(td) / "app.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
            zf.writestr("classes.dex", b"\xde\xad\xbe\xef" * 10)
        assert signer.zip_magic(apk)
        assert not signer.check_aab(apk)

        fake_aab = Path(td) / "bundle.aab"
        with zipfile.ZipFile(fake_aab, "w") as zf:
            zf.writestr("base/manifest/AndroidManifest.xml", "<manifest/>")
            zf.writestr("base/dex/classes.dex", b"\x00" * 32)
        assert signer.zip_magic(fake_aab) and signer.check_aab(fake_aab)

        broken = Path(td) / "broken.aab"
        with zipfile.ZipFile(broken, "w") as zf:
            zf.writestr("base/root/", "")  # no manifest
        assert not signer.check_aab(broken)

        text = Path(td) / "notes.txt"
        text.write_text("definitely not a zip", encoding="utf-8")
        assert not signer.zip_magic(text)

        tiny = Path(td) / "tiny.apk"
        tiny.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        try:
            signer.size_sanity(tiny, None)
            raise AssertionError("<1MB artifact must fail size sanity")
        except ValueError:
            pass
        big = Path(td) / "big.apk"
        with open(big, "wb") as fh:
            fh.seek(6 * 1024 * 1024)
            fh.write(b"\0")
        warnings = signer.size_sanity(big, None)
        assert any("5MB" in w for w in warnings)
    print("  PASS zip_magic + check_aab (base/manifest) + size sanity (<1MB fail, >5MB warn)")


# ---------------------------------------------------------------------------
# 9) gradle failure summary parser (compile stage)
# ---------------------------------------------------------------------------

def test_gradle_failure_summary() -> None:
    log_lines = [f"noise {i}" for i in range(200)] + [
        "FAILURE: Build failed with an exception.",
        "* What went wrong:",
        "Execution failed for task ':app:lintVitalRelease'.",
        "> Lint found fatal errors",
        "* Try:",
        "> Run with --stacktrace",
        "BUILD FAILED in 3m 12s",
    ]
    summary = pipeline.gradle_failure_summary("\n".join(log_lines))
    assert summary.startswith("FAILURE: Build failed")
    assert "lintVitalRelease" in summary and "noise 199" not in summary
    assert pipeline.gradle_failure_summary("a\nb\nc") == "a\nb\nc"
    print("  PASS gradle_failure_summary extracts FAILURE block, falls back to tail")


# ---------------------------------------------------------------------------
# 10) stage windows match BUILD-ENGINE-SPEC §2 exactly
# ---------------------------------------------------------------------------

def test_stage_windows() -> None:
    expected = {
        "prepare": (0, 10), "inject": (10, 20), "compile": (20, 60),
        "sign": (60, 80), "verify": (80, 90), "deliver": (90, 100),
    }
    assert common.STAGE_WINDOWS == expected
    assert common.STAGES == tuple(expected)
    prev_hi = 0
    for stage in common.STAGES:
        lo, hi = common.STAGE_WINDOWS[stage]
        assert lo == prev_hi, f"stage {stage} window must start where the previous ended"
        prev_hi = hi
    assert prev_hi == 100
    print("  PASS stage progress windows match spec §2 (0-10-20-60-80-90-100)")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

TESTS = [
    test_envelope_roundtrip,
    test_build_payload,
    test_inject_config,
    test_gradle_props,
    test_generate_icons,
    test_localize_app_name,
    test_log_scrubber,
    test_zip_checks,
    test_gradle_failure_summary,
    test_stage_windows,
]


def main() -> int:
    print(f"RavakWP build-engine offline smoke tests — engine {common.ENGINE_VERSION}")
    failures = 0
    for test in TESTS:
        try:
            test()
        except Exception:  # noqa: BLE001
            failures += 1
            print(f"  FAIL {test.__name__}")
            traceback.print_exc()
    total = len(TESTS)
    print(f"\n{total - failures}/{total} tests passed")
    if failures:
        print("RESULT: FAILED")
        return 1
    print("RESULT: ALL PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
