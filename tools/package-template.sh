#!/usr/bin/env bash
# =============================================================================
# package-template.sh — build the Android template zip consumed by the worker
# -----------------------------------------------------------------------------
# Zips the `android-app/` Kotlin template (repo root) into the plugin's
# build-template directory; the WP plugin then serves it to build workers via
# the HMAC-protected `internal/template` endpoint (BUILD-ENGINE-SPEC §3).
#
# Excluded: editor/build leftovers (.gradle, build/, local.properties, *.iml)
#
# Usage:  bash build-engine/tools/package-template.sh
# Output: plugin/ravakwp-app-builder/build-template/ravakwp-android-template.zip
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/android-app"
OUT_DIR="$REPO_ROOT/plugin/ravakwp-app-builder/build-template"
OUT="$OUT_DIR/ravakwp-android-template.zip"

if [[ ! -d "$SRC" ]]; then
    echo "ERROR: template source not found: $SRC" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT"

# NOTE: zip excludes match full stored paths — root-level and nested build
# dirs are both covered ("build/*" and "*/build/*").
(cd "$SRC" && zip -qr "$OUT" . \
    -x "*.gradle/*" -x "*/.gradle/*" -x ".gradle/*" \
    -x "build/*" -x "*/build/*" \
    -x "local.properties" -x "*/local.properties" \
    -x "*.iml" -x "*/.idea/*")

echo "template: $OUT"
du -h "$OUT" | awk '{print "size:     " $1}'
sha256sum "$OUT"
