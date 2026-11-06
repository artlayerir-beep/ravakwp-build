#!/usr/bin/env bash
# =============================================================================
# RavakWP Build Engine — container entrypoint wrapper
#
# Used by docker-compose (entrypoint override) and by local/dispatch.php for
# one-shot runs. Creates the persistence directories, tightens the umask so
# build sandboxes are never group/world readable (spec §5), then execs the
# Python worker with any pass-through arguments.
#
#   docker run --rm ravakwp/build-engine            → daemon loop
#   docker run --rm ravakwp/build-engine --once     → single build
# =============================================================================
set -euo pipefail

export RVK_WORKSPACES="${RVK_WORKSPACES:-/var/lib/ravakwp/workspaces}"
export RVK_CACHE_DIR="${RVK_CACHE_DIR:-/var/lib/ravakwp/templates}"
export RVK_GRADLE_HOME="${RVK_GRADLE_HOME:-/var/lib/ravakwp/gradle-home}"

mkdir -p "$RVK_WORKSPACES" "$RVK_CACHE_DIR" "$RVK_GRADLE_HOME"

# Build sandboxes hold keystores transiently — never group/world readable.
umask 077

echo "[entrypoint] workspaces=$RVK_WORKSPACES cache=$RVK_CACHE_DIR"
exec python3 /opt/worker/worker.py "$@"
