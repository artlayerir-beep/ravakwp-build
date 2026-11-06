#!/usr/bin/env python3
"""RavakWP Build Engine — worker main loop (BUILD-ENGINE-SPEC §0/§3).

One worker codebase for both deployment modes:

* job acquisition via Redis  — ``BRPOP rvk:builds`` when ``REDIS_URL`` is set
* REST table-queue fallback  — signed ``POST {wp}/internal/poll`` every 5s
  (with jitter) when Redis is not configured

Each claimed job runs through :class:`pipeline.BuildPipeline` on a bounded
``ThreadPoolExecutor`` (one build per slot, spec §5).  Any build failure is
reported to WordPress as ``status=failed`` with a human fa message plus the
scrubbed log tail.  SIGTERM drains gracefully: no new jobs are claimed,
running builds finish.

Usage:
    python3 worker.py                    # daemon loop
    python3 worker.py --once             # process a single job, then exit
    python3 worker.py --once --build-id 42
    python3 worker.py --validate         # env validation only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import signal
import socket
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__:  # dual-mode import: package (tests) or script (container)
    from . import common
    from .pipeline import BuildPipeline, PipelineConfig
    from .wp_client import WPClient
else:  # pragma: no cover — executed as `python3 /opt/worker/worker.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import common
    from pipeline import BuildPipeline, PipelineConfig
    from wp_client import WPClient

__all__ = ["WorkerEnv", "worker_id", "main"]


# ---------------------------------------------------------------------------
# Worker configuration (env-driven, validated at startup)
# ---------------------------------------------------------------------------

@dataclass
class WorkerEnv:
    mode: str = "local"                      # local | remote (informational)
    wp_site_url: str = ""
    wp_rest_url: str = ""
    hmac_key: str = ""                       # WP_HMAC_KEY (poll + fallback)
    store_key: str = ""                      # RVK_STORE_KEY (poll envelope)
    redis_url: str = ""
    concurrency: int = 1
    poll_interval: float = 5.0
    workspaces: Path = Path("/var/lib/ravakwp/workspaces")
    cache_dir: Path = Path("/var/lib/ravakwp/templates")
    gradle_home: Path = Path("/var/lib/ravakwp/gradle-home")
    heartbeat: Path = Path("/var/lib/ravakwp/worker-heartbeat")
    android_home: str = ""
    gradle_bin: str = "gradle"
    once: bool = False
    build_id_target: int | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "WorkerEnv":
        env = dict(os.environ if environ is None else environ)
        site = env.get("WP_SITE_URL", "").strip().rstrip("/")
        rest = env.get("WP_REST_URL", "").strip().rstrip("/")
        if not rest and site:
            rest = f"{site}/wp-json/ravakwp/v1"
        try:
            concurrency = int(env.get("WORKER_CONCURRENCY") or 1)
        except ValueError:
            concurrency = 1
        try:
            poll_interval = float(env.get("POLL_INTERVAL") or 5)
        except ValueError:
            poll_interval = 5.0
        target: int | None = None
        if env.get("RVK_ONCE_BUILD_ID"):
            try:
                target = int(env["RVK_ONCE_BUILD_ID"])
            except ValueError:
                target = None
        return cls(
            mode=env.get("WORKER_MODE", "local").strip().lower() or "local",
            wp_site_url=site,
            wp_rest_url=rest,
            hmac_key=env.get("WP_HMAC_KEY", "").strip(),
            store_key=env.get("RVK_STORE_KEY", "").strip(),
            redis_url=env.get("REDIS_URL", "").strip(),
            concurrency=max(1, min(concurrency, 16)),
            poll_interval=max(1.0, poll_interval),
            workspaces=Path(env.get("RVK_WORKSPACES", "/var/lib/ravakwp/workspaces")),
            cache_dir=Path(env.get("RVK_CACHE_DIR", "/var/lib/ravakwp/templates")),
            gradle_home=Path(env.get("RVK_GRADLE_HOME", "/var/lib/ravakwp/gradle-home")),
            heartbeat=Path(env.get("RVK_HEARTBEAT", "/var/lib/ravakwp/worker-heartbeat")),
            android_home=env.get("ANDROID_HOME", "/opt/android-sdk"),
            gradle_bin=env.get("GRADLE_BIN", "gradle"),
            extra=env,
        )

    @property
    def queue_mode(self) -> bool:
        return bool(self.redis_url)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.mode not in ("local", "remote"):
            errors.append(
                f"WORKER_MODE باید local یا remote باشد (الان: {self.mode}) "
                "/ WORKER_MODE must be local or remote"
            )
        if not self.queue_mode:
            if not self.wp_rest_url:
                errors.append(
                    "WP_SITE_URL تنظیم نشده است — در حالت بدون Redis لازم است "
                    "/ WP_SITE_URL is required when REDIS_URL is not set"
                )
            if not self.hmac_key:
                errors.append(
                    "WP_HMAC_KEY تنظیم نشده است — برای امضای درخواست poll لازم است "
                    "/ WP_HMAC_KEY is required for signed polling"
                )
        if self.wp_site_url and not self.wp_site_url.startswith(("http://", "https://")):
            errors.append(
                "WP_SITE_URL باید با http:// یا https:// شروع شود "
                "/ WP_SITE_URL must include the scheme"
            )
        if self.poll_interval < 1.0:
            errors.append("POLL_INTERVAL باید ≥ 1 ثانیه باشد / POLL_INTERVAL must be ≥ 1s")
        return errors


def worker_id() -> str:
    return f"{socket.gethostname()}#{os.getpid()}"


def beat(env: WorkerEnv) -> None:
    """Write the heartbeat file (Docker HEALTHCHECK freshness probe)."""
    path = env.heartbeat
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(time.time()), encoding="utf-8")
    except OSError:
        try:
            fallback = Path("/tmp/rvk-worker-heartbeat")
            fallback.write_text(str(time.time()), encoding="utf-8")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Startup banner + env validation output
# ---------------------------------------------------------------------------

def _key_fingerprint(key: str) -> str:
    if not key:
        return "-"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12] + "…"


def banner(env: WorkerEnv) -> None:
    line = "═" * 62
    print(line, flush=True)
    print(f"  RavakWP Build Engine  v{common.ENGINE_VERSION}", flush=True)
    print(f"  worker:    {worker_id()}", flush=True)
    print(f"  mode:      {env.mode}   concurrency: {env.concurrency}", flush=True)
    print(f"  queue:     {'redis (' + env.redis_url.split('@')[-1] + ')' if env.queue_mode else 'REST poll /internal/poll'}", flush=True)
    print(f"  site:      {env.wp_site_url or '-'}", flush=True)
    print(f"  hmac key:  {_key_fingerprint(env.hmac_key)}", flush=True)
    print(f"  workspace: {env.workspaces}", flush=True)
    print(f"  android:   {env.android_home or '-'}", flush=True)
    print(line, flush=True)


def print_validation(env: WorkerEnv) -> list[str]:
    errors = env.validate()
    for error in errors:
        print(f"✖ {error}", flush=True)
    return errors


# ---------------------------------------------------------------------------
# Dead-letter handling for unparsable / unverifiable jobs
# ---------------------------------------------------------------------------

def dead_letter(env: WorkerEnv, job: dict[str, Any], error: str) -> None:
    record = {
        "error": error,
        "ts": common.utc_iso(),
        "worker": worker_id(),
        "job": job,
    }
    text = json.dumps(record, ensure_ascii=False, default=str)
    text = common.LogScrubber([env.hmac_key]).scrub_text(text)
    if env.queue_mode:
        try:
            import redis  # type: ignore

            client = redis.Redis.from_url(env.redis_url, decode_responses=True)
            client.rpush(common.DEAD_KEY, text)
            print(f"[dead] job moved to {common.DEAD_KEY}: {error}", flush=True)
            return
        except Exception as exc:  # noqa: BLE001 — fall back to disk
            print(f"[dead] redis dead-letter failed ({exc}); writing to disk", flush=True)
    folder = env.workspaces / "_dead"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        name = f"{time.strftime('%Y%m%dT%H%M%S')}-{abs(hash(text)) % 10**8}.json"
        (folder / name).write_text(text, encoding="utf-8")
        # keep at most 100 dead jobs on disk
        files = sorted(folder.glob("*.json"))
        for stale in files[:-100]:
            stale.unlink(missing_ok=True)
        print(f"[dead] job written to {folder / name}: {error}", flush=True)
    except OSError as exc:
        print(f"[dead] could not persist dead job: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Job processing (runs on a pool thread)
# ---------------------------------------------------------------------------

def process_job(job: dict[str, Any], env: WorkerEnv, stop: threading.Event) -> dict[str, Any]:
    """Claimed-job entry point: envelope check → payload → pipeline run."""
    build_label = f"build:{job.get('build_id', '?')}"
    print(f"[{worker_id()}] claimed {build_label}", flush=True)

    hmac_key = str(job.get("hmac_key") or env.hmac_key or "")
    if "_sig" in job:  # Redis transport carries a signed envelope
        ok, reason = common.verify_job(job, hmac_key)
        if not ok:
            print(f"[{build_label}] ✖ {reason}", flush=True)
            dead_letter(env, job, reason)
            return {"status": "rejected", "error": reason}

    try:
        payload = common.BuildPayload.from_dict(job)
    except Exception as exc:  # noqa: BLE001 — unparsable payload
        error = f"payload نامعتبر است / invalid job payload: {exc}"
        print(f"[{build_label}] ✖ {error}", flush=True)
        dead_letter(env, job, str(exc))
        return {"status": "invalid", "error": error}

    build_id = payload.build_id
    scrubber = common.LogScrubber([hmac_key, env.hmac_key])
    tee = env.workspaces / payload.store_key / "builds" / str(build_id) / "build.log"
    log = common.BuildLog(scrubber, tee_path=tee)
    log.append(f"build {build_id} claimed by {worker_id()} (engine {common.ENGINE_VERSION})")

    client: WPClient | None = None
    try:
        client = WPClient(payload, fallback_hmac_key=env.hmac_key)
        client.progress(build_id, "preparing", "prepare", 1)

        config = PipelineConfig(
            android_home=env.android_home,
            gradle_bin=env.gradle_bin,
            workspaces_root=env.workspaces,
            cache_dir=env.cache_dir,
            gradle_home=env.gradle_home,
            on_heartbeat=lambda: beat(env),
        )
        pipeline = BuildPipeline(payload, client, config, log=log, scrubber=scrubber)
        result = pipeline.run()
        log.append(f"build finished with status={result.get('status')}")
        print(f"[{build_label}] finished: {result.get('status')}", flush=True)
        return result
    except common.BuildError as exc:  # pipeline.run() already reported it
        print(f"[{build_label}] failed: {exc.human()}", flush=True)
        return {"status": "failed", "error": exc.human()}
    except Exception as exc:  # noqa: BLE001 — unexpected worker-level error
        error = f"خطای غیرمنتظره کارگر / unexpected worker error: {type(exc).__name__}: {exc}"
        print(f"[{build_label}] ✖ {error}", flush=True)
        log.append(error)
        if client is not None:
            client.progress(
                build_id, "failed", "worker", 0,
                log_chunk=log.tail(80), error=common.BuildError("worker", "خطای غیرمنتظره در کارگر ساخت", str(exc), log.tail(80)).with_tail(80),
            )
        return {"status": "failed", "error": error}


# ---------------------------------------------------------------------------
# Job sources
# ---------------------------------------------------------------------------

class RedisSource:
    """BRPOP consumer for the optional Redis queue (spec §0)."""

    name = "redis"

    def __init__(self, env: WorkerEnv) -> None:
        try:
            import redis  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise SystemExit(
                "REDIS_URL تنظیم شده اما پکیج redis نصب نیست — pip install redis "
                "/ REDIS_URL is set but the redis package is not installed"
            ) from exc
        self._client = redis.Redis.from_url(
            env.redis_url,
            decode_responses=True,
            socket_timeout=env.poll_interval + 5,
            socket_connect_timeout=10,
            health_check_interval=30,
        )
        self._env = env

    def acquire(self, stop: threading.Event) -> dict[str, Any] | None:
        item = self._client.brpop(common.QUEUE_KEY, timeout=max(1, int(self._env.poll_interval)))
        if item is None:
            return None
        _key, raw = item
        try:
            job = json.loads(raw)
        except ValueError:
            dead_letter(self._env, {"raw": str(raw)[:2000]}, "queue item is not valid JSON")
            return None
        return job if isinstance(job, dict) else None


class RestSource:
    """Signed REST poller for the WP table queue (the always-available fallback)."""

    name = "rest"

    def __init__(self, env: WorkerEnv) -> None:
        stub = common.BuildPayload(
            build_id=0,
            store_key=env.store_key,
            site_url=env.wp_site_url,
            wp_rest_url=env.wp_rest_url,
            version_name="",
            version_code=0,
            package_name="",
            app_name="",
            hmac_key=env.hmac_key,
        )
        self._client = WPClient(stub)
        self._env = env

    def acquire(self, stop: threading.Event) -> dict[str, Any] | None:
        if stop.is_set():
            return None
        return self._client.poll(worker_id())


def make_source(env: WorkerEnv) -> RedisSource | RestSource:
    if env.queue_mode:
        return RedisSource(env)
    return RestSource(env)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RavakWP Build Engine worker")
    parser.add_argument("--once", action="store_true",
                        help="process one build then exit (used by local/dispatch.php)")
    parser.add_argument("--build-id", type=int, default=None,
                        help="with --once: wait for this specific build id")
    parser.add_argument("--validate", action="store_true",
                        help="validate environment and exit")
    parser.add_argument("--version", action="store_true",
                        help="print engine version and exit")
    args = parser.parse_args(argv)

    if args.version:
        print(f"ravakwp-build-engine {common.ENGINE_VERSION}")
        return 0

    env = WorkerEnv.from_env()
    env.once = args.once or bool(env.extra.get("RVK_ONCE"))
    if args.build_id is not None:
        env.build_id_target = args.build_id

    errors = print_validation(env)
    if args.validate:
        return 2 if errors else 0
    if errors:
        print("راه‌اندازی متوقف شد — متغیرهای محیطی را اصلاح کنید / startup aborted", flush=True)
        return 2

    for directory in (env.workspaces, env.cache_dir, env.gradle_home):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"✖ ساخت پوشه {directory} ممکن نشد / cannot create {directory}: {exc}", flush=True)
            return 2

    banner(env)
    stop = threading.Event()

    def _signal(signum: int, _frame: Any) -> None:
        print(f"[signal] {'SIGTERM' if signum == signal.SIGTERM else 'SIGINT'} — "
              "waiting for running builds to finish…", flush=True)
        stop.set()

    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)

    try:
        source = make_source(env)
    except SystemExit as exc:
        print(str(exc), flush=True)
        return 2

    processed_target = False
    with ThreadPoolExecutor(max_workers=env.concurrency, thread_name_prefix="rvk-build") as pool:
        futures: set[Future] = set()
        while not stop.is_set():
            beat(env)
            try:
                job = source.acquire(stop)
            except Exception as exc:  # noqa: BLE001 — keep the loop alive
                print(f"[queue] acquisition error ({source.name}): {exc}", flush=True)
                stop.wait(3.0)
                continue

            if job is None:
                if not env.queue_mode:  # REST poll already returned quickly
                    jitter = random.uniform(0.0, env.poll_interval * 0.3)
                    stop.wait(env.poll_interval + jitter)
                continue

            build_id = job.get("build_id")
            fut = pool.submit(process_job, job, env, stop)
            futures.add(fut)
            futures = {f for f in futures if not f.done()}

            if env.once and (env.build_id_target is None or build_id == env.build_id_target):
                try:
                    fut.result()
                except Exception as exc:  # noqa: BLE001
                    print(f"[once] job raised: {exc}", flush=True)
                processed_target = True
                break

        # drain: running builds finish, queued-but-unstarted futures cancelled
        for fut in futures:
            fut.cancel()
        if futures:
            print("[signal] draining running builds…", flush=True)
        pool.shutdown(wait=True)

    beat(env)
    if env.once and not processed_target:
        print("[once] no matching job was claimed", flush=True)
        return 3
    print("[worker] bye — محیط ساخت خاموش شد", flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
