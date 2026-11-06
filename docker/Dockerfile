# syntax=docker/dockerfile:1
# =============================================================================
# RavakWP Build Engine — Android (Kotlin/Compose) build image  (≈2.2 GB)
# -----------------------------------------------------------------------------
# Multi-stage:
#   stage 1 "sdk"    : downloads Android cmdline-tools + SDK 34 packages and
#                      Gradle 8.7 (all large, cache-friendly layers)
#   stage 2 "runtime": JDK17 base + SDK/Gradle from stage 1 + Python worker
# Build:  docker build -t ravakwp/build-engine .
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Android SDK + Gradle (~1.9 GB of layers, changes rarely)
# ---------------------------------------------------------------------------
FROM eclipse-temurin:17-jdk-jammy AS sdk

ENV ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk

# curl + unzip only (~3 MB) — apt list cleanup keeps the layer thin
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Android command-line-tools (~150 MB unpacked). Pinned version so builds are
# reproducible; installed under cmdline-tools/latest so sdkmanager works.
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -fsSLo /tmp/cmdline-tools.zip \
         https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    && unzip -q /tmp/cmdline-tools.zip -d ${ANDROID_HOME}/cmdline-tools \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && rm -f /tmp/cmdline-tools.zip

# Accept ALL licenses before installing packages (yes | sdkmanager --licenses)
RUN yes | ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager --licenses > /dev/null

# SDK packages (~330 MB): platform-tools, platform 34, build-tools 34.0.0
# (build-tools ships apksigner + zipalign used by the signing stage)
RUN ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager \
        "platform-tools" "platforms;android-34" "build-tools;34.0.0"

# Gradle 8.7 binary (~130 MB) → /opt/gradle (no wrapper downloads at build time)
RUN curl -fsSLo /tmp/gradle.zip https://services.gradle.org/distributions/gradle-8.7-bin.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && mv /opt/gradle-8.7 /opt/gradle \
    && rm -f /tmp/gradle.zip

# ---------------------------------------------------------------------------
# Stage 2 — runtime (~2.2 GB total)
# ---------------------------------------------------------------------------
FROM eclipse-temurin:17-jdk-jammy

# Temurin's JDK lives at /opt/java/openjdk (keytool for keystore generation)
ENV JAVA_HOME=/opt/java/openjdk \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    GRADLE_HOME=/opt/gradle \
    PATH=/opt/gradle/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/build-tools/34.0.0:/opt/java/openjdk/bin:${PATH}

# Copy the SDK + Gradle from stage 1 (single COPY each keeps layers lean)
COPY --from=sdk /opt/android-sdk /opt/android-sdk
COPY --from=sdk /opt/gradle /opt/gradle

# python3 + pip (~50 MB) — worker runtime; no apt lists kept
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Worker code (changes on every engine release → last layers)
COPY worker/ /opt/worker/
COPY docker/entrypoint.sh /opt/worker/entrypoint.sh
RUN chmod +x /opt/worker/entrypoint.sh \
    && pip3 install --no-cache-dir -r /opt/worker/requirements.txt

# Persistence points (mount as volumes in docker-compose)
#   /var/lib/ravakwp/workspaces  — per-build sandboxes (spec §3 tenancy)
#   /var/lib/ravakwp/templates   — template zip cache by template_ref
#   /var/lib/ravakwp/gradle-home — Gradle dependency cache (huge speed-up)
RUN mkdir -p /var/lib/ravakwp/workspaces /var/lib/ravakwp/templates /var/lib/ravakwp/gradle-home

ENV WORKER_MODE=local \
    WP_SITE_URL="" \
    WP_HMAC_KEY="" \
    REDIS_URL="" \
    WORKER_CONCURRENCY=1 \
    RVK_WORKSPACES=/var/lib/ravakwp/workspaces \
    RVK_CACHE_DIR=/var/lib/ravakwp/templates \
    RVK_GRADLE_HOME=/var/lib/ravakwp/gradle-home

VOLUME ["/var/lib/ravakwp/workspaces"]

# HEALTHCHECK: the worker touches a heartbeat file on every loop iteration
# and during long builds; freshness window is 90s (poll cycle is 5s).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python3", "-c", "import os,sys,time; p=os.environ.get('RVK_HEARTBEAT','/var/lib/ravakwp/worker-heartbeat'); p=p if os.path.exists(p) else '/tmp/rvk-worker-heartbeat'; sys.exit(0 if os.path.exists(p) and (time.time()-os.path.getmtime(p))<90 else 1)"]

# Same entrypoint as the spec (§4); docker/entrypoint.sh is the alternative
# wrapper used by compose / one-shot runs (mkdirs + umask + exec python3).
WORKDIR /opt/worker
ENTRYPOINT ["python3", "/opt/worker/worker.py"]
