"""RavakWP build-engine worker package.

One codebase, two deployment modes (BUILD-ENGINE-SPEC §0):
  * local  — the same container running on the WordPress host
  * remote — the same container on a separate Linux worker box
Only WHERE it runs and HOW jobs are acquired differ (Redis optional,
REST table-queue fallback always available).
"""

ENGINE_VERSION = "1.0.0"
