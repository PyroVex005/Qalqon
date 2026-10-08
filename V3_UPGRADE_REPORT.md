# QALQON Ultimate V3.0 upgrade report

This upgrade modifies the existing `uz.qalqon.security` project instead of replacing it.

## Preserved
- QALQON name, icon resources, package namespace, Compose navigation and existing local data stores.
- Existing installed-app, APK, URL, history and settings flows.

## V3 security changes
- 500 MB streamed APK input cap.
- APK ZIP structure validation before Android metadata parsing.
- Entry-count, expanded-size, single-entry and suspicious compression-ratio limits.
- Path traversal detection without extracting APK content.
- Explicit incomplete-analysis state for malformed APK files.
- Explainable risk rules now carry rule IDs, severity and confidence.
- Stronger sensitive-permission combination checks.
- Initial automatic assessment and battery/storage-aware 12-hour WorkManager checks.
- Debounced package-added/package-updated scans.
- Notification permission/state verification before alerts.
- Automated unit tests and Android lint in CI.

## Android limits
QALQON does not claim universal install blocking, unrestricted browser interception or guaranteed continuous 24/7 monitoring. Heuristic risk is evidence for review, not proof of malware.
