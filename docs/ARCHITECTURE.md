# Architecture

Android flow:

`Android API / selected file / reputation API -> repository/scanner -> deterministic RiskEngine -> MainViewModel StateFlow -> Compose UI`

The Compose UI never owns authoritative risk counts. It renders `DashboardState` generated from current scan output.

Automatic protection is event-driven: package broadcasts enqueue a WorkManager task. A daily WorkManager job refreshes cached security state without high-frequency polling.
