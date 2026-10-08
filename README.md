# QALQON — Android Security Platform

QALQON is a real-device-data-first Android security project. Production UI values are calculated from Android APIs, APK metadata, deterministic heuristics, local history, or an optional reputation backend. The project does not intentionally ship fake virus counts or random security scores.

## What works in this master project

- Kotlin + Jetpack Compose Android app
- Real installed-app inventory via `PackageManager`
- Deterministic per-app risk engine based on real permissions, install source, target SDK and signing metadata
- Real device-security checks (secure lock screen, security patch age, developer/ADB state where readable)
- Real dashboard counts and percentages computed at runtime
- Manual full scan with real progress (`processed / total`)
- APK picker using Storage Access Framework
- APK SHA-256 calculation, archive metadata, permissions and signing certificate fingerprint
- URL/link heuristic scanner with optional backend reputation lookup
- Package install/update/remove event receiver + WorkManager background analysis
- Notifications only for actual package events/findings
- SQLite scan history
- Uzbek default UI + English + Russian resources
- Dark / Light / System theme
- Official QALQON icon included and padded for Android adaptive launcher masks
- Optional FastAPI + PostgreSQL reputation backend (unknown stays unknown; no seeded fake threats)

## Android build (Windows — easiest)

Prerequisites:

1. Android Studio installed with Android SDK 35.
2. JDK 17+ (`JAVA_HOME` configured). Android Studio's bundled JDK can also be used.
3. Internet connection for the first Gradle/dependency download.

From the extracted project folder run:

```bat
BUILD_APK.bat
```

The helper downloads Gradle 8.10.2 locally if needed and runs `:app:assembleDebug`.
After a successful build it copies the installable APK to:

```text
dist/Qalqon-debug.apk
```

You can also open the `android` folder directly in Android Studio and use **Build > Build APK(s)**.

> Release signing keys/passwords are deliberately NOT included. Do not put production keystores or passwords in source control.

## Optional cloud reputation backend

The Android app works without the backend. With no configured backend it returns `UNKNOWN` for cloud reputation and continues local analysis.

Start backend locally:

```bash
cd backend
cp .env.example .env
docker compose up --build
```

To compile Android with your HTTPS backend URL:

```text
QALQON_BACKEND_URL=https://security.example.com
```

Set that as a Gradle property (`~/.gradle/gradle.properties` or project gradle.properties for local testing). Production should use HTTPS.

## Important Android limitation

QALQON is not Device Owner and does not bypass the Android sandbox. It cannot honestly promise full control of another app or all phone activity. It uses supported Android security APIs, package events, background work, and explicit user actions. If Android does not expose a fact, the app must show it as unavailable/restricted rather than inventing it.

## Google Play note

`QUERY_ALL_PACKAGES` is declared because installed-app analysis is a core antivirus/security function. Google Play applies policy review to broad app visibility. If you publish QALQON, complete the required declarations and keep package inventory use strictly tied to the security feature.
