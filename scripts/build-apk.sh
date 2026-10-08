#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GRADLE_VERSION=8.10.2
TOOLS="$ROOT/.tools"
GRADLE_HOME="$TOOLS/gradle-$GRADLE_VERSION"
mkdir -p "$TOOLS" "$ROOT/dist"
if [ ! -x "$GRADLE_HOME/bin/gradle" ]; then
  ZIP="$TOOLS/gradle-$GRADLE_VERSION-bin.zip"
  curl -L "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" -o "$ZIP"
  unzip -q -o "$ZIP" -d "$TOOLS"
fi
"$GRADLE_HOME/bin/gradle" -p "$ROOT/android" --no-daemon :app:assembleDebug
cp "$ROOT/android/app/build/outputs/apk/debug/app-debug.apk" "$ROOT/dist/Qalqon-debug.apk"
echo "SUCCESS: $ROOT/dist/Qalqon-debug.apk"
