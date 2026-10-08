$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$GradleVersion = "8.10.2"
$Tools = Join-Path $Root ".tools"
$GradleHome = Join-Path $Tools "gradle-$GradleVersion"
$GradleBat = Join-Path $GradleHome "bin\gradle.bat"

New-Item -ItemType Directory -Force -Path $Tools | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root "dist") | Out-Null

if (-not (Test-Path $GradleBat)) {
    $Zip = Join-Path $Tools "gradle-$GradleVersion-bin.zip"
    Write-Host "Downloading Gradle $GradleVersion..."
    Invoke-WebRequest -Uri "https://services.gradle.org/distributions/gradle-$GradleVersion-bin.zip" -OutFile $Zip
    Expand-Archive -Path $Zip -DestinationPath $Tools -Force
}

if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    Write-Host "ANDROID_HOME/ANDROID_SDK_ROOT is not set. Android Studio normally configures an SDK." -ForegroundColor Yellow
    Write-Host "If the build cannot find the SDK, create android\local.properties with sdk.dir=C:\\Users\\YOU\\AppData\\Local\\Android\\Sdk"
}

Push-Location (Join-Path $Root "android")
try {
    & $GradleBat --no-daemon :app:assembleDebug
    if ($LASTEXITCODE -ne 0) { throw "Gradle returned exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

$Apk = Join-Path $Root "android\app\build\outputs\apk\debug\app-debug.apk"
if (-not (Test-Path $Apk)) { throw "Build completed but APK was not found at $Apk" }
$Out = Join-Path $Root "dist\Qalqon-debug.apk"
Copy-Item $Apk $Out -Force
Write-Host ""
Write-Host "SUCCESS: $Out" -ForegroundColor Green
