@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-apk.ps1"
if errorlevel 1 (
  echo.
  echo QALQON build failed. Read the error above.
  exit /b 1
)
endlocal
