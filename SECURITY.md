# Security principles

- No random or hardcoded production threat results.
- Unknown reputation is never silently converted to safe.
- APKs are parsed as untrusted input and never executed by QALQON.
- APK file contents are not uploaded by default; only SHA-256 is sent when cloud reputation is configured.
- No Accessibility abuse, silent uninstall, silent permission granting, password interception, or hidden device control.
- Backend secrets and signing keys must not be stored in the APK.
- Use HTTPS for any production backend.
