package uz.qalqon.security.model

enum class RiskCategory { SAFE, LOW, ATTENTION, SUSPICIOUS, HIGH, KNOWN_MALICIOUS, UNKNOWN }
enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL }

data class RiskReason(
    val title: String,
    val detail: String,
    val weight: Int,
    val ruleId: String = "",
    val severity: Severity = Severity.INFORMATIONAL,
    val confidence: Int = 50,
    val evaluatedAt: Long = System.currentTimeMillis()
)

data class AppSecurityInfo(
    val label: String,
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val targetSdk: Int,
    val systemApp: Boolean,
    val installerPackage: String?,
    val requestedPermissions: List<String>,
    val grantedPermissions: List<String>,
    val certificateSha256: String?,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val riskScore: Int,
    val permissionRiskScore: Int,
    val category: RiskCategory,
    val reasons: List<RiskReason>,
    val signingCertificateSha256History: List<String> = emptyList(),
    val debuggable: Boolean = false
)

data class DeviceSecurityInfo(
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val sdk: Int,
    val securityPatch: String,
    val screenLockSecure: Boolean,
    val developerOptions: Boolean,
    val adbEnabled: Boolean,
    val score: Int,
    val reasons: List<RiskReason>
)

data class DashboardState(
    val loading: Boolean = false,
    val scanProcessed: Int = 0,
    val scanTotal: Int = 0,
    val totalApps: Int = 0,
    val safeApps: Int = 0,
    val attentionApps: Int = 0,
    val suspiciousApps: Int = 0,
    val highRiskApps: Int = 0,
    val appSecurityScore: Int? = null,
    val permissionSecurityScore: Int? = null,
    val deviceSecurityScore: Int? = null,
    val webSecurityScore: Int? = null,
    val privacySecurityScore: Int? = null,
    val overallSecurityScore: Int? = null,
    val lastScanAt: Long? = null,
    val device: DeviceSecurityInfo? = null
)

data class ApkScanResult(
    val displayName: String,
    val packageName: String?,
    val versionName: String?,
    val targetSdk: Int?,
    val sizeBytes: Long,
    val sha256: String,
    val certificateSha256: String?,
    val requestedPermissions: List<String>,
    val localRiskScore: Int,
    val riskScore: Int,
    val category: RiskCategory,
    val reasons: List<RiskReason>,
    val reputation: String = "unknown",
    val analysisComplete: Boolean = true,
    val archiveValid: Boolean = true,
    val archiveEntries: Int = 0,
    val uncompressedBytes: Long = 0L
)

data class UrlScanResult(
    val normalizedUrl: String,
    val host: String,
    val riskScore: Int,
    val category: RiskCategory,
    val reasons: List<RiskReason>,
    val reputation: String = "unknown"
)

data class ScanSnapshot(
    val id: Long = 0,
    val timestamp: Long,
    val overallScore: Int,
    val totalApps: Int,
    val suspiciousApps: Int,
    val highRiskApps: Int
)
