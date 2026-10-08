package uz.qalqon.security.model

enum class RiskCategory { SAFE, LOW, ATTENTION, SUSPICIOUS, HIGH, KNOWN_MALICIOUS, UNKNOWN }

enum class RiskSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL }

enum class AssessmentStatus {
    CONFIRMED_KNOWN_THREAT,
    SUSPICIOUS,
    NO_KNOWN_THREAT_DETECTED,
    UNKNOWN,
    SCAN_INCOMPLETE
}

data class RiskReason(
    val title: String,
    val detail: String,
    val weight: Int,
    val ruleId: String = "legacy",
    val severity: RiskSeverity = RiskSeverity.INFORMATIONAL,
    val confidence: Int = 50,
    val recommendedAction: String = "",
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
    val assessmentStatus: AssessmentStatus = AssessmentStatus.UNKNOWN
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
    val archiveValid: Boolean = true,
    val assessmentStatus: AssessmentStatus = AssessmentStatus.UNKNOWN
)

data class UrlScanResult(
    val normalizedUrl: String,
    val host: String,
    val riskScore: Int,
    val category: RiskCategory,
    val reasons: List<RiskReason>,
    val reputation: String = "unknown",
    val assessmentStatus: AssessmentStatus = AssessmentStatus.UNKNOWN
)

data class ScanSnapshot(
    val id: Long = 0,
    val timestamp: Long,
    val overallScore: Int,
    val totalApps: Int,
    val suspiciousApps: Int,
    val highRiskApps: Int
)
