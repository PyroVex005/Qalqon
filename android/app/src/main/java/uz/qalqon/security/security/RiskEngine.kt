package uz.qalqon.security.security

import android.Manifest
import android.os.Build
import uz.qalqon.security.model.*
import kotlin.math.roundToInt

object RiskEngine {
    private val permissionWeights = mapOf(
        Manifest.permission.READ_SMS to 16,
        Manifest.permission.RECEIVE_SMS to 10,
        Manifest.permission.SEND_SMS to 14,
        Manifest.permission.READ_CONTACTS to 8,
        Manifest.permission.WRITE_CONTACTS to 8,
        Manifest.permission.RECORD_AUDIO to 10,
        Manifest.permission.CAMERA to 6,
        Manifest.permission.ACCESS_FINE_LOCATION to 7,
        Manifest.permission.ACCESS_COARSE_LOCATION to 4,
        Manifest.permission.ACCESS_BACKGROUND_LOCATION to 11,
        Manifest.permission.READ_PHONE_STATE to 6,
        Manifest.permission.CALL_PHONE to 8,
        Manifest.permission.READ_CALL_LOG to 13,
        Manifest.permission.WRITE_CALL_LOG to 13,
        Manifest.permission.REQUEST_INSTALL_PACKAGES to 15,
        Manifest.permission.SYSTEM_ALERT_WINDOW to 15,
        Manifest.permission.MANAGE_EXTERNAL_STORAGE to 12
    )

    data class Evaluation(
        val totalRisk: Int,
        val permissionRisk: Int,
        val category: RiskCategory,
        val reasons: List<RiskReason>
    )

    fun evaluateApp(
        requested: List<String>,
        granted: List<String>,
        installer: String?,
        systemApp: Boolean,
        targetSdk: Int,
        certificateSha256: String?,
        debuggable: Boolean = false
    ): Evaluation {
        val reasons = mutableListOf<RiskReason>()
        var permissionRisk = 0
        permissionWeights.forEach { (permission, weight) ->
            when {
                granted.contains(permission) -> {
                    permissionRisk += weight
                    reasons += reason(
                        "PERM_GRANTED_${permission.substringAfterLast('.').uppercase()}",
                        "Sezgir ruxsat",
                        friendlyPermission(permission),
                        weight,
                        if (weight >= 13) Severity.MEDIUM else Severity.LOW,
                        95
                    )
                }
                requested.contains(permission) -> {
                    val pending = (weight / 4).coerceAtLeast(1)
                    permissionRisk += pending
                    reasons += reason(
                        "PERM_REQUESTED_${permission.substringAfterLast('.').uppercase()}",
                        "So‘ralgan sezgir ruxsat",
                        friendlyPermission(permission),
                        pending,
                        Severity.INFORMATIONAL,
                        95
                    )
                }
            }
        }

        val grantedSensitive = granted.filter { permissionWeights.containsKey(it) }
        if (grantedSensitive.size >= 4) {
            permissionRisk += 10
            reasons += reason("PERM_COMBO_MANY", "Ruxsatlar kombinatsiyasi", "Bir nechta sezgir imkoniyat bir vaqtda berilgan", 10, Severity.MEDIUM, 80)
        }
        if (granted.contains(Manifest.permission.SYSTEM_ALERT_WINDOW) && granted.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES)) {
            permissionRisk += 20
            reasons += reason("PERM_COMBO_OVERLAY_INSTALL", "Yuqori xavfli kombinatsiya", "Boshqa ilovalar ustida ko‘rsatish va APK o‘rnatishni so‘rash birga berilgan", 20, Severity.HIGH, 88)
        }
        if ((granted.contains(Manifest.permission.READ_SMS) || granted.contains(Manifest.permission.RECEIVE_SMS)) && granted.contains(Manifest.permission.READ_CONTACTS)) {
            permissionRisk += 12
            reasons += reason("PERM_COMBO_SMS_CONTACTS", "Maxfiylikka sezgir kombinatsiya", "SMS va kontakt ma’lumotlariga birgalikda kirish mumkin", 12, Severity.MEDIUM, 85)
        }
        if (granted.contains(Manifest.permission.RECORD_AUDIO) && granted.contains(Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
            permissionRisk += 10
            reasons += reason("PERM_COMBO_MIC_BG_LOCATION", "Maxfiylikka sezgir kombinatsiya", "Mikrofon va fon joylashuvi birga berilgan", 10, Severity.MEDIUM, 82)
        }
        permissionRisk = permissionRisk.coerceIn(0, 100)

        var otherRisk = 0
        if (!systemApp && installer.isNullOrBlank()) {
            otherRisk += 9
            reasons += reason("INSTALLER_UNKNOWN", "O‘rnatish manbasi noma’lum", "Android ishonchli installer nomini qaytarmadi; bu o‘zi malware isboti emas", 9, Severity.LOW, 65)
        }
        val sdkGap = (Build.VERSION.SDK_INT - targetSdk).coerceAtLeast(0)
        if (sdkGap >= 8) {
            otherRisk += 16
            reasons += reason("TARGET_SDK_VERY_OLD", "Juda eski target SDK", "Ilova Android $targetSdk API uchun mo‘ljallangan va zamonaviy himoyalardan kamroq foydalanishi mumkin", 16, Severity.MEDIUM, 92)
        } else if (sdkGap >= 5) {
            otherRisk += 9
            reasons += reason("TARGET_SDK_OLD", "Eski target SDK", "Ilova zamonaviy Android himoyalaridan to‘liq foydalanmasligi mumkin", 9, Severity.LOW, 88)
        }
        if (certificateSha256.isNullOrBlank()) {
            otherRisk += 5
            reasons += reason("SIGNING_INFO_UNAVAILABLE", "Imzo ma’lumoti mavjud emas", "Signing sertifikati olinmadi; tekshiruv qisman yakunlandi", 5, Severity.INFORMATIONAL, 90)
        }
        if (debuggable && !systemApp) {
            otherRisk += 7
            reasons += reason("APP_DEBUGGABLE", "Debuggable ilova", "Ilova production qurilmada debug rejimida ishlashga ruxsat beradi", 7, Severity.LOW, 90)
        }

        val total = (permissionRisk * 0.62 + otherRisk).roundToInt().coerceIn(0, 100)
        return Evaluation(total, permissionRisk, categoryFor(total), reasons.sortedByDescending { it.weight })
    }

    fun evaluateApk(requested: List<String>, targetSdk: Int?, certificateSha256: String?): Evaluation =
        evaluateApp(
            requested = requested,
            granted = emptyList(),
            installer = "selected-apk",
            systemApp = false,
            targetSdk = targetSdk ?: Build.VERSION.SDK_INT,
            certificateSha256 = certificateSha256
        )

    fun applyReputation(localRisk: Int, reputation: String): Pair<Int, RiskCategory> = when (reputation.lowercase()) {
        "known_malicious" -> 100 to RiskCategory.KNOWN_MALICIOUS
        "suspicious" -> (localRisk + 25).coerceAtMost(95).let { it to categoryFor(it) }
        "clean" -> localRisk to categoryFor(localRisk)
        else -> localRisk to categoryFor(localRisk)
    }

    fun categoryFor(score: Int): RiskCategory = when (score.coerceIn(0, 100)) {
        in 0..19 -> RiskCategory.SAFE
        in 20..39 -> RiskCategory.LOW
        in 40..59 -> RiskCategory.ATTENTION
        in 60..79 -> RiskCategory.SUSPICIOUS
        else -> RiskCategory.HIGH
    }

    fun buildDashboard(apps: List<AppSecurityInfo>, device: DeviceSecurityInfo, webScore: Int?, lastScan: Long): DashboardState {
        val appScore = if (apps.isEmpty()) null else (100 - apps.map { it.riskScore }.average().roundToInt()).coerceIn(0,100)
        val permissionScore = if (apps.isEmpty()) null else (100 - apps.map { it.permissionRiskScore }.average().roundToInt()).coerceIn(0,100)
        val privacyScore = permissionScore
        val weighted = mutableListOf<Pair<Int, Double>>()
        appScore?.let { weighted += it to 0.40 }
        permissionScore?.let { weighted += it to 0.25 }
        weighted += device.score to 0.25
        webScore?.let { weighted += it to 0.10 }
        val weightSum = weighted.sumOf { it.second }
        val overall = if (weightSum == 0.0) null else (weighted.sumOf { it.first * it.second } / weightSum).roundToInt().coerceIn(0,100)
        return DashboardState(
            loading = false,
            totalApps = apps.size,
            safeApps = apps.count { it.category == RiskCategory.SAFE || it.category == RiskCategory.LOW },
            attentionApps = apps.count { it.category == RiskCategory.ATTENTION },
            suspiciousApps = apps.count { it.category == RiskCategory.SUSPICIOUS },
            highRiskApps = apps.count { it.category == RiskCategory.HIGH || it.category == RiskCategory.KNOWN_MALICIOUS },
            appSecurityScore = appScore,
            permissionSecurityScore = permissionScore,
            deviceSecurityScore = device.score,
            webSecurityScore = webScore,
            privacySecurityScore = privacyScore,
            overallSecurityScore = overall,
            lastScanAt = lastScan,
            device = device
        )
    }

    private fun reason(id: String, title: String, detail: String, weight: Int, severity: Severity, confidence: Int) =
        RiskReason(title, detail, weight, id, severity, confidence)

    private fun friendlyPermission(permission: String): String = when (permission) {
        Manifest.permission.READ_SMS -> "SMS xabarlarini o‘qish"
        Manifest.permission.RECEIVE_SMS -> "SMS qabul qilish"
        Manifest.permission.SEND_SMS -> "SMS yuborish"
        Manifest.permission.READ_CONTACTS -> "Kontaktlarni o‘qish"
        Manifest.permission.WRITE_CONTACTS -> "Kontaktlarni o‘zgartirish"
        Manifest.permission.RECORD_AUDIO -> "Mikrofondan foydalanish"
        Manifest.permission.CAMERA -> "Kameradan foydalanish"
        Manifest.permission.ACCESS_FINE_LOCATION -> "Aniq joylashuv"
        Manifest.permission.ACCESS_COARSE_LOCATION -> "Taxminiy joylashuv"
        Manifest.permission.ACCESS_BACKGROUND_LOCATION -> "Fon rejimida joylashuv"
        Manifest.permission.READ_PHONE_STATE -> "Telefon holatini o‘qish"
        Manifest.permission.CALL_PHONE -> "Qo‘ng‘iroq qilish"
        Manifest.permission.READ_CALL_LOG -> "Qo‘ng‘iroqlar tarixini o‘qish"
        Manifest.permission.WRITE_CALL_LOG -> "Qo‘ng‘iroqlar tarixini o‘zgartirish"
        Manifest.permission.REQUEST_INSTALL_PACKAGES -> "APK o‘rnatishni so‘rash"
        Manifest.permission.SYSTEM_ALERT_WINDOW -> "Boshqa ilovalar ustida ko‘rsatish"
        Manifest.permission.MANAGE_EXTERNAL_STORAGE -> "Kengaytirilgan fayl tizimi ruxsati"
        else -> permission.substringAfterLast('.')
    }
}
