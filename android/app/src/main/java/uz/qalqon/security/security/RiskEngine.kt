package uz.qalqon.security.security

import android.Manifest
import android.os.Build
import uz.qalqon.security.model.*
import kotlin.math.roundToInt

object RiskEngine {
    private val permissionWeights = mapOf(
        Manifest.permission.READ_SMS to 15,
        Manifest.permission.RECEIVE_SMS to 10,
        Manifest.permission.SEND_SMS to 12,
        Manifest.permission.READ_CONTACTS to 8,
        Manifest.permission.WRITE_CONTACTS to 8,
        Manifest.permission.RECORD_AUDIO to 10,
        Manifest.permission.CAMERA to 6,
        Manifest.permission.ACCESS_FINE_LOCATION to 7,
        Manifest.permission.ACCESS_COARSE_LOCATION to 4,
        Manifest.permission.READ_PHONE_STATE to 6,
        Manifest.permission.CALL_PHONE to 8,
        Manifest.permission.READ_CALL_LOG to 12,
        Manifest.permission.WRITE_CALL_LOG to 12,
        Manifest.permission.REQUEST_INSTALL_PACKAGES to 12,
        Manifest.permission.SYSTEM_ALERT_WINDOW to 12
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
        certificateSha256: String?
    ): Evaluation {
        val reasons = mutableListOf<RiskReason>()
        var permissionRisk = 0
        permissionWeights.forEach { (permission, weight) ->
            when {
                granted.contains(permission) -> {
                    permissionRisk += weight
                    reasons += RiskReason("Sezgir ruxsat", friendlyPermission(permission), weight)
                }
                requested.contains(permission) -> {
                    val pending = (weight / 3).coerceAtLeast(1)
                    permissionRisk += pending
                    reasons += RiskReason("So‘ralgan sezgir ruxsat", friendlyPermission(permission), pending)
                }
            }
        }
        if (granted.count { permissionWeights.containsKey(it) } >= 4) {
            permissionRisk += 10
            reasons += RiskReason("Ruxsatlar kombinatsiyasi", "Bir nechta sezgir imkoniyat bir vaqtda berilgan", 10)
        }
        permissionRisk = permissionRisk.coerceIn(0, 100)

        var otherRisk = 0
        if (!systemApp && installer.isNullOrBlank()) {
            otherRisk += 10
            reasons += RiskReason("O‘rnatish manbasi noma’lum", "Android ishonchli installer nomini qaytarmadi", 10)
        }
        val sdkGap = Build.VERSION.SDK_INT - targetSdk
        if (sdkGap >= 8) {
            otherRisk += 14
            reasons += RiskReason("Juda eski target SDK", "Ilova Android $targetSdk API uchun mo‘ljallangan", 14)
        } else if (sdkGap >= 5) {
            otherRisk += 8
            reasons += RiskReason("Eski target SDK", "Ilova zamonaviy Android himoyalaridan to‘liq foydalanmasligi mumkin", 8)
        }
        if (certificateSha256.isNullOrBlank()) {
            otherRisk += 5
            reasons += RiskReason("Imzo ma’lumoti mavjud emas", "Signing sertifikati olinmadi", 5)
        }

        val total = (permissionRisk * 0.65 + otherRisk).roundToInt().coerceIn(0, 100)
        return Evaluation(total, permissionRisk, categoryFor(total), reasons.sortedByDescending { it.weight })
    }

    fun evaluateApk(requested: List<String>, targetSdk: Int?, certificateSha256: String?): Evaluation {
        val grantedAssumption = emptyList<String>()
        val base = evaluateApp(requested, grantedAssumption, installer = "selected-apk", systemApp = false,
            targetSdk = targetSdk ?: Build.VERSION.SDK_INT, certificateSha256 = certificateSha256)
        return base
    }

    fun applyReputation(localRisk: Int, reputation: String): Pair<Int, RiskCategory> {
        return when (reputation.lowercase()) {
            "known_malicious" -> 100 to RiskCategory.KNOWN_MALICIOUS
            "suspicious" -> (localRisk + 25).coerceAtMost(95) to categoryFor((localRisk + 25).coerceAtMost(95))
            else -> localRisk to categoryFor(localRisk)
        }
    }

    fun categoryFor(score: Int): RiskCategory = when (score) {
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
        Manifest.permission.READ_PHONE_STATE -> "Telefon holatini o‘qish"
        Manifest.permission.CALL_PHONE -> "Qo‘ng‘iroq qilish"
        Manifest.permission.READ_CALL_LOG -> "Qo‘ng‘iroqlar tarixini o‘qish"
        Manifest.permission.WRITE_CALL_LOG -> "Qo‘ng‘iroqlar tarixini o‘zgartirish"
        Manifest.permission.REQUEST_INSTALL_PACKAGES -> "APK o‘rnatishni so‘rash"
        Manifest.permission.SYSTEM_ALERT_WINDOW -> "Boshqa ilovalar ustida ko‘rsatish"
        else -> permission.substringAfterLast('.')
    }
}
