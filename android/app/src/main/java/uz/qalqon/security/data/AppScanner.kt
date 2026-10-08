package uz.qalqon.security.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import uz.qalqon.security.model.AppSecurityInfo
import uz.qalqon.security.model.AssessmentStatus
import uz.qalqon.security.security.RiskEngine
import java.security.MessageDigest

class AppScanner(private val context: Context) {
    private val pm = context.packageManager

    fun scanInstalledApps(onProgress: ((Int, Int) -> Unit)? = null): List<AppSecurityInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SERVICES
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
        }
        val result = ArrayList<AppSecurityInfo>(packages.size)
        packages.forEachIndexed { index, info ->
            runCatching { toSecurityInfo(info) }.getOrNull()?.let(result::add)
            onProgress?.invoke(index + 1, packages.size)
        }
        return result.sortedBy { it.label.lowercase() }
    }

    fun scanPackage(packageName: String): AppSecurityInfo? = runCatching {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        val info = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getPackageInfo(packageName, flags)
        }
        toSecurityInfo(info)
    }.getOrNull()

    private fun toSecurityInfo(info: PackageInfo): AppSecurityInfo {
        val ai = requireNotNull(info.applicationInfo)
        val label = pm.getApplicationLabel(ai).toString()
        val requested = info.requestedPermissions?.toList().orEmpty()
        val granted = requested.filterIndexed { index, _ ->
            (info.requestedPermissionsFlags?.getOrNull(index) ?: 0) and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }
        val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(info.packageName).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(info.packageName)
        }.getOrNull()
        val cert = signingSha256(info)
        val evaluation = RiskEngine.evaluateApp(requested, granted, installer, system, ai.targetSdkVersion, cert)
        val servicePermissions = info.services?.mapNotNull { it.permission }?.toSet().orEmpty()
        val capabilityReasons = mutableListOf<uz.qalqon.security.model.RiskReason>()
        var capabilityRisk = 0

        if ("android.permission.BIND_ACCESSIBILITY_SERVICE" in servicePermissions) {
            capabilityRisk += 8
            capabilityReasons += uz.qalqon.security.model.RiskReason(
                "Accessibility xizmati e’lon qilingan",
                "Ilova Accessibility Service imkoniyatini e’lon qilgan. Bu o‘zi zararli degani emas, ammo juda kuchli nazorat imkoniyatidir.",
                8
            )
        }
        if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" in servicePermissions) {
            capabilityRisk += 5
            capabilityReasons += uz.qalqon.security.model.RiskReason(
                "Notification listener e’lon qilingan",
                "Ilova bildirishnomalarni o‘qish uchun servis e’lon qilgan.",
                5
            )
        }
        if ("android.permission.BIND_VPN_SERVICE" in servicePermissions) {
            capabilityRisk += 4
            capabilityReasons += uz.qalqon.security.model.RiskReason(
                "VPN xizmati e’lon qilingan",
                "Ilova VPN tunnelini yaratish imkoniyatini e’lon qilgan.",
                4
            )
        }

        if (
            "android.permission.BIND_ACCESSIBILITY_SERVICE" in servicePermissions &&
            requested.contains(android.Manifest.permission.REQUEST_INSTALL_PACKAGES) &&
            requested.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW)
        ) {
            capabilityRisk += 18
            capabilityReasons += uz.qalqon.security.model.RiskReason(
                "Kuchli boshqaruv kombinatsiyasi",
                "Accessibility, APK o‘rnatish va overlay imkoniyatlari bir ilovada jamlangan.",
                18
            )
        }

        val finalRisk = (evaluation.totalRisk + capabilityRisk).coerceIn(0, 100)
        return AppSecurityInfo(
            label = label,
            packageName = info.packageName,
            versionName = info.versionName ?: "—",
            versionCode = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong(),
            targetSdk = ai.targetSdkVersion,
            systemApp = system,
            installerPackage = installer,
            requestedPermissions = requested,
            grantedPermissions = granted,
            certificateSha256 = cert,
            firstInstallTime = info.firstInstallTime,
            lastUpdateTime = info.lastUpdateTime,
            riskScore = finalRisk,
            permissionRiskScore = evaluation.permissionRisk,
            category = RiskEngine.categoryFor(finalRisk),
            reasons = (evaluation.reasons + capabilityReasons).sortedByDescending { it.weight },
            assessmentStatus = when {
                finalRisk >= 60 -> AssessmentStatus.SUSPICIOUS
                cert.isNullOrBlank() -> AssessmentStatus.UNKNOWN
                else -> AssessmentStatus.NO_KNOWN_THREAT_DETECTED
            }
        )
    }

    private fun signingSha256(info: PackageInfo): String? = runCatching {
        if (Build.VERSION.SDK_INT < 28) return@runCatching null
        val signingInfo = info.signingInfo ?: return@runCatching null
        val cert = signingInfo.apkContentsSigners.firstOrNull() ?: return@runCatching null
        MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { "%02X".format(it) }
    }.getOrNull()
}
