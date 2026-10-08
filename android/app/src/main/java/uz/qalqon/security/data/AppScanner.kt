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
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
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
            riskScore = evaluation.totalRisk,
            permissionRiskScore = evaluation.permissionRisk,
            category = evaluation.category,
            reasons = evaluation.reasons,
            assessmentStatus = when {
                evaluation.totalRisk >= 60 -> AssessmentStatus.SUSPICIOUS
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
