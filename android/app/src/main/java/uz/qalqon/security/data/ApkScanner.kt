package uz.qalqon.security.data

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import uz.qalqon.security.model.ApkScanResult
import uz.qalqon.security.security.RiskEngine
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

class ApkScanner(private val context: Context) {
    fun scan(uri: Uri): ApkScanResult {
        val resolver = context.contentResolver
        var displayName = "selected.apk"
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) displayName = c.getString(0) ?: displayName
        }
        val temp = File.createTempFile("qalqon_", ".apk", context.cacheDir)
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        try {
            resolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "APK faylini o‘qib bo‘lmadi" }
                FileOutputStream(temp).use { out ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buffer)
                        if (n <= 0) break
                        digest.update(buffer, 0, n)
                        out.write(buffer, 0, n)
                        size += n
                        require(size <= 2L * 1024 * 1024 * 1024) { "APK hajmi 2 GB dan katta" }
                    }
                }
            }
            val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
            val info = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageArchiveInfo(temp.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") context.packageManager.getPackageArchiveInfo(temp.absolutePath, flags)
            }
            val requested = info?.requestedPermissions?.toList().orEmpty()
            val target = info?.applicationInfo?.targetSdkVersion
            val cert = runCatching {
                if (Build.VERSION.SDK_INT < 28) null else info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()?.let {
                    MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02X".format(b) }
                }
            }.getOrNull()
            val eval = RiskEngine.evaluateApk(requested, target, cert)
            return ApkScanResult(
                displayName = displayName,
                packageName = info?.packageName,
                versionName = info?.versionName,
                targetSdk = target,
                sizeBytes = size,
                sha256 = sha256,
                certificateSha256 = cert,
                requestedPermissions = requested,
                localRiskScore = eval.totalRisk,
                riskScore = eval.totalRisk,
                category = eval.category,
                reasons = eval.reasons
            )
        } finally {
            temp.delete()
        }
    }
}
