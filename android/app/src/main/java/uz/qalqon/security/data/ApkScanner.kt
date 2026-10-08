package uz.qalqon.security.data

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import uz.qalqon.security.model.ApkScanResult
import uz.qalqon.security.model.RiskCategory
import uz.qalqon.security.model.RiskReason
import uz.qalqon.security.model.Severity
import uz.qalqon.security.security.RiskEngine
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

class ApkScanner(private val context: Context) {
    fun scan(uri: Uri): ApkScanResult {
        val resolver = context.contentResolver
        var displayName = "selected.apk"
        var declaredSize: Long? = null
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val nameIndex = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = c.getColumnIndex(OpenableColumns.SIZE)
                if (nameIndex >= 0) displayName = c.getString(nameIndex) ?: displayName
                if (sizeIndex >= 0 && !c.isNull(sizeIndex)) declaredSize = c.getLong(sizeIndex)
            }
        }
        require(declaredSize == null || declaredSize!! <= ApkArchiveGuard.MAX_INPUT_BYTES) { "APK hajmi xavfsizlik limitidan katta (500 MB)" }

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
                        size += n
                        require(size <= ApkArchiveGuard.MAX_INPUT_BYTES) { "APK hajmi xavfsizlik limitidan katta (500 MB)" }
                        digest.update(buffer, 0, n)
                        out.write(buffer, 0, n)
                    }
                }
            }
            val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
            val inspection = ApkArchiveGuard.inspect(temp)
            if (!inspection.valid) {
                val reasons = inspection.fatalFindings.mapIndexed { index, message ->
                    RiskReason("APK arxiv muammosi", message, 20, "APK_ARCHIVE_FATAL_${index + 1}", Severity.HIGH, 98)
                } + inspection.warnings.mapIndexed { index, message ->
                    RiskReason("APK arxiv ogohlantirishi", message, 3, "APK_ARCHIVE_WARN_${index + 1}", Severity.INFORMATIONAL, 90)
                }
                return ApkScanResult(
                    displayName = displayName,
                    packageName = null,
                    versionName = null,
                    targetSdk = null,
                    sizeBytes = size,
                    sha256 = sha256,
                    certificateSha256 = null,
                    requestedPermissions = emptyList(),
                    localRiskScore = 85,
                    riskScore = 85,
                    category = RiskCategory.HIGH,
                    reasons = reasons,
                    analysisComplete = false,
                    archiveValid = false,
                    archiveEntries = inspection.entryCount,
                    uncompressedBytes = inspection.uncompressedBytes
                )
            }

            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
            val info = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageArchiveInfo(temp.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") context.packageManager.getPackageArchiveInfo(temp.absolutePath, flags)
            }
            if (info == null) {
                val reasons = listOf(
                    RiskReason("APK metadata o‘qilmadi", "Android PackageManager ushbu arxivni installable APK sifatida tahlil qila olmadi", 35, "APK_METADATA_UNREADABLE", Severity.HIGH, 95)
                ) + inspection.warnings.mapIndexed { index, message ->
                    RiskReason("APK arxiv ogohlantirishi", message, 3, "APK_ARCHIVE_WARN_${index + 1}", Severity.INFORMATIONAL, 90)
                }
                return ApkScanResult(displayName, null, null, null, size, sha256, null, emptyList(), 70, 70, RiskCategory.SUSPICIOUS, reasons, analysisComplete = false, archiveValid = true, archiveEntries = inspection.entryCount, uncompressedBytes = inspection.uncompressedBytes)
            }

            val requested = info.requestedPermissions?.toList().orEmpty()
            val target = info.applicationInfo?.targetSdkVersion
            val cert = runCatching {
                if (Build.VERSION.SDK_INT < 28) null else info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()?.let {
                    MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02X".format(b) }
                }
            }.getOrNull()
            val eval = RiskEngine.evaluateApk(requested, target, cert)
            val archiveReasons = inspection.warnings.mapIndexed { index, message ->
                RiskReason("APK arxiv ogohlantirishi", message, 3, "APK_ARCHIVE_WARN_${index + 1}", Severity.INFORMATIONAL, 90)
            }
            return ApkScanResult(
                displayName = displayName,
                packageName = info.packageName,
                versionName = info.versionName,
                targetSdk = target,
                sizeBytes = size,
                sha256 = sha256,
                certificateSha256 = cert,
                requestedPermissions = requested,
                localRiskScore = eval.totalRisk,
                riskScore = eval.totalRisk,
                category = eval.category,
                reasons = (eval.reasons + archiveReasons).sortedByDescending { it.weight },
                analysisComplete = true,
                archiveValid = true,
                archiveEntries = inspection.entryCount,
                uncompressedBytes = inspection.uncompressedBytes
            )
        } finally {
            temp.delete()
        }
    }
}
