package uz.qalqon.security.data

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import uz.qalqon.security.model.ApkScanResult
import uz.qalqon.security.model.AssessmentStatus
import uz.qalqon.security.model.RiskCategory
import uz.qalqon.security.model.RiskReason
import uz.qalqon.security.model.RiskSeverity
import uz.qalqon.security.security.RiskEngine
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

class ApkScanner(private val context: Context) {
    companion object {
        const val MAX_APK_BYTES = 512L * 1024 * 1024
        const val MAX_ZIP_ENTRIES = 20_000
        const val MAX_TOTAL_UNCOMPRESSED_BYTES = 2L * 1024 * 1024 * 1024
        const val MAX_COMPRESSION_RATIO = 250L
    }

    private data class ArchiveCheck(val valid: Boolean, val message: String? = null)

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
                        size += n
                        require(size <= MAX_APK_BYTES) { "APK hajmi 512 MB limitdan katta" }
                        digest.update(buffer, 0, n)
                        out.write(buffer, 0, n)
                    }
                }
            }

            val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
            val archive = validateArchive(temp)
            if (!archive.valid) {
                return incompleteResult(displayName, size, sha256, archive.message ?: "APK arxivi yaroqsiz")
            }

            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
            val info = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageArchiveInfo(temp.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") context.packageManager.getPackageArchiveInfo(temp.absolutePath, flags)
            } ?: return incompleteResult(displayName, size, sha256, "Android APK metadata ma’lumotini o‘qiy olmadi")

            val requested = info.requestedPermissions?.toList().orEmpty()
            val target = info.applicationInfo?.targetSdkVersion
            val cert = runCatching {
                if (Build.VERSION.SDK_INT < 28) null else info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()?.let {
                    MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02X".format(b) }
                }
            }.getOrNull()

            val eval = RiskEngine.evaluateApk(requested, target, cert)
            val status = when {
                eval.totalRisk >= 60 -> AssessmentStatus.SUSPICIOUS
                cert.isNullOrBlank() -> AssessmentStatus.UNKNOWN
                else -> AssessmentStatus.NO_KNOWN_THREAT_DETECTED
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
                reasons = eval.reasons,
                archiveValid = true,
                assessmentStatus = status
            )
        } finally {
            temp.delete()
        }
    }

    private fun incompleteResult(displayName: String, size: Long, sha256: String, message: String): ApkScanResult {
        return ApkScanResult(
            displayName = displayName,
            packageName = null,
            versionName = null,
            targetSdk = null,
            sizeBytes = size,
            sha256 = sha256,
            certificateSha256 = null,
            requestedPermissions = emptyList(),
            localRiskScore = 0,
            riskScore = 0,
            category = RiskCategory.UNKNOWN,
            reasons = listOf(
                RiskReason(
                    title = "Skan to‘liq yakunlanmadi",
                    detail = message,
                    weight = 0,
                    ruleId = "APK_PARSE_INCOMPLETE",
                    severity = RiskSeverity.INFORMATIONAL,
                    confidence = 100,
                    recommendedAction = "Fayl manbasini tekshiring va ishonchli nusxa bilan qayta urinib ko‘ring."
                )
            ),
            archiveValid = false,
            assessmentStatus = AssessmentStatus.SCAN_INCOMPLETE
        )
    }

    private fun validateArchive(file: File): ArchiveCheck {
        return runCatching {
            ZipFile(file).use { zip ->
                var entries = 0
                var totalUncompressed = 0L
                var hasManifest = false
                val enumeration = zip.entries()
                while (enumeration.hasMoreElements()) {
                    val entry = enumeration.nextElement()
                    entries++
                    if (entries > MAX_ZIP_ENTRIES) return ArchiveCheck(false, "APK ichida haddan tashqari ko‘p ZIP yozuvlari bor")
                    if (entry.name == "AndroidManifest.xml") hasManifest = true
                    if (entry.isDirectory) continue

                    val unpacked = entry.size
                    if (unpacked > 0) {
                        if (unpacked > MAX_TOTAL_UNCOMPRESSED_BYTES - totalUncompressed) {
                            return ArchiveCheck(false, "APK ochilganda ruxsat etilgan hajmdan oshadi")
                        }
                        totalUncompressed += unpacked
                    }

                    val compressed = entry.compressedSize
                    if (unpacked > 16L * 1024 * 1024 && compressed > 0 && unpacked / compressed > MAX_COMPRESSION_RATIO) {
                        return ArchiveCheck(false, "APK ichida xavfli darajada yuqori siqish nisbati aniqlandi")
                    }
                }
                if (!hasManifest) ArchiveCheck(false, "AndroidManifest.xml topilmadi") else ArchiveCheck(true)
            }
        }.getOrElse { ArchiveCheck(false, "APK ZIP arxivini tekshirib bo‘lmadi: " + (it.message ?: "noma’lum xato")) }
    }
}
