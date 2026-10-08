package uz.qalqon.security.data

import java.io.File
import java.util.zip.ZipFile

object ApkArchiveGuard {
    const val MAX_APK_BYTES = 512L * 1024 * 1024
    const val MAX_ZIP_ENTRIES = 20_000
    const val MAX_TOTAL_UNCOMPRESSED_BYTES = 2L * 1024 * 1024 * 1024
    const val MAX_COMPRESSION_RATIO = 250L

    data class Result(val valid: Boolean, val message: String? = null)

    fun validate(file: File): Result {
        if (!file.isFile) return Result(false, "APK fayli topilmadi")
        if (file.length() > MAX_APK_BYTES) return Result(false, "APK hajmi 512 MB limitdan katta")
        return runCatching {
            ZipFile(file).use { zip ->
                var entries = 0
                var totalUncompressed = 0L
                var hasManifest = false
                val enumeration = zip.entries()
                while (enumeration.hasMoreElements()) {
                    val entry = enumeration.nextElement()
                    entries++
                    if (entries > MAX_ZIP_ENTRIES) return Result(false, "APK ichida haddan tashqari ko‘p ZIP yozuvlari bor")
                    if (entry.name == "AndroidManifest.xml") hasManifest = true
                    if (entry.isDirectory) continue

                    val unpacked = entry.size
                    if (unpacked > 0) {
                        if (unpacked > MAX_TOTAL_UNCOMPRESSED_BYTES - totalUncompressed) {
                            return Result(false, "APK ochilganda ruxsat etilgan hajmdan oshadi")
                        }
                        totalUncompressed += unpacked
                    }

                    val compressed = entry.compressedSize
                    if (unpacked > 16L * 1024 * 1024 && compressed > 0 && unpacked / compressed > MAX_COMPRESSION_RATIO) {
                        return Result(false, "APK ichida xavfli darajada yuqori siqish nisbati aniqlandi")
                    }
                }
                if (!hasManifest) Result(false, "AndroidManifest.xml topilmadi") else Result(true)
            }
        }.getOrElse { Result(false, "APK ZIP arxivini tekshirib bo‘lmadi: " + (it.message ?: "noma’lum xato")) }
    }
}
