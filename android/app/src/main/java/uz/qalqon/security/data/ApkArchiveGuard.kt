package uz.qalqon.security.data

import java.io.File
import java.util.zip.ZipException
import java.util.zip.ZipFile

object ApkArchiveGuard {
    const val MAX_INPUT_BYTES = 500L * 1024 * 1024
    private const val MAX_UNCOMPRESSED_BYTES = 1536L * 1024 * 1024
    private const val MAX_SINGLE_ENTRY_BYTES = 300L * 1024 * 1024
    private const val MAX_ENTRIES = 25_000
    private const val MAX_SUSPICIOUS_RATIO = 250.0

    data class Inspection(
        val valid: Boolean,
        val entryCount: Int,
        val uncompressedBytes: Long,
        val hasManifest: Boolean,
        val dexFiles: Int,
        val fatalFindings: List<String>,
        val warnings: List<String>
    )

    fun inspect(file: File): Inspection {
        val fatal = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        var entries = 0
        var uncompressed = 0L
        var hasManifest = false
        var dexFiles = 0
        try {
            ZipFile(file).use { zip ->
                val enumeration = zip.entries()
                while (enumeration.hasMoreElements()) {
                    val entry = enumeration.nextElement()
                    entries++
                    if (entries > MAX_ENTRIES) {
                        fatal += "Arxivda juda ko‘p fayl bor"
                        break
                    }
                    val name = entry.name.replace('\\', '/')
                    if (name == "AndroidManifest.xml") hasManifest = true
                    if (name.matches(Regex("classes(\\d*)?\\.dex"))) dexFiles++
                    if (name.startsWith("/") || name.split('/').any { it == ".." }) {
                        fatal += "Arxiv ichida xavfsiz bo‘lmagan yo‘l topildi: $name"
                    }
                    if (!entry.isDirectory) {
                        val size = entry.size
                        val compressed = entry.compressedSize
                        if (size > 0) {
                            uncompressed += size
                            if (size > MAX_SINGLE_ENTRY_BYTES) fatal += "Arxivdagi bitta fayl juda katta"
                            if (uncompressed > MAX_UNCOMPRESSED_BYTES) fatal += "Arxiv ochilganda hajm limiti oshadi"
                            if (compressed > 0 && size >= 10L * 1024 * 1024) {
                                val ratio = size.toDouble() / compressed.toDouble()
                                if (ratio > MAX_SUSPICIOUS_RATIO) fatal += "G‘ayritabiiy siqish nisbati aniqlandi"
                            }
                        } else if (size < 0) {
                            warnings += "Ba’zi arxiv elementlarining ochilgan hajmi oldindan noma’lum"
                        }
                    }
                    if (fatal.isNotEmpty()) break
                }
            }
        } catch (_: ZipException) {
            fatal += "Fayl yaroqli ZIP/APK arxivi emas"
        } catch (e: Exception) {
            fatal += "Arxivni xavfsiz tekshirib bo‘lmadi: ${e.javaClass.simpleName}"
        }
        if (!hasManifest) fatal += "AndroidManifest.xml topilmadi"
        if (dexFiles == 0) warnings += "DEX kodi topilmadi; bu APK resurs-only bo‘lishi mumkin"
        return Inspection(fatal.isEmpty(), entries, uncompressed, hasManifest, dexFiles, fatal.distinct(), warnings.distinct())
    }
}
