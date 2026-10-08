package uz.qalqon.security.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkArchiveGuardTest {
    @Test
    fun acceptsZipWithAndroidManifest() {
        val file = tempZip(
            "AndroidManifest.xml" to "manifest".toByteArray(),
            "classes.dex" to byteArrayOf(1, 2, 3)
        )
        try {
            assertTrue(ApkArchiveGuard.validate(file).valid)
        } finally {
            file.delete()
        }
    }

    @Test
    fun rejectsArchiveWithoutManifest() {
        val file = tempZip("classes.dex" to byteArrayOf(1, 2, 3))
        try {
            assertFalse(ApkArchiveGuard.validate(file).valid)
        } finally {
            file.delete()
        }
    }

    @Test
    fun rejectsMalformedArchive() {
        val file = File.createTempFile("qalqon_bad_", ".apk")
        file.writeText("not a zip")
        try {
            assertFalse(ApkArchiveGuard.validate(file).valid)
        } finally {
            file.delete()
        }
    }

    private fun tempZip(vararg entries: Pair<String, ByteArray>): File {
        val file = File.createTempFile("qalqon_test_", ".apk")
        ZipOutputStream(FileOutputStream(file)).use { out ->
            entries.forEach { (name, bytes) ->
                out.putNextEntry(ZipEntry(name))
                out.write(bytes)
                out.closeEntry()
            }
        }
        return file
    }
}
