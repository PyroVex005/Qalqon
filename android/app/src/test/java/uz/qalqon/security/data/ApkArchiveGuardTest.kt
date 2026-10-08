package uz.qalqon.security.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkArchiveGuardTest {
    @Test fun archiveWithManifestIsAccepted() {
        val file = File.createTempFile("qalqon_test", ".apk")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml")); zip.write(byteArrayOf(1,2,3)); zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex")); zip.write(byteArrayOf(4,5,6)); zip.closeEntry()
            }
            assertTrue(ApkArchiveGuard.inspect(file).valid)
        } finally { file.delete() }
    }

    @Test fun pathTraversalIsRejected() {
        val file = File.createTempFile("qalqon_test", ".apk")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml")); zip.write(byteArrayOf(1)); zip.closeEntry()
                zip.putNextEntry(ZipEntry("../evil.bin")); zip.write(byteArrayOf(2)); zip.closeEntry()
            }
            assertFalse(ApkArchiveGuard.inspect(file).valid)
        } finally { file.delete() }
    }
}
