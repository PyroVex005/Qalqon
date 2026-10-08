package uz.qalqon.security.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uz.qalqon.security.model.AssessmentStatus

class UrlScannerTest {
    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonHttpSchemes() {
        UrlScanner.scan("javascript:alert(1)")
    }

    @Test
    fun directIpIsFlagged() {
        val result = UrlScanner.scan("http://127.0.0.1/login")
        assertTrue(result.riskScore > 0)
        assertTrue(result.reasons.any { it.title.contains("IP") })
    }

    @Test
    fun ordinaryHttpsDomainIsNotCalledMalicious() {
        val result = UrlScanner.scan("https://example.com/")
        assertEquals(0, result.riskScore)
        assertEquals(AssessmentStatus.NO_KNOWN_THREAT_DETECTED, result.assessmentStatus)
    }

    @Test
    fun punycodeDomainGetsExplainableWarning() {
        val result = UrlScanner.scan("https://xn--80ak6aa92e.com/login/verify")
        assertTrue(result.riskScore > 0)
        assertTrue(result.reasons.any { it.title.contains("Punycode") })
    }
}
