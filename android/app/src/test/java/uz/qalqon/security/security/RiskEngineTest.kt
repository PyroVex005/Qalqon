package uz.qalqon.security.security

import android.Manifest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uz.qalqon.security.model.RiskCategory

class RiskEngineTest {
    @Test
    fun knownMaliciousReputationOverridesLocalScore() {
        val result = RiskEngine.applyReputation(12, "known_malicious")
        assertEquals(100, result.first)
        assertEquals(RiskCategory.KNOWN_MALICIOUS, result.second)
    }

    @Test
    fun suspiciousReputationRaisesButCapsScore() {
        val result = RiskEngine.applyReputation(80, "suspicious")
        assertEquals(95, result.first)
    }

    @Test
    fun sensitiveGrantedPermissionsProduceEvidence() {
        val permissions = listOf(
            Manifest.permission.READ_SMS,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
        val result = RiskEngine.evaluateApp(
            requested = permissions,
            granted = permissions,
            installer = "com.android.vending",
            systemApp = false,
            targetSdk = 35,
            certificateSha256 = "ABC"
        )
        assertTrue(result.permissionRisk > 0)
        assertTrue(result.reasons.isNotEmpty())
    }
}
