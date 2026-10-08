package uz.qalqon.security.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uz.qalqon.security.model.RiskCategory

class RiskEngineTest {
    @Test fun categoryBoundariesAreStable() {
        assertEquals(RiskCategory.SAFE, RiskEngine.categoryFor(0))
        assertEquals(RiskCategory.LOW, RiskEngine.categoryFor(20))
        assertEquals(RiskCategory.ATTENTION, RiskEngine.categoryFor(40))
        assertEquals(RiskCategory.SUSPICIOUS, RiskEngine.categoryFor(60))
        assertEquals(RiskCategory.HIGH, RiskEngine.categoryFor(80))
    }

    @Test fun knownMaliciousReputationWins() {
        val (score, category) = RiskEngine.applyReputation(12, "known_malicious")
        assertEquals(100, score)
        assertEquals(RiskCategory.KNOWN_MALICIOUS, category)
    }

    @Test fun suspiciousReputationCapsRisk() {
        val (score, _) = RiskEngine.applyReputation(90, "suspicious")
        assertEquals(95, score)
        assertTrue(score <= 100)
    }
}
