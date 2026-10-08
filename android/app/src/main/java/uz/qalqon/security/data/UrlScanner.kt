package uz.qalqon.security.data

import uz.qalqon.security.model.RiskReason
import uz.qalqon.security.model.UrlScanResult
import uz.qalqon.security.security.RiskEngine
import java.net.IDN
import java.net.URI

object UrlScanner {
    private val suspiciousWords = listOf("login", "verify", "verification", "account", "wallet", "password", "bonus", "prize", "gift", "secure-update")

    fun scan(raw: String): UrlScanResult {
        val input = raw.trim()
        require(input.isNotEmpty()) { "Link bo‘sh" }
        val normalized = if (input.contains("://")) input else "https://$input"
        val uri = URI(normalized)
        val host = uri.host?.lowercase() ?: throw IllegalArgumentException("Host aniqlanmadi")
        val reasons = mutableListOf<RiskReason>()
        var risk = 0
        if (!uri.scheme.equals("https", true)) { risk += 15; reasons += RiskReason("HTTPS yo‘q", "Ulanish shifrlanmagan bo‘lishi mumkin", 15) }
        if (isIp(host)) { risk += 25; reasons += RiskReason("IP manzil ishlatilgan", "Domen o‘rniga to‘g‘ridan-to‘g‘ri IP ko‘rsatilgan", 25) }
        if (host.contains("xn--")) { risk += 20; reasons += RiskReason("Punycode domen", "Domen ko‘rinishi o‘xshash belgilarni yashirishi mumkin", 20) }
        if (host.split('.').size > 5) { risk += 10; reasons += RiskReason("Ko‘p subdomen", "Manzil tuzilishi odatdagidan murakkab", 10) }
        if (uri.rawAuthority?.contains('@') == true) { risk += 25; reasons += RiskReason("@ belgisi", "Haqiqiy hostni yashirishga urinish bo‘lishi mumkin", 25) }
        val text = (host + uri.path.orEmpty()).lowercase()
        val matched = suspiciousWords.filter { text.contains(it) }
        if (matched.size >= 2) { risk += 12; reasons += RiskReason("Phishingga o‘xshash so‘zlar", matched.joinToString(), 12) }
        if (normalized.length > 180) { risk += 10; reasons += RiskReason("Juda uzun URL", "Uzun manzillar haqiqiy domenni yashirish uchun ishlatilishi mumkin", 10) }
        runCatching { IDN.toUnicode(host) }.getOrNull()?.let { unicode ->
            if (unicode.any { it.code > 127 }) { risk += 10; reasons += RiskReason("Unicode domen", "Domen xalqaro belgilarni o‘z ichiga oladi; nomini diqqat bilan tekshiring", 10) }
        }
        risk = risk.coerceIn(0,100)
        return UrlScanResult(normalized, host, risk, RiskEngine.categoryFor(risk), reasons.sortedByDescending { it.weight })
    }

    private fun isIp(host: String): Boolean = host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || host.contains(':')
}
