package uz.qalqon.security.data

import uz.qalqon.security.model.AssessmentStatus
import uz.qalqon.security.model.RiskReason
import uz.qalqon.security.model.UrlScanResult
import uz.qalqon.security.security.RiskEngine
import java.net.IDN
import java.net.URI

object UrlScanner {
    private val suspiciousWords = listOf("login", "verify", "verification", "account", "wallet", "password", "bonus", "prize", "gift", "secure-update", "recovery", "signin")
    private val suspiciousQueryKeys = setOf("redirect", "redirect_uri", "continue", "next", "url", "target")

    fun scan(raw: String): UrlScanResult {
        val input = raw.trim()
        require(input.isNotEmpty()) { "Link bo‘sh" }
        val normalized = if (input.contains("://")) input else "https://$input"
        val uri = runCatching { URI(normalized) }.getOrElse { throw IllegalArgumentException("Link formati noto‘g‘ri") }
        val scheme = uri.scheme?.lowercase() ?: throw IllegalArgumentException("URL sxemasi aniqlanmadi")
        require(scheme == "http" || scheme == "https") { "Faqat HTTP yoki HTTPS linklar tekshiriladi" }
        val host = uri.host?.trimEnd('.')?.lowercase() ?: throw IllegalArgumentException("Host aniqlanmadi")
        require(host.length in 1..253) { "Domen uzunligi noto‘g‘ri" }

        val reasons = mutableListOf<RiskReason>()
        var risk = 0
        fun add(title: String, detail: String, weight: Int) {
            risk += weight
            reasons += RiskReason(title, detail, weight)
        }

        if (scheme != "https") add("HTTPS yo‘q", "Ulanish shifrlanmagan bo‘lishi mumkin", 15)
        if (isIp(host)) add("IP manzil ishlatilgan", "Domen o‘rniga to‘g‘ridan-to‘g‘ri IP ko‘rsatilgan", 25)
        if (host.contains("xn--")) add("Punycode domen", "Domen ko‘rinishi o‘xshash belgilarni yashirishi mumkin", 20)
        if (host.split('.').size > 5) add("Ko‘p subdomen", "Manzil tuzilishi odatdagidan murakkab", 10)
        if (uri.rawAuthority?.contains('@') == true) add("@ belgisi", "Haqiqiy hostni yashirishga urinish bo‘lishi mumkin", 25)
        if (uri.port !in -1..65535) add("Noto‘g‘ri port", "URL port qiymati yaroqsiz", 15)

        val text = (host + uri.rawPath.orEmpty()).lowercase()
        val matched = suspiciousWords.filter { text.contains(it) }
        if (matched.size >= 2) add("Phishingga o‘xshash so‘zlar", matched.joinToString(), 12)
        if (normalized.length > 180) add("Juda uzun URL", "Uzun manzillar haqiqiy domenni yashirish uchun ishlatilishi mumkin", 10)

        val raw = uri.rawPath.orEmpty() + "?" + uri.rawQuery.orEmpty()
        val encodedDelimiters = listOf("%2f", "%5c", "%40", "%3a").count { raw.lowercase().contains(it) }
        if (encodedDelimiters >= 2) add("Ko‘p kodlangan ajratgich", "URL ichida manzilni yashirishga xizmat qilishi mumkin bo‘lgan kodlangan belgilar bor", 8)

        val query = uri.rawQuery.orEmpty().lowercase()
        if (suspiciousQueryKeys.count { key -> query.contains("$key=") } >= 2) {
            add("Ko‘p yo‘naltirish parametri", "URL bir nechta redirect/target parametrlaridan foydalanadi", 8)
        }

        runCatching { IDN.toUnicode(host) }.getOrNull()?.let { unicode ->
            if (unicode.any { it.code > 127 }) add("Unicode domen", "Domen xalqaro belgilarni o‘z ichiga oladi; nomini diqqat bilan tekshiring", 10)
        }

        risk = risk.coerceIn(0, 100)
        val status = if (risk >= 60) AssessmentStatus.SUSPICIOUS else AssessmentStatus.NO_KNOWN_THREAT_DETECTED
        return UrlScanResult(normalized, host, risk, RiskEngine.categoryFor(risk), reasons.sortedByDescending { it.weight }, assessmentStatus = status)
    }

    private fun isIp(host: String): Boolean {
        val ipv4 = host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) && host.split('.').all { it.toIntOrNull() in 0..255 }
        val ipv6 = host.contains(':')
        return ipv4 || ipv6
    }
}
