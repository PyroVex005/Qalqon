package uz.qalqon.security.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uz.qalqon.security.BuildConfig
import java.net.HttpURLConnection
import java.net.URL

class ReputationClient {
    val configured: Boolean get() = BuildConfig.QALQON_BACKEND_URL.trim().startsWith("https://")

    suspend fun hash(sha256: String): String = post("/api/v1/reputation/hash", JSONObject().put("sha256", sha256))
    suspend fun domain(domain: String): String = post("/api/v1/reputation/url", JSONObject().put("url", "https://$domain"))

    private suspend fun post(path: String, body: JSONObject): String = withContext(Dispatchers.IO) {
        if (!configured) return@withContext "unknown"
        runCatching {
            val connection = URL(BuildConfig.QALQON_BACKEND_URL.trimEnd('/') + path).openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            if (connection.responseCode !in 200..299) return@runCatching "unknown"
            val text = connection.inputStream.bufferedReader().use { it.readText() }
            JSONObject(text).optString("status", "unknown")
        }.getOrDefault("unknown")
    }
}
