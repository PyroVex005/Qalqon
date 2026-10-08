package uz.qalqon.security

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uz.qalqon.security.data.*
import uz.qalqon.security.model.*
import uz.qalqon.security.security.RiskEngine

class MainViewModel(app: Application): AndroidViewModel(app) {
    private val appScanner = AppScanner(app)
    private val deviceScanner = DeviceScanner(app)
    private val apkScanner = ApkScanner(app)
    private val historyDb = HistoryDatabaseHelper(app)
    private val settingsStore = SettingsStore(app)
    private val reputation = ReputationClient()

    private val _dashboard = MutableStateFlow(DashboardState())
    val dashboard = _dashboard.asStateFlow()
    private val _apps = MutableStateFlow<List<AppSecurityInfo>>(emptyList())
    val apps = _apps.asStateFlow()
    private val _apkResult = MutableStateFlow<ApkScanResult?>(null)
    val apkResult = _apkResult.asStateFlow()
    private val _urlResult = MutableStateFlow<UrlScanResult?>(null)
    val urlResult = _urlResult.asStateFlow()
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()
    private val _history = MutableStateFlow<List<ScanSnapshot>>(emptyList())
    val history = _history.asStateFlow()
    val settings = settingsStore.flow.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), SettingsState())

    private var webScore: Int? = null

    init { refreshAll() }

    fun clearError() { _error.value = null }

    fun refreshAll() {
        if (_dashboard.value.loading) return
        viewModelScope.launch {
            _dashboard.update { it.copy(loading = true, scanProcessed = 0, scanTotal = 0) }
            runCatching {
                val device = withContext(Dispatchers.IO) { deviceScanner.scan() }
                val list = withContext(Dispatchers.IO) {
                    appScanner.scanInstalledApps { p,t -> _dashboard.update { it.copy(loading = true, scanProcessed = p, scanTotal = t) } }
                }
                val now = System.currentTimeMillis()
                val dash = RiskEngine.buildDashboard(list, device, webScore, now)
                _apps.value = list
                _dashboard.value = dash
                dash.overallSecurityScore?.let { historyDb.insert(ScanSnapshot(timestamp = now, overallScore = it, totalApps = list.size, suspiciousApps = dash.suspiciousApps, highRiskApps = dash.highRiskApps)) }
                _history.value = withContext(Dispatchers.IO) { historyDb.list() }
            }.onFailure {
                _dashboard.update { s -> s.copy(loading = false) }
                _error.value = it.message ?: "Tekshiruv xatosi"
            }
        }
    }

    fun scanApk(uri: Uri) {
        viewModelScope.launch {
            runCatching {
                var result = withContext(Dispatchers.IO) { apkScanner.scan(uri) }
                val rep = reputation.hash(result.sha256)
                val final = RiskEngine.applyReputation(result.localRiskScore, rep)
                val status = when (rep.lowercase()) {
                    "known_malicious" -> AssessmentStatus.CONFIRMED_KNOWN_THREAT
                    "suspicious" -> AssessmentStatus.SUSPICIOUS
                    else -> result.assessmentStatus
                }
                result = result.copy(riskScore = final.first, category = final.second, reputation = rep, assessmentStatus = status)
                _apkResult.value = result
            }.onFailure { _error.value = it.message ?: "APK tekshiruvida xato" }
        }
    }

    fun scanUrl(raw: String) {
        viewModelScope.launch {
            runCatching {
                var result = withContext(Dispatchers.Default) { UrlScanner.scan(raw) }
                val rep = reputation.domain(result.host)
                val final = RiskEngine.applyReputation(result.riskScore, rep)
                val status = when (rep.lowercase()) {
                    "known_malicious" -> AssessmentStatus.CONFIRMED_KNOWN_THREAT
                    "suspicious" -> AssessmentStatus.SUSPICIOUS
                    else -> result.assessmentStatus
                }
                result = result.copy(riskScore = final.first, category = final.second, reputation = rep, assessmentStatus = status)
                _urlResult.value = result
                webScore = (100 - result.riskScore).coerceIn(0,100)
                _dashboard.value.device?.let { device -> _dashboard.value = RiskEngine.buildDashboard(_apps.value, device, webScore, _dashboard.value.lastScanAt ?: System.currentTimeMillis()) }
            }.onFailure { _error.value = it.message ?: "Link tekshiruvida xato" }
        }
    }

    fun completeOnboarding() { viewModelScope.launch { settingsStore.completeOnboarding() } }
    fun setTheme(mode: ThemeMode) { viewModelScope.launch { settingsStore.setTheme(mode) } }
    fun loadHistory() { viewModelScope.launch(Dispatchers.IO) { _history.value = historyDb.list() } }
    fun cloudConfigured(): Boolean = reputation.configured
}
