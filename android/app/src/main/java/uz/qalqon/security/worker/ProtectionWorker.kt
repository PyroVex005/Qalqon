package uz.qalqon.security.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uz.qalqon.security.data.AppScanner
import uz.qalqon.security.data.DeviceScanner
import uz.qalqon.security.data.HistoryDatabaseHelper
import uz.qalqon.security.model.ScanSnapshot
import uz.qalqon.security.security.RiskEngine
import uz.qalqon.security.util.NotificationHelper

class ProtectionWorker(context: Context, params: WorkerParameters): CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        runCatching {
            val packageName = inputData.getString("package")
            val scanner = AppScanner(applicationContext)
            if (!packageName.isNullOrBlank()) {
                val app = scanner.scanPackage(packageName)
                if (app != null && app.riskScore >= 40) {
                    NotificationHelper.finding(applicationContext, packageName.hashCode(), "QALQON: ${app.label}", "${app.riskScore}% xavf darajasi — ${app.reasons.firstOrNull()?.title ?: "tekshirish tavsiya etiladi"}")
                }
            } else {
                val apps = scanner.scanInstalledApps()
                val device = DeviceScanner(applicationContext).scan()
                val now = System.currentTimeMillis()
                val dashboard = RiskEngine.buildDashboard(apps, device, null, now)
                dashboard.overallSecurityScore?.let { score ->
                    HistoryDatabaseHelper(applicationContext).insert(ScanSnapshot(timestamp = now, overallScore = score, totalApps = apps.size, suspiciousApps = dashboard.suspiciousApps, highRiskApps = dashboard.highRiskApps))
                }
            }
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
