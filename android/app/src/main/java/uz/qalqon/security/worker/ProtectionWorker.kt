package uz.qalqon.security.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uz.qalqon.security.data.AppScanner
import uz.qalqon.security.data.DeviceScanner
import uz.qalqon.security.data.HistoryDatabaseHelper
import uz.qalqon.security.model.RiskCategory
import uz.qalqon.security.model.ScanSnapshot
import uz.qalqon.security.security.RiskEngine
import uz.qalqon.security.util.NotificationHelper

class ProtectionWorker(context: Context, params: WorkerParameters): CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val packageName = inputData.getString("package")
            val scanner = AppScanner(applicationContext)
            if (!packageName.isNullOrBlank()) {
                val app = scanner.scanPackage(packageName) ?: return@withContext Result.success()
                if (app.category == RiskCategory.KNOWN_MALICIOUS || app.riskScore >= 60) {
                    val detail = app.reasons.firstOrNull()?.let { "${it.title}: ${it.detail}" } ?: "Qo‘shimcha tekshiruv tavsiya etiladi"
                    NotificationHelper.finding(
                        applicationContext,
                        packageName.hashCode(),
                        "QALQON: ${app.label}",
                        "Xavf bahosi ${app.riskScore}/100. $detail"
                    )
                }
            } else {
                val apps = scanner.scanInstalledApps()
                val device = DeviceScanner(applicationContext).scan()
                val now = System.currentTimeMillis()
                val dashboard = RiskEngine.buildDashboard(apps, device, null, now)
                dashboard.overallSecurityScore?.let { score ->
                    HistoryDatabaseHelper(applicationContext).insert(
                        ScanSnapshot(
                            timestamp = now,
                            overallScore = score,
                            totalApps = apps.size,
                            suspiciousApps = dashboard.suspiciousApps,
                            highRiskApps = dashboard.highRiskApps
                        )
                    )
                }
            }
            Result.success()
        } catch (_: SecurityException) {
            Result.failure()
        } catch (_: IllegalArgumentException) {
            Result.failure()
        } catch (_: Throwable) {
            if (runAttemptCount < 2) Result.retry() else Result.failure()
        }
    }
}
