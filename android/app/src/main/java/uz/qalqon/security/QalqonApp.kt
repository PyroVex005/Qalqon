package uz.qalqon.security

import android.app.Application
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import uz.qalqon.security.util.NotificationHelper
import uz.qalqon.security.worker.ProtectionWorker
import java.util.concurrent.TimeUnit

class QalqonApp: Application() {
    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannel(this)

        val batteryAware = Constraints.Builder()
            .setRequiresBatteryNotLow(true)
            .build()

        val initial = OneTimeWorkRequestBuilder<ProtectionWorker>()
            .setConstraints(batteryAware)
            .setInitialDelay(20, TimeUnit.SECONDS)
            .build()

        WorkManager.getInstance(this).enqueueUniqueWork(
            "qalqon_initial_security",
            ExistingWorkPolicy.KEEP,
            initial
        )

        val daily = PeriodicWorkRequestBuilder<ProtectionWorker>(24, TimeUnit.HOURS)
            .setConstraints(batteryAware)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "qalqon_daily_security",
            ExistingPeriodicWorkPolicy.UPDATE,
            daily
        )
    }
}
