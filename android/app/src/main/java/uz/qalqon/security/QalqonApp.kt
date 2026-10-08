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

        val constraints = Constraints.Builder()
            .setRequiresBatteryNotLow(true)
            .setRequiresStorageNotLow(true)
            .build()

        val initial = OneTimeWorkRequestBuilder<ProtectionWorker>()
            .setInitialDelay(10, TimeUnit.SECONDS)
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(this).enqueueUniqueWork("qalqon_initial_security", ExistingWorkPolicy.KEEP, initial)

        val periodic = PeriodicWorkRequestBuilder<ProtectionWorker>(12, TimeUnit.HOURS)
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "qalqon_periodic_security",
            ExistingPeriodicWorkPolicy.UPDATE,
            periodic
        )
    }
}
