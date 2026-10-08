package uz.qalqon.security

import android.app.Application
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import uz.qalqon.security.util.NotificationHelper
import uz.qalqon.security.worker.ProtectionWorker
import java.util.concurrent.TimeUnit

class QalqonApp: Application() {
    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannel(this)
        val daily = PeriodicWorkRequestBuilder<ProtectionWorker>(24, TimeUnit.HOURS).build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork("qalqon_daily_security", ExistingPeriodicWorkPolicy.UPDATE, daily)
    }
}
