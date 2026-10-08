package uz.qalqon.security.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import uz.qalqon.security.worker.ProtectionWorker
import java.util.concurrent.TimeUnit

class PackageChangeReceiver: BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return
        val packageName = intent.data?.schemeSpecificPart ?: return
        if (packageName == context.packageName) return

        val work = OneTimeWorkRequestBuilder<ProtectionWorker>()
            .setInitialDelay(3, TimeUnit.SECONDS)
            .setInputData(Data.Builder().putString("package", packageName).build())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            "qalqon_package_${packageName.hashCode()}",
            ExistingWorkPolicy.REPLACE,
            work
        )
    }
}
