package uz.qalqon.security.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.Data
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import uz.qalqon.security.worker.ProtectionWorker

class PackageChangeReceiver: BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_PACKAGE_REMOVED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val packageName = intent.data?.schemeSpecificPart ?: return
        val work = OneTimeWorkRequestBuilder<ProtectionWorker>().setInputData(Data.Builder().putString("package", packageName).build()).build()
        WorkManager.getInstance(context).enqueue(work)
    }
}
