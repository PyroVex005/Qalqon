package uz.qalqon.security.util

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import uz.qalqon.security.MainActivity
import uz.qalqon.security.R

object NotificationHelper {
    const val CHANNEL = "qalqon_security"
    fun createChannel(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "QALQON Security", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "Qurilma xavfsizlik hodisalari"
        })
    }
    fun finding(context: Context, id: Int, title: String, text: String) {
        val intent = Intent(context, MainActivity::class.java)
        val pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title).setContentText(text).setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(pending).setAutoCancel(true).build()
        context.getSystemService(NotificationManager::class.java).notify(id, n)
    }
}
