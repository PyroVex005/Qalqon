package uz.qalqon.security.data

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import uz.qalqon.security.model.DeviceSecurityInfo
import uz.qalqon.security.model.RiskReason
import java.time.LocalDate
import java.time.temporal.ChronoUnit

class DeviceScanner(private val context: Context) {
    fun scan(): DeviceSecurityInfo {
        val reasons = mutableListOf<RiskReason>()
        var penalty = 0
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        val secure = keyguard?.isDeviceSecure == true
        if (!secure) {
            penalty += 20
            reasons += RiskReason("Ekran qulfi", "Qurilmada xavfsiz ekran qulfi aniqlanmadi", 20)
        }
        val patch = Build.VERSION.SECURITY_PATCH.orEmpty()
        runCatching {
            if (patch.isNotBlank()) {
                val days = ChronoUnit.DAYS.between(LocalDate.parse(patch), LocalDate.now())
                if (days > 365) {
                    penalty += 15; reasons += RiskReason("Xavfsizlik patchi eskirgan", "$days kun oldingi patch", 15)
                } else if (days > 180) {
                    penalty += 8; reasons += RiskReason("Xavfsizlik patchini tekshiring", "$days kun oldingi patch", 8)
                }
            }
        }
        val developer = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1 }.getOrDefault(false)
        val adb = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1 }.getOrDefault(false)
        if (developer) { penalty += 5; reasons += RiskReason("Developer options faol", "Bu o‘zi virus emas, ammo xavfsizlik yuzasidan e’tibor talab qilishi mumkin", 5) }
        if (adb) { penalty += 10; reasons += RiskReason("USB debugging faol", "ADB orqali qurilmaga rivojlantiruvchi buyruqlari yuborilishi mumkin", 10) }
        return DeviceSecurityInfo(
            manufacturer = Build.MANUFACTURER.ifBlank { "—" },
            model = Build.MODEL.ifBlank { "—" },
            androidVersion = Build.VERSION.RELEASE ?: "—",
            sdk = Build.VERSION.SDK_INT,
            securityPatch = patch.ifBlank { "—" },
            screenLockSecure = secure,
            developerOptions = developer,
            adbEnabled = adb,
            score = (100 - penalty).coerceIn(0, 100),
            reasons = reasons
        )
    }
}
