package uz.qalqon.security.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import uz.qalqon.security.model.ScanSnapshot

class HistoryDatabaseHelper(context: Context): SQLiteOpenHelper(context, "qalqon_history.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""CREATE TABLE scan_history(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, overall_score INTEGER NOT NULL, total_apps INTEGER NOT NULL, suspicious_apps INTEGER NOT NULL, high_risk_apps INTEGER NOT NULL)""")
    }
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun insert(snapshot: ScanSnapshot) {
        writableDatabase.insert("scan_history", null, ContentValues().apply {
            put("timestamp", snapshot.timestamp); put("overall_score", snapshot.overallScore); put("total_apps", snapshot.totalApps); put("suspicious_apps", snapshot.suspiciousApps); put("high_risk_apps", snapshot.highRiskApps)
        })
    }

    fun clear() { writableDatabase.delete("scan_history", null, null) }

    fun list(limit: Int = 30): List<ScanSnapshot> {
        val out = mutableListOf<ScanSnapshot>()
        readableDatabase.query("scan_history", null, null, null, null, null, "timestamp DESC", limit.toString()).use { c ->
            while (c.moveToNext()) out += ScanSnapshot(
                id = c.getLong(c.getColumnIndexOrThrow("id")), timestamp = c.getLong(c.getColumnIndexOrThrow("timestamp")), overallScore = c.getInt(c.getColumnIndexOrThrow("overall_score")),
                totalApps = c.getInt(c.getColumnIndexOrThrow("total_apps")), suspiciousApps = c.getInt(c.getColumnIndexOrThrow("suspicious_apps")), highRiskApps = c.getInt(c.getColumnIndexOrThrow("high_risk_apps"))
            )
        }
        return out
    }
}
