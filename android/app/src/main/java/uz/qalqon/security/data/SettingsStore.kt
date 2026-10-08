package uz.qalqon.security.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

private val Context.qalqonDataStore by preferencesDataStore("qalqon_settings")

enum class ThemeMode { SYSTEM, LIGHT, DARK }
data class SettingsState(val loaded: Boolean = false, val onboardingDone: Boolean = false, val theme: ThemeMode = ThemeMode.SYSTEM)

class SettingsStore(private val context: Context) {
    private val onboarding = booleanPreferencesKey("onboarding_done")
    private val theme = stringPreferencesKey("theme")
    val flow: Flow<SettingsState> = context.qalqonDataStore.data.catch { emit(androidx.datastore.preferences.core.emptyPreferences()) }.map { p ->
        SettingsState(true, p[onboarding] ?: false, runCatching { ThemeMode.valueOf(p[theme] ?: "SYSTEM") }.getOrDefault(ThemeMode.SYSTEM))
    }
    suspend fun completeOnboarding() { context.qalqonDataStore.edit { it[onboarding] = true } }
    suspend fun setTheme(mode: ThemeMode) { context.qalqonDataStore.edit { it[theme] = mode.name } }
}
