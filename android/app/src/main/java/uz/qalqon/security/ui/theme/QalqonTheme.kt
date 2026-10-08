package uz.qalqon.security.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import uz.qalqon.security.data.ThemeMode

private val Dark = darkColorScheme(
    primary = Color(0xFF43B8FF), secondary = Color(0xFF6EE7FF), background = Color(0xFF061321), surface = Color(0xFF0B2138),
    surfaceVariant = Color(0xFF12304D), onPrimary = Color(0xFF001D31), onBackground = Color(0xFFF2F7FF), onSurface = Color(0xFFF2F7FF),
    error = Color(0xFFFF6B74)
)
private val Light = lightColorScheme(
    primary = Color(0xFF0069C2), secondary = Color(0xFF006782), background = Color(0xFFF5F8FC), surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFE3EFF9), onPrimary = Color.White, onBackground = Color(0xFF0A1725), onSurface = Color(0xFF0A1725), error = Color(0xFFB3261E)
)

@Composable fun QalqonTheme(mode: ThemeMode, content: @Composable () -> Unit) {
    val dark = when(mode) { ThemeMode.DARK -> true; ThemeMode.LIGHT -> false; ThemeMode.SYSTEM -> isSystemInDarkTheme() }
    MaterialTheme(colorScheme = if (dark) Dark else Light, typography = Typography(), content = content)
}
