package uz.qalqon.security.ui

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

fun Drawable.toImageBitmap(): ImageBitmap {
    val bitmap = if (this is BitmapDrawable && bitmap != null) bitmap else {
        val w = intrinsicWidth.takeIf { it > 0 } ?: 96
        val h = intrinsicHeight.takeIf { it > 0 } ?: 96
        Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also { b -> setBounds(0,0,w,h); draw(Canvas(b)) }
    }
    return bitmap.asImageBitmap()
}

@Composable fun rememberAppIcon(packageName: String): ImageBitmap? {
    val context = androidx.compose.ui.platform.LocalContext.current
    val state = produceState<ImageBitmap?>(null, packageName) {
        value = withContext(Dispatchers.IO) { runCatching { context.packageManager.getApplicationIcon(packageName).toImageBitmap() }.getOrNull() }
    }
    return state.value
}
