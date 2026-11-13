package dev.tunel.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Los colores del icono de Túnel.
private val light = lightColorScheme(
    primary = Color(0xFF00796B),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB2F2E4),
    onPrimaryContainer = Color(0xFF00201A),
)

private val dark = darkColorScheme(
    primary = Color(0xFF36E6C2),
    onPrimary = Color(0xFF00382E),
    primaryContainer = Color(0xFF005144),
    onPrimaryContainer = Color(0xFFB2F2E4),
    background = Color(0xFF101418),
    surface = Color(0xFF101418),
)

@Composable
fun TunelTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) dark else light, content = content)
}
