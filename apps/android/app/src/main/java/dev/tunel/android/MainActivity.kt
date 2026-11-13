package dev.tunel.android

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.tunel.android.ui.TunelApp
import dev.tunel.android.ui.TunelTheme

class MainActivity : ComponentActivity() {
    private val model: TunelViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // En el selector de apps no se ven los hosts: la captura sale en blanco. Antes de
        // Android 13 solo se consigue impidiendo también las capturas de pantalla.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        } else {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContent {
            TunelTheme {
                val state by model.store.state.collectAsStateWithLifecycle()
                TunelApp(
                    state = state,
                    onUnlock = model::unlock,
                    onCreate = model::create,
                    onLock = model.store::lock,
                )
            }
        }
    }
}
