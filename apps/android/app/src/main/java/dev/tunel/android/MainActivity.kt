package dev.tunel.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.runtime.getValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dev.tunel.android.ui.AccountCallbacks
import dev.tunel.android.ui.TerminalCallbacks
import dev.tunel.android.ui.TunelApp
import dev.tunel.android.ui.TunelTheme
import kotlinx.coroutines.launch

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
        // Al recrearse (un giro), el intent es el de antes: ya se atendió.
        if (savedInstanceState == null) handleOAuthReturn(intent)
        val account = AccountCallbacks(
            lastServer = { model.lastServer },
            onLoadOptions = model::loadOptions,
            onForgetOptions = model.store.account::forgetOptions,
            onSignIn = model::signIn,
            onProvider = model::beginProvider,
            onFinishProvider = model::finishProvider,
            onCancelProvider = model.store.account::cancelProvider,
            onSync = model::sync,
            onSignOut = model::signOut,
        )
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                model.browserRequests.collect(::openBrowser)
            }
        }
        setContent {
            TunelTheme {
                val state by model.store.state.collectAsStateWithLifecycle()
                val session by model.store.terminal.collectAsStateWithLifecycle()
                TunelApp(
                    state = state,
                    onUnlock = model::unlock,
                    onCreate = model::create,
                    onLock = model.store::lock,
                    account = account,
                    terminal = TerminalCallbacks(
                        screen = session?.let(model::terminalScreen),
                        onConnect = model::openTerminal,
                        onClose = model::closeTerminal,
                        onLeft = model::terminalScreenLeft,
                    ),
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleOAuthReturn(intent)
    }

    /** La vuelta del navegador (`tunel://oauth?…`) al entrar con un proveedor. */
    private fun handleOAuthReturn(intent: Intent?) {
        val uri = intent?.takeIf { it.action == Intent.ACTION_VIEW }?.data ?: return
        if (uri.scheme == "tunel" && uri.host == "oauth") model.providerReturned(uri.toString())
    }

    /** Una pestaña del navegador del sistema: la contraseña del proveedor no pasa por la app. */
    private fun openBrowser(url: String) {
        try {
            CustomTabsIntent.Builder().build().launchUrl(this, Uri.parse(url))
        } catch (_: ActivityNotFoundException) {
            model.store.account.browserFailed()
        }
    }
}
