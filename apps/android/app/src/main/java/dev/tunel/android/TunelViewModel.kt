package dev.tunel.android

import android.app.Application
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import dev.tunel.android.core.TerminalModel
import dev.tunel.android.core.VaultStore
import dev.tunel.android.ui.TerminalScreenState
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import uniffi.tunel_mobile.HostSummary
import java.io.File

/** Una sola bóveda para toda la app; sobrevive a los giros de pantalla. */
class TunelViewModel(application: Application) : AndroidViewModel(application) {
    /** La clave del desbloqueo con huella, en el almacén de Android. */
    val biometrics = KeystoreBiometrics(application)

    // noBackupFilesDir: fuera de las copias de seguridad de Android.
    val store = VaultStore(
        File(application.noBackupFilesDir, "vault.json").absolutePath,
        biometricDevice = biometrics,
    )

    private val settings = application.getSharedPreferences("ajustes", Context.MODE_PRIVATE)

    /** El último servidor usado; no es secreto. */
    var lastServer: String
        get() = settings.getString(KEY_SERVER, "").orEmpty()
        set(value) = settings.edit { putString(KEY_SERVER, value.trim()) }

    private var lockTimer: Job? = null

    /** La pantalla de la terminal abierta: sobrevive a los giros, como la sesión. */
    private var screen: TerminalScreenState? = null

    // Fuera de la app más de unos minutos, se bloquea, como en iOS. El temporizador bloquea
    // aunque no se vuelva; el reloj monótono cubre el tiempo con el teléfono dormido.
    private val lockInBackground = object : DefaultLifecycleObserver {
        override fun onStop(owner: LifecycleOwner) {
            store.didEnterBackground(SystemClock.elapsedRealtime())
            store.terminal.value?.didEnterBackground()
            lockTimer?.cancel()
            lockTimer = viewModelScope.launch {
                delay(VaultStore.BACKGROUND_GRACE_MS)
                store.lock(promptingBiometrics = true)
            }
        }

        override fun onStart(owner: LifecycleOwner) {
            lockTimer?.cancel()
            store.didBecomeActive(SystemClock.elapsedRealtime())
            // Si se bloqueó, ya no hay terminal; si no, se reconecta si se cortó.
            store.terminal.value?.didBecomeActive()
        }
    }

    init {
        ProcessLifecycleOwner.get().lifecycle.addObserver(lockInBackground)
    }

    fun unlock(password: String) {
        viewModelScope.launch { store.unlock(password) }
    }

    fun create(password: String, confirmation: String) {
        viewModelScope.launch { store.create(password, confirmation) }
    }

    fun unlockWithBiometrics() {
        viewModelScope.launch { store.biometrics.unlock() }
    }

    fun setBiometricUnlock(enabled: Boolean) {
        viewModelScope.launch { store.biometrics.setEnabled(enabled) }
    }

    fun loadOptions(server: String) {
        lastServer = server
        viewModelScope.launch { store.account.loadOptions(server) }
    }

    fun signIn(server: String, email: String, password: String) {
        viewModelScope.launch { store.account.signIn(server, email, password) }
    }

    private val _browserRequests = Channel<String>(Channel.BUFFERED)

    /**
     * Páginas de proveedores que hay que abrir en el navegador. Las abre la ventana que esté
     * delante en ese momento, no la que pidió entrar (pudo recrearse entretanto).
     */
    val browserRequests: Flow<String> = _browserRequests.receiveAsFlow()

    fun beginProvider(server: String, providerId: String) {
        viewModelScope.launch {
            store.account.beginProvider(server, providerId)?.let { _browserRequests.send(it) }
        }
    }

    fun providerReturned(callback: String) {
        viewModelScope.launch { store.account.providerReturned(callback) }
    }

    fun finishProvider(masterPassword: String) {
        viewModelScope.launch { store.account.finishProvider(masterPassword) }
    }

    fun sync() {
        viewModelScope.launch { store.account.sync() }
    }

    fun signOut() {
        viewModelScope.launch { store.account.signOut() }
    }

    /** La pantalla de `model`; la crea la primera vez y cierra la de una sesión anterior. */
    fun terminalScreen(model: TerminalModel): TerminalScreenState {
        screen?.takeIf { it.model === model }?.let { return it }
        screen?.close()
        return TerminalScreenState(model).also { screen = it }
    }

    fun openTerminal(host: HostSummary) {
        store.openTerminal(host)
    }

    fun closeTerminal() = store.closeTerminal()

    /**
     * La pantalla de la terminal salió de la composición. Si fue por un giro, la sesión sigue
     * y la pantalla también; si la sesión ya no está, se cierra ahora que nada la dibuja (la
     * terminal no se puede cerrar mientras se muestra).
     */
    fun terminalScreenLeft(left: TerminalScreenState) {
        if (store.terminal.value === left.model) return
        // Un fotograma después: lo que la terminal dejó en cola al irse ya habrá corrido.
        Handler(Looper.getMainLooper()).post {
            left.close()
            if (screen === left) screen = null
        }
    }

    override fun onCleared() {
        screen?.close()
        ProcessLifecycleOwner.get().lifecycle.removeObserver(lockInBackground)
        store.lock()
    }

    private companion object {
        const val KEY_SERVER = "servidor"
    }
}
