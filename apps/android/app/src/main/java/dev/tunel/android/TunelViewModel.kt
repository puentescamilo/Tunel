package dev.tunel.android

import android.app.Application
import android.content.Context
import android.os.SystemClock
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import dev.tunel.android.core.VaultStore
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.io.File

/** Una sola bóveda para toda la app; sobrevive a los giros de pantalla. */
class TunelViewModel(application: Application) : AndroidViewModel(application) {
    // noBackupFilesDir: fuera de las copias de seguridad de Android.
    val store = VaultStore(File(application.noBackupFilesDir, "vault.json").absolutePath)

    private val settings = application.getSharedPreferences("ajustes", Context.MODE_PRIVATE)

    /** El último servidor usado; no es secreto. */
    var lastServer: String
        get() = settings.getString(KEY_SERVER, "").orEmpty()
        set(value) = settings.edit { putString(KEY_SERVER, value.trim()) }

    private var lockTimer: Job? = null

    // Fuera de la app más de unos minutos, se bloquea, como en iOS. El temporizador bloquea
    // aunque no se vuelva; el reloj monótono cubre el tiempo con el teléfono dormido.
    private val lockInBackground = object : DefaultLifecycleObserver {
        override fun onStop(owner: LifecycleOwner) {
            store.didEnterBackground(SystemClock.elapsedRealtime())
            lockTimer?.cancel()
            lockTimer = viewModelScope.launch {
                delay(VaultStore.BACKGROUND_GRACE_MS)
                store.lock()
            }
        }

        override fun onStart(owner: LifecycleOwner) {
            lockTimer?.cancel()
            store.didBecomeActive(SystemClock.elapsedRealtime())
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

    override fun onCleared() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(lockInBackground)
        store.lock()
    }

    private companion object {
        const val KEY_SERVER = "servidor"
    }
}
