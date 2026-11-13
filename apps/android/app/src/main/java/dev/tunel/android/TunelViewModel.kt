package dev.tunel.android

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import dev.tunel.android.core.VaultStore
import kotlinx.coroutines.launch
import java.io.File

/** Una sola bóveda para toda la app; sobrevive a los giros de pantalla. */
class TunelViewModel(application: Application) : AndroidViewModel(application) {
    // noBackupFilesDir: fuera de las copias de seguridad de Android.
    val store = VaultStore(File(application.noBackupFilesDir, "vault.json").absolutePath)

    // Al salir de la app se bloquea, como en iOS.
    private val lockInBackground = object : DefaultLifecycleObserver {
        override fun onStop(owner: LifecycleOwner) = store.lock()
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

    override fun onCleared() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(lockInBackground)
        store.lock()
    }
}
