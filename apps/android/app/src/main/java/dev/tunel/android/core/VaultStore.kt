package dev.tunel.android.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import uniffi.tunel_mobile.TunelException
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.errorMessage
import uniffi.tunel_mobile.vaultExists
import java.util.concurrent.atomic.AtomicBoolean

/** Estado de la bóveda para la interfaz: si hay que crearla, desbloquearla o ya está abierta. */
class VaultStore(
    private val path: String,
    /** Dónde se deriva la clave (Argon2id tarda): nunca en el hilo principal. */
    private val worker: CoroutineDispatcher = Dispatchers.Default,
) {
    enum class Phase {
        /** No hay bóveda en este dispositivo. */
        NEEDS_SETUP,
        LOCKED,
        UNLOCKED,
    }

    data class State(
        val phase: Phase,
        val tree: HostTree = HostTree.EMPTY,
        /** Mientras se deriva la clave: la interfaz desactiva el botón. */
        val isWorking: Boolean = false,
        val errorMessage: String? = null,
    )

    private val _state = MutableStateFlow(
        State(if (vaultExists(path)) Phase.LOCKED else Phase.NEEDS_SETUP),
    )
    val state: StateFlow<State> = _state.asStateFlow()

    private val working = AtomicBoolean(false)

    /** Protege `vault` y `generation`: `lock()` llega del hilo principal mientras se abre. */
    private val guard = Any()

    /** Sube con cada bloqueo: una apertura que empezó antes ya no se publica. */
    private var generation = 0L

    private var vault: Vault? = null

    suspend fun unlock(password: String) = open { Vault.unlock(path, password) }

    suspend fun create(password: String, confirmation: String) {
        if (password != confirmation) {
            _state.update { it.copy(errorMessage = "Las contraseñas no coinciden") }
            return
        }
        open { Vault.create(path, password) }
    }

    /**
     * Suelta la bóveda: el núcleo borra los secretos de la memoria y libera el archivo. Si se
     * está abriendo en ese momento, la apertura se descarta al terminar.
     */
    fun lock() {
        val toClose = synchronized(guard) {
            generation++
            val open = vault
            vault = null
            if (open != null) _state.value = State(Phase.LOCKED)
            open
        }
        // Sin esperar al recolector de basura: los secretos se borran ya.
        toClose?.close()
    }

    fun dismissError() = _state.update { it.copy(errorMessage = null) }

    private suspend fun open(action: () -> Vault) {
        if (!working.compareAndSet(false, true)) return
        val started = synchronized(guard) { generation }
        _state.update { it.copy(isWorking = true, errorMessage = null) }
        var opened: Vault? = null
        try {
            val fresh = withContext(worker) { action() }
            opened = fresh
            val tree = withContext(worker) { HostTree(fresh.hosts(), fresh.groups()) }
            val published = synchronized(guard) {
                if (generation != started) return@synchronized false
                vault = fresh
                _state.value = State(Phase.UNLOCKED, tree)
                true
            }
            if (published) {
                opened = null
            } else {
                // Se bloqueó mientras tanto: la bóveda ya existe, pero queda cerrada.
                _state.value = State(Phase.LOCKED)
            }
        } catch (error: TunelException) {
            _state.update { it.copy(isWorking = false, errorMessage = errorMessage(error)) }
        } finally {
            // También si se cancela a medias: nada queda abierto ni a medio cargar.
            opened?.close()
            _state.update { if (it.isWorking) it.copy(isWorking = false) else it }
            working.set(false)
        }
    }
}
