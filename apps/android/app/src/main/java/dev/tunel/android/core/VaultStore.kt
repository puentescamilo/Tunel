package dev.tunel.android.core

import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import uniffi.tunel_mobile.AccountInfo
import uniffi.tunel_mobile.HostSummary
import uniffi.tunel_mobile.TunelException
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.errorMessage
import uniffi.tunel_mobile.vaultExists
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

/** Estado de la bóveda para la interfaz: si hay que crearla, desbloquearla o ya está abierta. */
class VaultStore(
    private val path: String,
    /** Dónde se deriva la clave (Argon2id tarda) y se habla con el servidor: nunca en el hilo principal. */
    private val worker: CoroutineDispatcher = Dispatchers.Default,
    /** La hora de una sincronización, en milisegundos. */
    private val clock: () -> Long = System::currentTimeMillis,
    /** El hilo principal: ahí llega lo que cuenta una sesión de terminal. */
    private val main: Executor = MainThreadExecutor,
    /** Dónde se guarda la clave del desbloqueo con huella. */
    biometricDevice: BiometricDevice = NoBiometrics,
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
        /** La cuenta a la que está unido el dispositivo; `null` si no lo está. */
        val account: AccountInfo? = null,
        val sync: SyncStatus = SyncStatus.Idle,
        val signIn: SignInState = SignInState(),
        val biometric: BiometricState = BiometricState(),
    )

    /** Desbloqueo con huella. */
    val biometrics = BiometricActions(this, path, biometricDevice, worker)

    private val _state = MutableStateFlow(
        if (vaultExists(path)) {
            // Al abrir la app, la huella se pide sola.
            State(Phase.LOCKED, biometric = biometrics.locked(promptOnAppear = true))
        } else {
            State(Phase.NEEDS_SETUP)
        },
    )
    val state: StateFlow<State> = _state.asStateFlow()

    private val working = AtomicBoolean(false)

    /** Protege `vault`, `generation` y el inicio de sesión: `lock()` llega del hilo principal. */
    internal val guard = Any()

    /** Sube con cada bloqueo: lo que empezó antes ya no se publica. */
    internal var generation = 0L
        private set

    internal var vault: Vault? = null
        private set

    private val _terminal = MutableStateFlow<TerminalModel?>(null)

    /** La terminal abierta, si hay una. Al bloquear se cierra. */
    val terminal: StateFlow<TerminalModel?> = _terminal.asStateFlow()

    /** Unirse a la cuenta y sincronizar. */
    val account = AccountActions(this, worker, clock)

    /** Desde cuándo está la app en segundo plano (reloj monótono), o `null` si está delante. */
    private var backgroundSince: Long? = null

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
     * está abriendo en ese momento, la apertura se descarta al terminar. Bloquear a mano no
     * pide la huella sola; bloquear por estar fuera de la app, sí (`promptingBiometrics`).
     */
    fun lock(promptingBiometrics: Boolean = false) {
        val toClose = synchronized(guard) {
            generation++
            val open = vault
            vault = null
            if (open != null) {
                _state.value = State(Phase.LOCKED, biometric = biometrics.locked(promptingBiometrics))
            }
            listOfNotNull(open) + account.forget()
        }
        // Sin esperar al recolector de basura: los secretos se borran ya.
        toClose.forEach { it.close() }
        closeTerminal()
    }

    /**
     * Abre la terminal de `host` (sin conectar todavía: lo hace la pantalla con su tamaño) y
     * cierra la que hubiera. `null` si la bóveda está bloqueada.
     */
    fun openTerminal(host: HostSummary): TerminalModel? {
        if (synchronized(guard) { vault } == null) return null
        _terminal.value?.close()
        return TerminalModel(host, { synchronized(guard) { vault } }, main).also {
            _terminal.value = it
        }
    }

    fun closeTerminal() {
        _terminal.value?.close()
        _terminal.value = null
    }

    /** La app pasó a segundo plano en `now` (milisegundos de un reloj monótono). */
    fun didEnterBackground(now: Long) {
        backgroundSince = now
    }

    /**
     * La app vuelve a primer plano: si estuvo fuera [BACKGROUND_GRACE_MS] o más, se bloquea.
     * Así se puede ir al navegador para entrar con Google, o copiar algo de otra app, sin
     * volver a escribir la contraseña maestra.
     */
    fun didBecomeActive(now: Long) {
        val since = backgroundSince ?: return
        backgroundSince = null
        if (now - since >= BACKGROUND_GRACE_MS) lock(promptingBiometrics = true)
    }

    fun dismissError() = _state.update { it.copy(errorMessage = null) }

    internal fun update(transform: (State) -> State) = _state.update(transform)

    /** Aplica `transform` solo si la bóveda sigue abierta desde `started`. */
    internal fun publish(started: Long, transform: (State) -> State): Boolean =
        synchronized(guard) {
            if (generation != started || vault == null) return false
            _state.update(transform)
            true
        }

    /** Hosts, grupos y cuenta de `vault`, leídos fuera del hilo principal. */
    internal suspend fun snapshot(vault: Vault): Pair<HostTree, AccountInfo?> =
        withContext(worker) { HostTree(vault.hosts(), vault.groups()) to vault.account() }

    internal suspend fun openWith(action: () -> Vault) = open(action)

    private suspend fun open(action: () -> Vault) {
        if (!working.compareAndSet(false, true)) return
        val started = synchronized(guard) { generation }
        _state.update { it.copy(isWorking = true, errorMessage = null) }
        var opened: Vault? = null
        try {
            val fresh = withContext(worker) { action() }
            opened = fresh
            val (tree, account) = snapshot(fresh)
            val biometric = biometrics.unlocked(fresh)
            val published = synchronized(guard) {
                if (generation != started) return@synchronized false
                vault = fresh
                _state.value = State(Phase.UNLOCKED, tree, account = account, biometric = biometric)
                true
            }
            if (published) {
                opened = null
            } else {
                // Se bloqueó mientras tanto: la bóveda ya existe, pero queda cerrada.
                _state.value = State(Phase.LOCKED, biometric = biometrics.locked(false))
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

    companion object {
        /** Cuánto puede estar la app en segundo plano sin bloquearse, como en iOS. */
        const val BACKGROUND_GRACE_MS = 180_000L
    }
}

/** El hilo principal de Android. Se crea al usarlo: las pruebas en el Mac pasan el suyo. */
private object MainThreadExecutor : Executor {
    private val handler by lazy { Handler(Looper.getMainLooper()) }

    override fun execute(command: Runnable) {
        handler.post(command)
    }
}
