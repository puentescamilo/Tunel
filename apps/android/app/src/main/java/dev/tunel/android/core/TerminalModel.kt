package dev.tunel.android.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import uniffi.tunel_mobile.HostKeyQuestion
import uniffi.tunel_mobile.HostSummary
import uniffi.tunel_mobile.LoginQuestion
import uniffi.tunel_mobile.TerminalListener
import uniffi.tunel_mobile.TerminalSession
import uniffi.tunel_mobile.TunelException
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.errorMessage
import java.util.concurrent.Executor

/** En qué punto está la sesión de terminal. */
sealed interface TerminalPhase {
    data object Connecting : TerminalPhase

    data object Connected : TerminalPhase

    /** Terminó; `error` es `null` si se cerró con normalidad (por ejemplo, con `exit`). */
    data class Closed(val error: String?) : TerminalPhase
}

data class TerminalState(
    val phase: TerminalPhase = TerminalPhase.Connecting,
    /** El servidor presenta una clave desconocida o distinta: hay que preguntar. */
    val hostKey: HostKeyQuestion? = null,
    /** El servidor pide datos para entrar (contraseña, código…). */
    val login: LoginQuestion? = null,
)

/**
 * Una sesión SSH para la pantalla de terminal. La conexión la hace el núcleo; aquí solo se
 * lleva el estado, las preguntas pendientes y el paso de bytes. Todo se llama desde el hilo
 * principal; lo que cuenta el núcleo llega por `main`, en orden.
 */
class TerminalModel internal constructor(
    val host: HostSummary,
    /** La bóveda abierta, o `null` si se bloqueó. */
    private val vault: () -> Vault?,
    private val main: Executor,
) {
    private val _state = MutableStateFlow(TerminalState())
    val state: StateFlow<TerminalState> = _state.asStateFlow()

    /**
     * Lo que llega del servidor. Lo que llegue antes de que la pantalla se lo pida se guarda y
     * se entrega entonces.
     */
    var onOutput: ((ByteArray) -> Unit)? = null
        set(value) {
            field = value
            flushPending()
        }

    private var session: TerminalSession? = null
    private val pending = ArrayDeque<ByteArray>()
    private var cols = DEFAULT_COLS
    private var rows = DEFAULT_ROWS

    /** Cada conexión tiene su número: lo que llegue de una anterior se descarta. */
    private var generation = 0

    /** La app pasó a segundo plano con la sesión abierta. */
    private var wasInBackground = false

    /** Estaba conectada y se cortó con la app en segundo plano: la red, no la persona. */
    private var dropped = false

    private var started = false

    /** La primera vez que se muestra la pantalla, conecta; las siguientes (un giro), no. */
    fun start() {
        if (started) return
        started = true
        connect()
    }

    /** Conecta con el tamaño actual de la pantalla. Si ya había una sesión, la cierra antes. */
    fun connect() {
        session?.disconnect()
        session = null
        generation++
        dropped = false
        _state.value = TerminalState(TerminalPhase.Connecting)
        val open = vault()
        if (open == null) {
            finish(LOCKED)
            return
        }
        val listener = Listener(generation)
        session = try {
            open.openTerminal(host.id, cols.toUShort(), rows.toUShort(), listener)
        } catch (error: TunelException) {
            finish(errorMessage(error))
            null
        } catch (_: IllegalStateException) {
            // El núcleo ya soltó la bóveda: se bloqueó.
            finish(LOCKED)
            null
        }
    }

    fun send(data: ByteArray) {
        session?.send(data)
    }

    fun resize(cols: Int, rows: Int) {
        if (cols <= 0 || rows <= 0) return
        val newCols = cols.coerceAtMost(UShort.MAX_VALUE.toInt())
        val newRows = rows.coerceAtMost(UShort.MAX_VALUE.toInt())
        if (newCols == this.cols && newRows == this.rows) return
        this.cols = newCols
        this.rows = newRows
        session?.resize(newCols.toUShort(), newRows.toUShort())
    }

    fun answerHostKey(accept: Boolean) {
        _state.update { it.copy(hostKey = null) }
        try {
            session?.answerHostKey(accept)
        } catch (error: TunelException) {
            finish(errorMessage(error))
        }
    }

    /** `null` cancela. */
    fun answerLogin(answers: List<String>?) {
        _state.update { it.copy(login = null) }
        session?.answerLogin(answers)
    }

    /** Cierra la sesión; lo que llegue después ya no se atiende. */
    fun close() {
        generation++
        session?.disconnect()
        session = null
        pending.clear()
    }

    fun didEnterBackground() {
        wasInBackground = true
    }

    /**
     * De vuelta en primer plano: si la conexión abierta se cortó mientras tanto, se reconecta.
     * No si ya había terminado (`exit`, una clave rechazada, un inicio de sesión cancelado).
     */
    fun didBecomeActive() {
        val reconnect = wasInBackground && dropped
        wasInBackground = false
        if (reconnect) connect()
    }

    private fun handle(event: Event, from: Int) {
        if (from != generation) return
        when (event) {
            Event.Connected -> _state.update { it.copy(phase = TerminalPhase.Connected) }
            is Event.Output -> onOutput?.invoke(event.data) ?: pending.addLast(event.data)
            is Event.HostKey -> _state.update { it.copy(hostKey = event.question) }
            is Event.Login -> _state.update { it.copy(login = event.question) }
            is Event.Closed -> {
                // Ya cerrada (no se pudo guardar la clave): se queda el motivo de entonces.
                if (_state.value.phase is TerminalPhase.Closed) return
                val wasConnected = _state.value.phase == TerminalPhase.Connected
                finish(event.error)
                dropped = wasConnected && wasInBackground
            }
        }
    }

    private fun finish(error: String?) {
        dropped = false
        session = null
        _state.value = TerminalState(TerminalPhase.Closed(error))
    }

    private fun flushPending() {
        val sink = onOutput ?: return
        while (pending.isNotEmpty()) sink(pending.removeFirst())
    }

    private sealed interface Event {
        data object Connected : Event

        class Output(val data: ByteArray) : Event

        data class HostKey(val question: HostKeyQuestion) : Event

        data class Login(val question: LoginQuestion) : Event

        data class Closed(val error: String?) : Event
    }

    /** Recibe los avisos del núcleo, desde sus hilos, y los pasa en orden a `main`. */
    private inner class Listener(private val from: Int) : TerminalListener {
        override fun connected() = deliver(Event.Connected)

        override fun output(data: ByteArray) = deliver(Event.Output(data))

        override fun hostKey(question: HostKeyQuestion) = deliver(Event.HostKey(question))

        override fun login(question: LoginQuestion) = deliver(Event.Login(question))

        override fun closed(error: String?) = deliver(Event.Closed(error))

        private fun deliver(event: Event) = main.execute { handle(event, from) }
    }

    private companion object {
        const val DEFAULT_COLS = 80
        const val DEFAULT_ROWS = 24
        const val LOCKED = "La bóveda está bloqueada"
    }
}
