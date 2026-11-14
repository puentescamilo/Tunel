package dev.tunel.android.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import uniffi.tunel_mobile.ProviderSignIn
import uniffi.tunel_mobile.TunelException
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.errorMessage
import uniffi.tunel_mobile.signInOptions
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Unirse a la cuenta de Túnel y descargar lo sincronizado, sobre la bóveda abierta de
 * [VaultStore]. Lo que habla con el servidor corre en `worker`; si la bóveda se bloquea a
 * medias, el resultado se descarta.
 */
class AccountActions internal constructor(
    private val store: VaultStore,
    private val worker: CoroutineDispatcher,
    private val clock: () -> Long,
) {
    private val busy = AtomicBoolean(false)

    /**
     * Un inicio de sesión con un proveedor: esperando al navegador o, después, a la
     * contraseña maestra. Lo protege `store.guard`.
     */
    private var pending: ProviderSignIn? = null

    /** Cómo se puede entrar en `server`: proveedores y si admite contraseña. */
    suspend fun loadOptions(server: String) {
        run { started, _ ->
            val options = withContext(worker) { signInOptions(server) }
            store.publish(started) { it.copy(signIn = it.signIn.copy(options = options)) }
        }
    }

    /** Se cambió el servidor: hay que volver a preguntar cómo se entra. */
    fun forgetOptions() {
        store.update { it.copy(signIn = it.signIn.copy(options = null, errorMessage = null)) }
    }

    suspend fun signIn(server: String, email: String, password: String) {
        val joined = run { started, vault ->
            withContext(worker) { vault.signInWithPassword(server, email, password) }
            reload(started, vault)
        }
        if (joined != null) sync()
    }

    /**
     * Empieza a entrar con un proveedor y devuelve la dirección que hay que abrir en el
     * navegador, o `null` si falló (el motivo queda en el estado).
     */
    suspend fun beginProvider(server: String, providerId: String): String? = run { started, _ ->
        val signIn = withContext(worker) { ProviderSignIn.begin(server, providerId) }
        val previous = synchronized(store.guard) {
            if (store.generation != started) {
                signIn.close()
                return@run null
            }
            pending.also { pending = signIn }
        }
        previous?.close()
        signIn.url()
    }

    /**
     * El navegador volvió a `callback` (`tunel://oauth?…`). Si no se esperaba a nadie, no
     * hace nada: otra app puede abrir esa dirección.
     */
    suspend fun providerReturned(callback: String) {
        run { started, _ ->
            val signIn = synchronized(store.guard) { pending } ?: return@run
            val email = try {
                withContext(worker) { signIn.returned(callback) }
            } catch (error: TunelException) {
                // Ya no sirve: hay que empezar de nuevo.
                drop(signIn)
                throw error
            }
            store.publish(started) { it.copy(signIn = it.signIn.copy(providerEmail = email)) }
        }
    }

    /**
     * Termina de entrar con un proveedor con la contraseña maestra de la cuenta. Si no es la
     * correcta, se puede volver a intentar sin pasar otra vez por el navegador.
     */
    suspend fun finishProvider(masterPassword: String) {
        val joined = run { started, vault ->
            val signIn = synchronized(store.guard) { pending } ?: return@run null
            withContext(worker) { vault.signInWithProvider(signIn, masterPassword) }
            drop(signIn)
            reload(started, vault)
        }
        if (joined != null) sync()
    }

    /** Deja el inicio de sesión con el proveedor. No mientras se termina: ya está en marcha. */
    fun cancelProvider() {
        if (!busy.compareAndSet(false, true)) return
        try {
            synchronized(store.guard) { pending.also { pending = null } }?.close()
            store.update { it.copy(signIn = it.signIn.copy(providerEmail = null, errorMessage = null)) }
        } finally {
            busy.set(false)
        }
    }

    /** No se pudo abrir el navegador: el inicio de sesión no sigue. */
    fun browserFailed() {
        synchronized(store.guard) { pending.also { pending = null } }?.close()
        store.update {
            it.copy(signIn = it.signIn.copy(errorMessage = "No hay ningún navegador para abrir la página del proveedor"))
        }
    }

    /** Descarga lo nuevo. Los errores se quedan en `sync`: la lista sigue con lo que había. */
    suspend fun sync() {
        val (vault, started) = synchronized(store.guard) {
            val open = store.vault
            val state = store.state.value
            if (open == null || state.account == null || state.sync == SyncStatus.Syncing) return
            store.update { it.copy(sync = SyncStatus.Syncing) }
            open to store.generation
        }
        var outcome: SyncStatus = SyncStatus.Idle
        try {
            val report = withContext(worker) { vault.sync() }
            reload(started, vault)
            outcome = SyncStatus.Synced(clock(), report.teamProblems, report.invitations.toInt())
        } catch (error: TunelException) {
            outcome = SyncStatus.Failed(errorMessage(error))
        } catch (error: IllegalStateException) {
            // El núcleo ya soltó la bóveda: se bloqueó mientras iba la red.
            if (stillOpen(started)) throw error
        } finally {
            // También si se cancela: no se queda «Sincronizando…» para siempre.
            store.publish(started) { it.copy(sync = outcome) }
        }
    }

    /** Desvincula el dispositivo; lo descargado se borra. */
    suspend fun signOut() {
        run { started, vault ->
            withContext(worker) { vault.signOut() }
            reload(started, vault)
            store.publish(started) { it.copy(sync = SyncStatus.Idle) }
        }
    }

    /** Al bloquear: lo que hay que cerrar. Se llama con `store.guard` tomado. */
    internal fun forget(): List<AutoCloseable> = listOfNotNull(pending).also { pending = null }

    private fun drop(signIn: ProviderSignIn) {
        val mine = synchronized(store.guard) {
            (pending === signIn).also { if (it) pending = null }
        }
        if (mine) signIn.close()
        store.update { it.copy(signIn = it.signIn.copy(providerEmail = null)) }
    }

    private suspend fun reload(started: Long, vault: Vault) {
        val (tree, account) = store.snapshot(vault)
        store.publish(started) { it.copy(tree = tree, account = account) }
    }

    private fun stillOpen(started: Long) =
        synchronized(store.guard) { store.generation == started && store.vault != null }

    /**
     * Ejecuta `work` con la bóveda abierta, mostrando que trabaja y el error, si lo hay.
     * Devuelve `null` si no se pudo empezar o falló.
     */
    private suspend fun <T> run(work: suspend (started: Long, vault: Vault) -> T): T? {
        val (vault, started) = synchronized(store.guard) {
            store.vault?.let { it to store.generation }
        } ?: return null
        if (!busy.compareAndSet(false, true)) return null
        store.publish(started) { it.copy(signIn = it.signIn.copy(isWorking = true, errorMessage = null)) }
        return try {
            work(started, vault)
        } catch (error: TunelException) {
            store.publish(started) { it.copy(signIn = it.signIn.copy(errorMessage = errorMessage(error))) }
            null
        } catch (error: IllegalStateException) {
            if (stillOpen(started)) throw error
            null
        } finally {
            store.publish(started) { it.copy(signIn = it.signIn.copy(isWorking = false)) }
            busy.set(false)
        }
    }
}
