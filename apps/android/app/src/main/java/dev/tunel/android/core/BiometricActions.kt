package dev.tunel.android.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import uniffi.tunel_mobile.TunelException
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.biometricId
import uniffi.tunel_mobile.biometricReady
import uniffi.tunel_mobile.errorMessage
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Desbloqueo con huella. El núcleo guarda junto a la bóveda su clave sellada; la clave que
 * abre ese sello la guarda [BiometricDevice] y solo sale tras la huella. La primera vez de
 * cada día hay que entrar con la contraseña maestra, para no olvidarla.
 */
class BiometricActions internal constructor(
    private val store: VaultStore,
    private val path: String,
    private val device: BiometricDevice,
    private val worker: CoroutineDispatcher,
) {
    private val busy = AtomicBoolean(false)

    val isAvailable: Boolean get() = device.isAvailable

    /** Pide la huella y abre la bóveda. Si se cancela, no pasa nada: queda la contraseña. */
    suspend fun unlock() {
        // Se pida o no, ya no se vuelve a pedir sola (un giro de pantalla no la repite).
        store.update { it.copy(biometric = it.biometric.copy(promptOnAppear = false)) }
        val state = store.state.value
        if (!state.biometric.ready || state.isWorking) return
        val id = biometricId(path) ?: return
        if (!busy.compareAndSet(false, true)) return
        try {
            store.update { it.copy(errorMessage = null) }
            val key = load(id)
            if (key != null) {
                try {
                    store.openWith { Vault.unlockBiometric(path, key) }
                } finally {
                    key.fill(0)
                }
            }
        } finally {
            busy.set(false)
        }
        // Sigue bloqueada (cancelada, clave perdida…): se vuelve a mirar qué se puede ofrecer.
        if (store.state.value.phase != VaultStore.Phase.UNLOCKED) {
            store.update { it.copy(biometric = locked(promptOnAppear = false)) }
        }
    }

    /**
     * Activa o quita la huella para la bóveda abierta. Activarla pide la huella una vez:
     * así se comprueba que funciona y se cifra la clave.
     */
    suspend fun setEnabled(enabled: Boolean) {
        val (vault, started) = synchronized(store.guard) {
            store.vault?.let { it to store.generation }
        } ?: return
        if (!device.isAvailable || !busy.compareAndSet(false, true)) return
        store.update { it.copy(errorMessage = null) }
        var problem: String? = null
        try {
            if (enabled) enable(vault) else disable(vault)
        } catch (error: TunelException) {
            problem = errorMessage(error)
        } catch (error: BiometricFailure) {
            problem = error.message
        } catch (_: IllegalStateException) {
            // Se bloqueó mientras tanto: el núcleo ya soltó la bóveda.
            return
        } finally {
            busy.set(false)
        }
        val now = withContext(worker) { runCatching { vault.biometricEnabled() }.getOrDefault(false) }
        store.publish(started) {
            it.copy(
                biometric = it.biometric.copy(enabled = now),
                errorMessage = problem?.let { reason -> "No se pudo activar la huella: $reason" },
            )
        }
    }

    /**
     * Cómo queda la huella al bloquear (o al arrancar la app). Solo cuenta como activada si el
     * teléfono aún tiene la clave: si cambiaron las huellas, Android la borró.
     */
    internal fun locked(promptOnAppear: Boolean): BiometricState {
        val enabled = device.isAvailable && biometricId(path)?.let(device::has) == true
        val ready = enabled && biometricReady(path)
        return BiometricState(
            ready = ready,
            waitsForPassword = enabled && !ready,
            promptOnAppear = promptOnAppear,
        )
    }

    /**
     * Cómo queda al abrir `vault`, fuera del hilo principal. Si el núcleo la tiene activada
     * pero el teléfono perdió la clave, se desactiva también en el núcleo: así Ajustes la
     * muestra apagada y se puede volver a activar.
     */
    internal suspend fun unlocked(vault: Vault): BiometricState = withContext(worker) {
        val id = biometricId(path)
        if (id != null && !device.has(id)) {
            runCatching { vault.disableBiometric() }
        }
        BiometricState(enabled = vault.biometricEnabled())
    }

    private suspend fun load(id: String): ByteArray? {
        val problem = try {
            return device.load(id)
        } catch (_: BiometricKeyMissing) {
            "La huella ya no tiene la clave de la bóveda (¿cambiaron las huellas registradas?). " +
                "Entra con la contraseña y vuelve a activarla en Ajustes."
        } catch (error: BiometricFailure) {
            "La huella no pudo abrir la bóveda (${error.message}). Entra con la contraseña."
        }
        store.update { it.copy(errorMessage = problem) }
        return null
    }

    private suspend fun enable(vault: Vault) {
        val saved = withContext(worker) { vault.enableBiometric() }
        try {
            val stored = try {
                device.save(saved.id, saved.key)
            } catch (error: Throwable) {
                // Sin la clave guardada, el archivo de la bóveda no sirve para nada. También
                // si se cancela: por eso `NonCancellable`.
                withContext(NonCancellable + worker) { runCatching { vault.disableBiometric() } }
                throw error
            }
            if (!stored) withContext(NonCancellable + worker) { vault.disableBiometric() }
        } finally {
            saved.key.fill(0)
        }
    }

    private suspend fun disable(vault: Vault) {
        try {
            withContext(worker) { vault.disableBiometric() }
        } finally {
            device.removeAll()
        }
    }
}
