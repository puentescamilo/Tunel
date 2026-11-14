package dev.tunel.android.core

import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Una huella en memoria: se acepta o se cancela según `accepts`. */
private class FakeBiometrics : BiometricDevice {
    var accepts = true
    var failure: String? = null
    val items = mutableMapOf<String, ByteArray>()

    override val isAvailable = true

    override suspend fun save(id: String, key: ByteArray): Boolean {
        failure?.let { throw BiometricFailure(it) }
        if (!accepts) return false
        items.clear()
        items[id] = key.copyOf()
        return true
    }

    override suspend fun load(id: String): ByteArray? {
        failure?.let { throw BiometricFailure(it) }
        if (!accepts) return null
        return items[id]?.copyOf() ?: throw BiometricKeyMissing()
    }

    override fun has(id: String) = id in items

    override fun removeAll() = items.clear()
}

/** El desbloqueo con huella contra el núcleo de verdad. */
class BiometricActionsTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val password = "correcta-caballo"
    private val device = FakeBiometrics()

    private suspend fun TestScope.unlockedStore(): VaultStore {
        val store = VaultStore(
            folder.root.resolve("vault.json").absolutePath,
            StandardTestDispatcher(testScheduler),
            biometricDevice = device,
        )
        store.create(password, password)
        return store
    }

    private val VaultStore.biometric get() = state.value.biometric

    @Test
    fun theFingerprintOpensTheVaultOnceEnabled() = runTest {
        val store = unlockedStore()

        store.biometrics.setEnabled(true)
        assertTrue(store.biometric.enabled)
        assertEquals(1, device.items.size)
        store.lock()
        assertTrue(store.biometric.ready)
        store.biometrics.unlock()

        assertEquals(VaultStore.Phase.UNLOCKED, store.state.value.phase)
        assertNull(store.state.value.errorMessage)
        assertTrue(store.biometric.enabled)
    }

    @Test
    fun cancellingTheFingerprintLeavesTheVaultLockedWithoutComplaining() = runTest {
        val store = unlockedStore()
        store.biometrics.setEnabled(true)
        store.lock()

        device.accepts = false
        store.biometrics.unlock()

        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertNull(store.state.value.errorMessage)
        assertTrue(store.biometric.ready)
    }

    @Test
    fun cancellingTheConfirmationDoesNotEnableIt() = runTest {
        val store = unlockedStore()

        device.accepts = false
        store.biometrics.setEnabled(true)

        assertFalse(store.biometric.enabled)
        assertTrue(device.items.isEmpty())
        store.lock()
        assertFalse(store.biometric.ready)
        assertFalse(store.biometric.waitsForPassword)
    }

    @Test
    fun aSystemErrorWhileEnablingIsExplainedAndLeavesItOff() = runTest {
        val store = unlockedStore()

        device.failure = "Demasiados intentos"
        store.biometrics.setEnabled(true)

        assertFalse(store.biometric.enabled)
        assertEquals("No se pudo activar la huella: Demasiados intentos", store.state.value.errorMessage)
    }

    @Test
    fun aKeyLostWhileLockedExplainsWhatToDo() = runTest {
        val store = unlockedStore()
        store.biometrics.setEnabled(true)
        store.lock()

        // Se pierde la clave con la pantalla de bloqueo ya mostrando el botón.
        device.items.clear()
        store.biometrics.unlock()

        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertTrue(store.state.value.errorMessage.orEmpty().contains("ya no tiene la clave"))
        // Y deja de ofrecerla.
        assertFalse(store.biometric.ready)
    }

    @Test
    fun afterTheFingerprintsChangeItIsOffAndCanBeEnabledAgain() = runTest {
        val store = unlockedStore()
        store.biometrics.setEnabled(true)
        // Como cuando se registra otra huella: Android invalida la clave.
        device.items.clear()

        store.lock()
        assertFalse(store.biometric.ready)
        assertFalse(store.biometric.waitsForPassword)
        store.unlock(password)
        assertFalse(store.biometric.enabled)

        store.biometrics.setEnabled(true)
        store.lock()
        store.biometrics.unlock()
        assertEquals(VaultStore.Phase.UNLOCKED, store.state.value.phase)
    }

    @Test
    fun aKeyFromAnotherActivationDoesNotOpenTheVault() = runTest {
        val store = unlockedStore()
        store.biometrics.setEnabled(true)
        store.lock()

        val id = device.items.keys.single()
        device.items[id] = ByteArray(32) { 7 }
        store.biometrics.unlock()

        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertTrue(store.state.value.errorMessage.orEmpty().isNotBlank())
    }

    @Test
    fun disablingForgetsTheKeyAndStopsOfferingIt() = runTest {
        val store = unlockedStore()
        store.biometrics.setEnabled(true)

        store.biometrics.setEnabled(false)
        store.lock()

        assertTrue(device.items.isEmpty())
        assertFalse(store.biometric.ready)
        assertFalse(store.biometric.waitsForPassword)
    }

    @Test
    fun onlyALockAfterTheGracePeriodPromptsTheFingerprintByItself() = runTest {
        val store = unlockedStore()

        store.lock()
        assertFalse(store.biometric.promptOnAppear)

        store.unlock(password)
        store.didEnterBackground(now = 0)
        store.didBecomeActive(now = VaultStore.BACKGROUND_GRACE_MS)
        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertTrue(store.biometric.promptOnAppear)
    }

    @Test
    fun withoutFingerprintEnabledNothingIsOffered() = runTest {
        val store = unlockedStore()

        store.lock()
        store.biometrics.unlock()

        assertFalse(store.biometric.ready)
        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
    }
}
