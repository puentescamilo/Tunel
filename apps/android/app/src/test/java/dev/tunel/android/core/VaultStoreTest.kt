package dev.tunel.android.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.minPasswordLength
import uniffi.tunel_mobile.vaultExists
import kotlin.coroutines.CoroutineContext

/** Contra el núcleo de verdad, compilado para este equipo. */
class VaultStoreTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val password = "correcta-caballo"

    private fun path() = folder.root.resolve("vault.json").absolutePath

    private fun TestScope.store(path: String = path()) =
        VaultStore(path, StandardTestDispatcher(testScheduler))

    @Test
    fun withoutAVaultItAsksToCreateOne() = runTest {
        val store = store()
        assertEquals(VaultStore.Phase.NEEDS_SETUP, store.state.value.phase)

        store.create(password, password)

        assertEquals(VaultStore.Phase.UNLOCKED, store.state.value.phase)
        assertNull(store.state.value.errorMessage)
        assertFalse(store.state.value.isWorking)
    }

    @Test
    fun mismatchedPasswordsDoNotCreateTheVault() = runTest {
        val store = store()

        store.create(password, "correcta-caballa")

        assertEquals(VaultStore.Phase.NEEDS_SETUP, store.state.value.phase)
        assertEquals("Las contraseñas no coinciden", store.state.value.errorMessage)
        assertFalse(vaultExists(path()))
    }

    @Test
    fun aShortPasswordShowsTheCoreMessage() = runTest {
        val store = store()

        store.create("corta", "corta")

        assertEquals(VaultStore.Phase.NEEDS_SETUP, store.state.value.phase)
        assertEquals(
            "La contraseña maestra debe tener al menos ${minPasswordLength()} caracteres",
            store.state.value.errorMessage,
        )
    }

    @Test
    fun lockingAndUnlockingAgainWorksWithTheRightPassword() = runTest {
        val store = store()
        store.create(password, password)

        store.lock()
        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        store.unlock(password)

        assertEquals(VaultStore.Phase.UNLOCKED, store.state.value.phase)
    }

    @Test
    fun aWrongPasswordShowsTheCoreMessage() = runTest {
        val store = store()
        store.create(password, password)
        store.lock()

        store.unlock("otra-contraseña")

        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertEquals("Contraseña maestra incorrecta", store.state.value.errorMessage)
    }

    @Test
    fun anExistingVaultStartsLocked() = runTest {
        Vault.create(path(), password).close()

        assertEquals(VaultStore.Phase.LOCKED, store().state.value.phase)
    }

    @Test
    fun lockingForgetsTheHosts() = runTest {
        val store = store()
        store.create(password, password)

        store.lock()

        assertEquals(HostTree.EMPTY, store.state.value.tree)
    }

    @Test
    fun lockingWhileItOpensKeepsItLocked() = runTest {
        Vault.create(path(), password).close()
        val worker = GatedDispatcher()
        val store = VaultStore(path(), worker)

        val opening = launch { store.unlock(password) }
        runCurrent()
        // La app pasa a segundo plano mientras se deriva la clave.
        store.lock()
        finish(opening, worker)

        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertFalse(store.state.value.isWorking)
        assertEquals(HostTree.EMPTY, store.state.value.tree)
        // Y se puede volver a abrir: la apertura descartada cerró la bóveda.
        finish(launch { store.unlock(password) }, worker)
        assertEquals(VaultStore.Phase.UNLOCKED, store.state.value.phase)
    }

    @Test
    fun cancellingWhileItOpensLeavesNothingHalfDone() = runTest {
        Vault.create(path(), password).close()
        val worker = GatedDispatcher()
        val store = VaultStore(path(), worker)

        val opening = launch { store.unlock(password) }
        runCurrent()
        worker.runAll()
        opening.cancel()
        runCurrent()

        assertEquals(VaultStore.Phase.LOCKED, store.state.value.phase)
        assertFalse(store.state.value.isWorking)
    }

    /** Alterna el trabajo del núcleo y el de la prueba hasta que la apertura acaba. */
    private fun TestScope.finish(job: Job, worker: GatedDispatcher) {
        while (job.isActive) {
            worker.runAll()
            runCurrent()
        }
    }
}

/** Retiene el trabajo del núcleo hasta que la prueba lo suelta. */
private class GatedDispatcher : CoroutineDispatcher() {
    private val queue = ArrayDeque<Runnable>()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        queue.addLast(block)
    }

    fun runAll() {
        while (queue.isNotEmpty()) queue.removeFirst().run()
    }
}
