package dev.tunel.android.core

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Unirse a la cuenta y sincronizar, contra el núcleo y un servidor de verdad. */
class AccountActionsTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val password = "correcta-caballo"

    private suspend fun TestScope.openStore(): VaultStore {
        val store = VaultStore(
            folder.root.resolve("vault.json").absolutePath,
            StandardTestDispatcher(testScheduler),
            clock = { 42 },
        )
        store.create(password, password)
        return store
    }

    private suspend fun VaultStore.signIn(server: TestServer, accountPassword: String = TestServer.PASSWORD) =
        account.signIn(server.url, TestServer.EMAIL, accountPassword)

    private fun VaultStore.labels() = state.value.tree.hosts.map { it.label }

    @Test
    fun aNewVaultHasNoAccountAndSyncingDoesNothing() = runTest {
        val store = openStore()

        store.account.sync()

        assertNull(store.state.value.account)
        assertEquals(SyncStatus.Idle, store.state.value.sync)
    }

    @Test
    fun aServerWithoutHttpsOnTheInternetIsRejectedWithAMessage() = runTest {
        val store = openStore()

        store.account.loadOptions("http://tunel.example.com")

        val signIn = store.state.value.signIn
        assertNull(signIn.options)
        assertFalse(signIn.isWorking)
        assertTrue(signIn.errorMessage.orEmpty().isNotBlank())
    }

    @Test
    fun theServerSaysHowToSignIn() = runTest {
        TestServer().use { server ->
            val store = openStore()

            store.account.loadOptions(server.url)

            val options = store.state.value.signIn.options
            assertNotNull(options)
            assertTrue(options?.passwordLogin == true)
        }
    }

    @Test
    fun signingInDownloadsTheHostsOfTheAccount() = runTest {
        TestServer("web-01", "db-01").use { server ->
            val store = openStore()

            store.signIn(server)

            val state = store.state.value
            assertEquals(TestServer.EMAIL, state.account?.email)
            assertEquals(listOf("db-01", "web-01"), store.labels().sorted())
            assertEquals(SyncStatus.Synced(at = 42, problems = emptyList(), invitations = 0), state.sync)
            assertFalse(state.signIn.isWorking)
            assertNull(state.signIn.errorMessage)
        }
    }

    @Test
    fun aWrongAccountPasswordIsExplainedAndNothingChanges() = runTest {
        TestServer("web-01").use { server ->
            val store = openStore()

            store.signIn(server, accountPassword = "otra-contraseña")

            val state = store.state.value
            assertNull(state.account)
            assertTrue(state.tree.hosts.isEmpty())
            assertTrue(state.signIn.errorMessage.orEmpty().isNotBlank())
        }
    }

    @Test
    fun theAccountIsStillThereAfterLockingAndUnlocking() = runTest {
        TestServer("web-01").use { server ->
            val store = openStore()
            store.signIn(server)

            store.lock()
            store.unlock(password)

            assertEquals(TestServer.EMAIL, store.state.value.account?.email)
            assertEquals(listOf("web-01"), store.labels())
            // Hasta que se vuelve a sincronizar.
            assertEquals(SyncStatus.Idle, store.state.value.sync)
        }
    }

    @Test
    fun signingOutForgetsTheAccountAndWhatItDownloaded() = runTest {
        TestServer("web-01").use { server ->
            val store = openStore()
            store.signIn(server)

            store.account.signOut()

            val state = store.state.value
            assertNull(state.account)
            assertTrue(state.tree.hosts.isEmpty())
            assertEquals(SyncStatus.Idle, state.sync)
        }
    }

    @Test
    fun lockingWhileItSyncsLeavesItLockedWithoutErrors() = runTest {
        TestServer("web-01").use { server ->
            val worker = GatedDispatcher()
            val path = folder.root.resolve("vault.json").absolutePath
            val store = VaultStore(path, worker)
            finish(launch { store.create(password, password) }, worker)
            finish(launch { store.signIn(server) }, worker)

            val syncing = launch { store.account.sync() }
            runCurrent()
            assertEquals(SyncStatus.Syncing, store.state.value.sync)
            // La app pasa a segundo plano mientras va la red.
            store.lock()
            finish(syncing, worker)

            val state = store.state.value
            assertEquals(VaultStore.Phase.LOCKED, state.phase)
            assertEquals(SyncStatus.Idle, state.sync)
            assertTrue(state.tree.hosts.isEmpty())
            assertNull(state.account)
        }
    }

    @Test
    fun aBrowserReturnNobodyWaitedForIsIgnored() = runTest {
        val store = openStore()

        store.account.providerReturned("tunel://oauth?code=ajeno&state=ajeno")

        val signIn = store.state.value.signIn
        assertNull(signIn.providerEmail)
        assertNull(signIn.errorMessage)
    }

    @Test
    fun withTheVaultLockedNothingTalksToTheServer() = runTest {
        TestServer().use { server ->
            val store = openStore()
            store.lock()

            store.account.loadOptions(server.url)

            assertEquals(VaultStore.State(VaultStore.Phase.LOCKED), store.state.value)
        }
    }

    @Test
    fun lockingForgetsAHalfDoneSignIn() = runTest {
        val store = openStore()
        store.account.loadOptions("http://tunel.example.com")

        store.lock()
        store.unlock(password)

        assertEquals(SignInState(), store.state.value.signIn)
    }

    @Test
    fun withoutABrowserItExplainsWhyTheProviderDidNotOpen() = runTest {
        val store = openStore()

        store.account.browserFailed()

        val signIn = store.state.value.signIn
        assertEquals("No hay ningún navegador para abrir la página del proveedor", signIn.errorMessage)
        assertNull(signIn.providerEmail)
    }
}
