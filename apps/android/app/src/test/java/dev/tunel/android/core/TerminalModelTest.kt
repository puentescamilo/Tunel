package dev.tunel.android.core

import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.tunel_mobile.HostSummary

/** La terminal contra el núcleo y un servidor SSH de verdad. */
class TerminalModelTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val server = TestSshServer()
    private val main = MainQueue()

    @After
    fun stopServer() = server.close()

    private suspend fun TestScope.openStore(): VaultStore {
        val store = VaultStore(
            folder.root.resolve("vault.json").absolutePath,
            StandardTestDispatcher(testScheduler),
            main = main,
        )
        store.create("correcta-caballo", "correcta-caballo")
        return store
    }

    /** Un host personal que apunta al servidor de juguete. */
    private fun VaultStore.addHost(): HostSummary {
        val vault = checkNotNull(vault)
        val draft = vault.newHostDraft(null).apply {
            label = "juguete"
            address = "127.0.0.1"
            port = server.port.toUShort()
            protocol = "SSH"
            newUsername = TestSshServer.USER
            newPassword = TestSshServer.PASSWORD
        }
        return vault.saveHost(draft)
    }

    /** Lo que la terminal mostraría, como texto. */
    private class Screen(model: TerminalModel) {
        private val text = StringBuilder()

        init {
            model.onOutput = { text.append(it.decodeToString()) }
        }

        operator fun contains(fragment: String) = fragment in text
    }

    private fun TerminalModel.connectTrusting(): Screen {
        val screen = Screen(this)
        start()
        main.runUntil { state.value.hostKey != null }
        answerHostKey(true)
        main.runUntil { "bienvenida" in screen }
        return screen
    }

    @Test
    fun theFirstConnectionAsksAboutTheServerKeyAndThenOpensTheShell() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        val screen = Screen(terminal)

        terminal.start()
        main.runUntil { terminal.state.value.hostKey != null }

        val question = checkNotNull(terminal.state.value.hostKey)
        assertTrue(question.fingerprint.startsWith("SHA256:"))
        assertNull(question.expected)
        terminal.answerHostKey(true)
        main.runUntil { "bienvenida" in screen }
        assertEquals(TerminalPhase.Connected, terminal.state.value.phase)
    }

    @Test
    fun whatIsTypedReachesTheServerAndItsAnswerIsShown() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        val screen = terminal.connectTrusting()

        terminal.send("hola".encodeToByteArray())

        main.runUntil { "HOLA" in screen }
    }

    @Test
    fun anAcceptedKeyIsNotAskedAboutAgain() = runTest {
        val store = openStore()
        val host = store.addHost()
        checkNotNull(store.openTerminal(host)).connectTrusting()

        val again = checkNotNull(store.openTerminal(host))
        val screen = Screen(again)
        again.start()
        main.runUntil { "bienvenida" in screen }

        assertNull(again.state.value.hostKey)
    }

    @Test
    fun rejectingTheKeyClosesAndSaysWhy() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.start()
        main.runUntil { terminal.state.value.hostKey != null }

        terminal.answerHostKey(false)
        main.runUntil { terminal.state.value.phase is TerminalPhase.Closed }

        val phase = terminal.state.value.phase as TerminalPhase.Closed
        assertTrue(phase.error.orEmpty().contains("rechazaste"))
    }

    @Test
    fun exitEndsTheSessionNormally() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.connectTrusting()

        terminal.send("exit\r".encodeToByteArray())
        main.runUntil { terminal.state.value.phase is TerminalPhase.Closed }

        assertEquals(TerminalPhase.Closed(null), terminal.state.value.phase)
    }

    @Test
    fun whatArrivesBeforeTheScreenIsReadyIsKept() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.start()
        main.runUntil { terminal.state.value.hostKey != null }
        terminal.answerHostKey(true)
        main.runUntil { terminal.state.value.phase == TerminalPhase.Connected }

        val screen = Screen(terminal)
        main.runUntil { "bienvenida" in screen }
    }

    @Test
    fun comingBackAfterTheConnectionDroppedReconnects() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.connectTrusting()
        terminal.didEnterBackground()
        // Se cae el servidor (o la red) con la app en segundo plano.
        server.close()
        main.runUntil { terminal.state.value.phase is TerminalPhase.Closed }

        terminal.didBecomeActive()

        assertEquals(TerminalPhase.Connecting, terminal.state.value.phase)
    }

    @Test
    fun comingBackAfterExitDoesNotReconnect() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.connectTrusting()
        terminal.send("exit\r".encodeToByteArray())
        main.runUntil { terminal.state.value.phase is TerminalPhase.Closed }

        terminal.didEnterBackground()
        terminal.didBecomeActive()

        assertEquals(TerminalPhase.Closed(null), terminal.state.value.phase)
    }

    @Test
    fun comingBackAfterRejectingTheKeyDoesNotAskAgain() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.start()
        main.runUntil { terminal.state.value.hostKey != null }
        terminal.didEnterBackground()
        terminal.answerHostKey(false)
        main.runUntil { terminal.state.value.phase is TerminalPhase.Closed }

        terminal.didBecomeActive()

        assertTrue(terminal.state.value.phase is TerminalPhase.Closed)
        assertNull(terminal.state.value.hostKey)
    }

    @Test
    fun lockingClosesTheTerminal() = runTest {
        val store = openStore()
        val terminal = checkNotNull(store.openTerminal(store.addHost()))
        terminal.connectTrusting()

        store.lock()

        assertNull(store.terminal.value)
        // Si la pantalla intentara reconectar, la bóveda ya no está.
        terminal.connect()
        assertEquals(TerminalPhase.Closed("La bóveda está bloqueada"), terminal.state.value.phase)
    }

    @Test
    fun withTheVaultLockedNoTerminalOpens() = runTest {
        val store = openStore()
        val host = store.addHost()
        store.lock()

        assertNull(store.openTerminal(host))
    }
}
