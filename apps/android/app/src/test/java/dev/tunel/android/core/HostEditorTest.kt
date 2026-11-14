package dev.tunel.android.core

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Crear, editar y borrar hosts contra el núcleo de verdad. */
class HostEditorTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val password = "correcta-caballo"

    private suspend fun TestScope.openStore(): VaultStore {
        val store = VaultStore(folder.root.resolve("vault.json").absolutePath, StandardTestDispatcher(testScheduler))
        store.create(password, password)
        return store
    }

    private val VaultStore.form get() = editor.form.value

    private fun VaultStore.fill(label: String, address: String) = editor.edit {
        it.copy(draft = it.draft.copy(label = label, address = address))
    }

    private suspend fun VaultStore.addHost(label: String, address: String = "10.0.0.1") =
        checkNotNull(run {
            editor.startNew(null)
            fill(label, address)
            editor.save()
        })

    @Test
    fun aNewHostAppearsInTheListAndClosesTheForm() = runTest {
        val store = openStore()

        store.editor.startNew(null)
        assertTrue(store.form?.isNew == true)
        store.fill("web-01", "10.0.0.1")
        val saved = store.editor.save()

        assertNotNull(saved)
        assertNull(store.form)
        assertEquals(listOf("web-01"), store.state.value.tree.hosts.map { it.label })
    }

    @Test
    fun editingKeepsTheHostAndChangesWhatWasEdited() = runTest {
        val store = openStore()
        val host = store.addHost("web-01")

        store.editor.startEditing(host)
        assertEquals("web-01", store.form?.draft?.label)
        store.editor.edit { it.copy(draft = it.draft.copy(label = "web-02"), port = "2222", tags = "prod, web ,") }
        store.editor.save()

        val edited = store.state.value.tree.hosts.single()
        assertEquals(host.id, edited.id)
        assertEquals("web-02", edited.label)
        assertEquals(2222, edited.port.toInt())
        assertEquals(listOf("prod", "web"), edited.tags)
    }

    @Test
    fun deletingRemovesTheHost() = runTest {
        val store = openStore()
        val host = store.addHost("web-01")

        store.editor.startEditing(host)
        assertTrue(store.editor.delete())

        assertTrue(store.state.value.tree.hosts.isEmpty())
        assertNull(store.form)
    }

    @Test
    fun aWrongPortIsExplainedAndNothingIsSaved() = runTest {
        val store = openStore()
        store.editor.startNew(null)
        store.fill("web-01", "10.0.0.1")

        store.editor.edit { it.copy(port = "70000") }
        assertNull(store.editor.save())

        assertEquals("El puerto tiene que estar entre 1 y 65535", store.form?.errorMessage)
        assertTrue(store.state.value.tree.hosts.isEmpty())
    }

    @Test
    fun theCoreExplainsAnInvalidAddress() = runTest {
        val store = openStore()
        store.editor.startNew(null)
        store.fill("web-01", "10.0 .0.1")

        assertNull(store.editor.save())

        assertEquals("La dirección no puede tener espacios", store.form?.errorMessage)
        assertFalse(store.form?.isSaving == true)
    }

    @Test
    fun aNewCredentialNeedsAUser() = runTest {
        val store = openStore()
        store.editor.startNew(null)
        store.fill("web-01", "10.0.0.1")

        store.editor.edit { it.copy(credential = Credential.New) }
        assertNull(store.editor.save())

        assertEquals("Escribe el usuario de la credencial nueva", store.form?.errorMessage)
    }

    @Test
    fun aNewCredentialBecomesAnIdentityToChooseNextTime() = runTest {
        val store = openStore()
        store.editor.startNew(null)
        store.fill("web-01", "10.0.0.1")
        store.editor.edit {
            it.copy(
                credential = Credential.New,
                draft = it.draft.copy(newUsername = "ana", newPassword = "secreto"),
            )
        }
        store.editor.save()

        store.editor.startNew(null)
        val identity = store.form?.identities?.single()
        assertEquals("ana", identity?.username)
    }

    @Test
    fun choosingNoCredentialDropsWhatWasTypedForANewOne() = runTest {
        val store = openStore()
        store.editor.startNew(null)
        store.fill("web-01", "10.0.0.1")
        store.editor.edit {
            it.copy(credential = Credential.None, draft = it.draft.copy(newUsername = "ana", newPassword = "secreto"))
        }

        store.editor.save()
        store.editor.startNew(null)

        assertTrue(store.form?.identities.orEmpty().isEmpty())
    }

    @Test
    fun aJumpHostCycleIsExplained() = runTest {
        val store = openStore()
        val bastion = store.addHost("bastion")
        val web = store.addHost("web")
        store.editor.startEditing(web)
        store.editor.edit { it.copy(draft = it.draft.copy(jumpHostIds = listOf(bastion.id))) }
        store.editor.save()

        store.editor.startEditing(bastion)
        store.editor.edit { it.copy(draft = it.draft.copy(jumpHostIds = listOf(web.id))) }
        assertNull(store.editor.save())

        assertTrue(store.form?.errorMessage.orEmpty().contains("ciclo"))
    }

    @Test
    fun lockingDiscardsTheFormAndWhatWasTyped() = runTest {
        val store = openStore()
        store.editor.startNew(null)
        store.editor.edit {
            it.copy(credential = Credential.New, draft = it.draft.copy(newUsername = "ana", newPassword = "secreto"))
        }

        store.lock()

        assertNull(store.form)
    }

    @Test
    fun withTheVaultLockedNoFormOpens() = runTest {
        val store = openStore()
        store.lock()

        store.editor.startNew(null)

        assertNull(store.form)
    }

    @Test
    fun whileSavingTheFormCannotBeCancelled() = runTest {
        val worker = GatedDispatcher()
        val store = VaultStore(folder.root.resolve("vault.json").absolutePath, worker)
        finish(launch { store.create(password, password) }, worker)
        finish(launch { store.editor.startNew(null) }, worker)
        store.fill("web-01", "10.0.0.1")

        val saving = launch { store.editor.save() }
        runCurrent()
        store.editor.cancel()
        assertTrue(store.form?.isSaving == true)
        finish(saving, worker)

        assertNull(store.form)
        assertEquals(listOf("web-01"), store.state.value.tree.hosts.map { it.label })
    }

    @Test
    fun aSlowSaveFromBeforeALockDoesNotTouchTheNextForm() = runTest {
        val worker = GatedDispatcher()
        val store = VaultStore(folder.root.resolve("vault.json").absolutePath, worker)
        finish(launch { store.create(password, password) }, worker)
        finish(launch { store.editor.startNew(null) }, worker)
        store.fill("viejo", "10.0.0.1")
        val saving = launch { store.editor.save() }
        runCurrent()

        store.lock()
        finish(launch { store.unlock(password) }, worker)
        finish(launch { store.editor.startNew(null) }, worker)
        store.fill("nuevo", "10.0.0.2")
        finish(saving, worker)

        assertEquals("nuevo", store.form?.draft?.label)
        assertFalse(store.form?.isSaving == true)
        assertNull(store.form?.errorMessage)
    }

    @Test
    fun editingAHostThatIsGoneSaysWhy() = runTest {
        val store = openStore()
        val host = store.addHost("web-01")
        store.editor.startEditing(host)
        store.editor.delete()

        store.editor.startEditing(host)

        assertNull(store.form)
        assertEquals("Ese host ya no está en la bóveda", store.editor.notice.value)
    }

    @Test
    fun teamHostsAreNotEditableHere() = runTest {
        val store = openStore()
        val host = store.addHost("web-01")

        assertTrue(store.editor.canEdit(host))
        assertFalse(store.editor.canEdit(host.copy(team = "Infra")))
    }
}
