package dev.tunel.android.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import uniffi.tunel_mobile.GroupSummary
import uniffi.tunel_mobile.HostDraft
import uniffi.tunel_mobile.HostSummary
import uniffi.tunel_mobile.IdentitySummary
import uniffi.tunel_mobile.TunelException
import uniffi.tunel_mobile.Vault
import uniffi.tunel_mobile.errorMessage

/** Qué credencial usa el host del formulario. */
sealed interface Credential {
    data object None : Credential

    data class Existing(val id: String) : Credential

    /** Una identidad nueva con el usuario y la contraseña del formulario. */
    data object New : Credential
}

/**
 * El formulario abierto para crear o editar un host personal. Lo que se escribe como texto
 * (puerto, etiquetas) se interpreta al guardar.
 */
data class HostForm(
    val draft: HostDraft,
    val port: String,
    val tags: String,
    val credential: Credential,
    /** Identidades y grupos para elegir, leídos al abrir el formulario. */
    val identities: List<IdentitySummary>,
    val groups: List<GroupSummary>,
    val isSaving: Boolean = false,
    val errorMessage: String? = null,
) {
    val isNew: Boolean get() = draft.id == null

    /** El nombre para mostrar: el escrito o, si no, la dirección. */
    val title: String get() = draft.label.ifBlank { draft.address }
}

/**
 * Crear, editar y borrar hosts de la bóveda personal. Los de un Team se editan desde el
 * escritorio. El formulario vive aquí (no en la pantalla) para sobrevivir a los giros; al
 * bloquear se descarta, con la contraseña que tuviera.
 */
class HostEditor internal constructor(
    private val store: VaultStore,
    private val worker: CoroutineDispatcher,
) {
    private val _form = MutableStateFlow<HostForm?>(null)

    /** El formulario abierto, o `null`. */
    val form: StateFlow<HostForm?> = _form.asStateFlow()

    private val _notice = MutableStateFlow<String?>(null)

    /** Por qué no se pudo abrir el formulario (el host ya no está…), para mostrarlo una vez. */
    val notice: StateFlow<String?> = _notice.asStateFlow()

    /**
     * Cada formulario abierto tiene su número: lo que termine de uno anterior (un guardado
     * lento) no toca el que se está escribiendo.
     */
    private var serial = 0L

    /**
     * Solo los hosts personales: los de un Team se editan desde el escritorio. Sin preguntar
     * al núcleo: se llama al pintar, y el núcleo puede estar ocupado guardando.
     */
    fun canEdit(host: HostSummary): Boolean = host.team == null

    /** Abre el formulario de un host nuevo, en `groupId` si es un grupo personal. */
    suspend fun startNew(groupId: String?) {
        // Un grupo de Team no admite hosts personales.
        val personal = groupId?.let { store.state.value.tree.group(it) }?.takeIf { it.team == null }?.id
        open { vault -> vault.newHostDraft(personal) }
    }

    suspend fun startEditing(host: HostSummary) = open { vault -> vault.hostDraft(host.id) }

    fun dismissNotice() {
        _notice.value = null
    }

    /** Un cambio en el formulario. */
    fun edit(change: (HostForm) -> HostForm) {
        _form.update { form -> form?.let { change(it).copy(errorMessage = null) } }
    }

    fun dismissError() = _form.update { it?.copy(errorMessage = null) }

    /** Cierra el formulario sin guardar. No mientras guarda: el cambio ya va camino del núcleo. */
    fun cancel() {
        if (_form.value?.isSaving == true) return
        serial++
        _form.value = null
    }

    /** Guarda el host y cierra el formulario. Devuelve el host guardado, o `null` si no se pudo. */
    suspend fun save(): HostSummary? {
        val form = _form.value?.takeUnless { it.isSaving } ?: return null
        val draft = finalDraft(form) ?: return null
        return write(form) { vault -> vault.saveHost(draft) }
    }

    /** Borra el host del formulario y lo cierra. */
    suspend fun delete(): Boolean {
        val form = _form.value?.takeUnless { it.isSaving } ?: return false
        val id = form.draft.id ?: return false
        return write(form) { vault -> vault.deleteHost(id) } != null
    }

    /** Al bloquear: el formulario (y la contraseña escrita) no se quedan. */
    internal fun forget() {
        serial++
        _form.value = null
        _notice.value = null
    }

    /** Lee el borrador, las identidades y los grupos fuera del hilo principal y abre el formulario. */
    private suspend fun open(read: (Vault) -> HostDraft) {
        val (vault, started) = synchronized(store.guard) {
            store.vault?.let { it to store.generation }
        } ?: return
        val opened = try {
            withContext(worker) {
                val draft = read(vault)
                HostForm(
                    draft = draft,
                    port = draft.port?.toString().orEmpty(),
                    tags = draft.tags.joinToString(", "),
                    credential = draft.identityId?.let { Credential.Existing(it) } ?: Credential.None,
                    identities = vault.identities(),
                    groups = vault.groups().filter { it.team == null },
                )
            }
        } catch (error: TunelException) {
            _notice.value = errorMessage(error)
            return
        } catch (error: CancellationException) {
            throw error
        } catch (_: IllegalStateException) {
            // Se bloqueó mientras tanto.
            return
        }
        synchronized(store.guard) {
            if (store.generation != started) return
            serial++
            _form.value = opened
        }
    }

    /** El borrador listo para el núcleo, o `null` (con el motivo) si algo no vale. */
    private fun finalDraft(form: HostForm): HostDraft? {
        val portText = form.port.trim()
        val port = when {
            portText.isEmpty() -> null
            else -> portText.toIntOrNull()?.takeIf { it in 1..MAX_PORT }?.toUShort()
                ?: return fail("El puerto tiene que estar entre 1 y 65535")
        }
        val draft = form.draft.copy(
            port = port,
            tags = form.tags.split(',').map { it.trim() }.filter { it.isNotEmpty() },
        )
        return when (val credential = form.credential) {
            Credential.None -> draft.copy(identityId = null, newUsername = "", newPassword = "")
            is Credential.Existing -> draft.copy(identityId = credential.id, newUsername = "", newPassword = "")
            Credential.New -> {
                if (draft.newUsername.isBlank()) return fail("Escribe el usuario de la credencial nueva")
                draft.copy(identityId = null)
            }
        }
    }

    private fun fail(message: String): HostDraft? {
        _form.update { it?.copy(errorMessage = message) }
        return null
    }

    /**
     * Ejecuta el cambio en el núcleo, recarga la lista y cierra el formulario. Los errores
     * del núcleo (`InvalidHost` con el motivo, `TeamHostReadOnly`…) se quedan en el formulario.
     */
    private suspend fun <T : Any> write(form: HostForm, change: (Vault) -> T): T? {
        val (vault, started, mine) = synchronized(store.guard) {
            val open = store.vault ?: return null
            // Bajo `guard`: un bloqueo no puede colarse y dejar el formulario publicado.
            _form.value = form.copy(isSaving = true, errorMessage = null)
            Triple(open, store.generation, serial)
        }
        /** Solo si sigue abierto este formulario. */
        fun updateMine(change: (HostForm) -> HostForm?) = synchronized(store.guard) {
            if (serial == mine) _form.update { it?.let(change) }
        }
        return try {
            val result = withContext(worker) { change(vault) }
            val (tree, account) = store.snapshot(vault)
            if (store.publish(started) { it.copy(tree = tree, account = account) }) {
                updateMine { null }
            }
            result
        } catch (error: CancellationException) {
            throw error
        } catch (error: TunelException) {
            updateMine { it.copy(isSaving = false, errorMessage = errorMessage(error)) }
            null
        } catch (error: IllegalStateException) {
            // Se bloqueó mientras guardaba: el formulario ya se descartó.
            if (store.vault !== vault) return null
            updateMine { it.copy(isSaving = false, errorMessage = UNEXPECTED) }
            null
        } catch (error: Exception) {
            // Un fallo inesperado del núcleo: se dice, no se tira la app.
            updateMine { it.copy(isSaving = false, errorMessage = UNEXPECTED) }
            null
        } finally {
            updateMine { if (it.isSaving) it.copy(isSaving = false) else it }
        }
    }

    private companion object {
        const val MAX_PORT = 65_535
        const val UNEXPECTED = "Algo falló al guardar. Inténtalo de nuevo."
    }
}
