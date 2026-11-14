package dev.tunel.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import dev.tunel.android.core.Credential
import dev.tunel.android.core.HostForm
import uniffi.tunel_mobile.HostSummary

/** Lo que puede hacer el formulario de un host; lo resuelve el ViewModel. */
class EditorCallbacks(
    val onStartNew: (groupId: String?) -> Unit,
    val onStartEditing: (HostSummary) -> Unit,
    val canEdit: (HostSummary) -> Boolean,
    val onEdit: ((HostForm) -> HostForm) -> Unit,
    val onSave: () -> Unit,
    val onDelete: () -> Unit,
    val onCancel: () -> Unit,
    val onDismissError: () -> Unit,
    val onDismissNotice: () -> Unit,
)

private val PROTOCOLS = listOf("SSH", "Mosh", "Telnet")

/** El formulario para crear o editar un host personal. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostEditorScreen(form: HostForm, hosts: List<HostSummary>, callbacks: EditorCallbacks) {
    var confirmingDelete by remember { mutableStateOf(false) }
    val edit = callbacks.onEdit

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (form.isNew) "Nuevo host" else "Editar host") },
                navigationIcon = {
                    IconButton(onClick = callbacks.onCancel, enabled = !form.isSaving) {
                        Icon(Icons.Filled.Close, contentDescription = "Cancelar")
                    }
                },
                actions = {
                    if (form.isSaving) {
                        CircularProgressIndicator(Modifier.padding(end = 16.dp).size(24.dp), strokeWidth = 2.dp)
                    } else {
                        TextButton(
                            onClick = callbacks.onSave,
                            enabled = form.draft.address.isNotBlank(),
                        ) { Text("Guardar") }
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .imePadding()
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            General(form, edit)
            HorizontalDivider()
            Credentials(form, edit)
            HorizontalDivider()
            GroupPicker(form, edit)
            HorizontalDivider()
            JumpHosts(form, hosts, edit)
            HorizontalDivider()
            OutlinedTextField(
                value = form.tags,
                onValueChange = { text -> edit { it.copy(tags = text) } },
                label = { Text("Etiquetas") },
                placeholder = { Text("prod, web") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = form.draft.notes,
                onValueChange = { text -> edit { it.copy(draft = it.draft.copy(notes = text)) } },
                label = { Text("Notas") },
                minLines = 3,
                modifier = Modifier.fillMaxWidth(),
            )
            if (!form.isNew) {
                OutlinedButton(
                    onClick = { confirmingDelete = true },
                    enabled = !form.isSaving,
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                    Text("  Borrar host", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }

    form.errorMessage?.let { message ->
        AlertDialog(
            onDismissRequest = callbacks.onDismissError,
            title = { Text("No se pudo guardar") },
            text = { Text(message) },
            confirmButton = { TextButton(onClick = callbacks.onDismissError) { Text("Aceptar") } },
        )
    }
    if (confirmingDelete) {
        AlertDialog(
            onDismissRequest = { confirmingDelete = false },
            title = { Text("¿Borrar «${form.title}»?") },
            text = { Text("Se borra también de tus otros equipos. Los hosts que saltaban por él dejan de hacerlo.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmingDelete = false
                    callbacks.onDelete()
                }) { Text("Borrar", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmingDelete = false }) { Text("Cancelar") } },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun General(form: HostForm, edit: ((HostForm) -> HostForm) -> Unit) {
    OutlinedTextField(
        value = form.draft.label,
        onValueChange = { text -> edit { it.copy(draft = it.draft.copy(label = text)) } },
        label = { Text("Nombre") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = form.draft.address,
        onValueChange = { text -> edit { it.copy(draft = it.draft.copy(address = text)) } },
        label = { Text("Dirección (nombre o IP)") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = form.port,
        onValueChange = { text -> edit { it.copy(port = text.filter(Char::isDigit).take(5)) } },
        label = { Text("Puerto (opcional)") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
        PROTOCOLS.forEachIndexed { index, name ->
            SegmentedButton(
                selected = form.draft.protocol == name,
                onClick = { edit { it.copy(draft = it.draft.copy(protocol = name)) } },
                shape = SegmentedButtonDefaults.itemShape(index, PROTOCOLS.size),
            ) { Text(name) }
        }
    }
}

@Composable
private fun Credentials(form: HostForm, edit: ((HostForm) -> HostForm) -> Unit) {
    val options = buildList {
        add(Credential.None to "Ninguna")
        form.identities.forEach { identity ->
            val name = if (identity.username.isEmpty()) identity.label else "${identity.label} (${identity.username})"
            add(Credential.Existing(identity.id) to name)
        }
        add(Credential.New to "Nueva…")
    }
    Picker(
        label = "Credencial",
        selected = options.firstOrNull { it.first == form.credential }?.second ?: "Ninguna",
        options = options,
        onSelect = { credential -> edit { it.copy(credential = credential) } },
    )
    if (form.credential == Credential.New) {
        OutlinedTextField(
            value = form.draft.newUsername,
            onValueChange = { text -> edit { it.copy(draft = it.draft.copy(newUsername = text)) } },
            label = { Text("Usuario") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = form.draft.newPassword,
            onValueChange = { text -> edit { it.copy(draft = it.draft.copy(newPassword = text)) } },
            label = { Text("Contraseña (opcional)") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "Se guarda como una identidad nueva. Las claves SSH se añaden desde el escritorio.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun GroupPicker(form: HostForm, edit: ((HostForm) -> HostForm) -> Unit) {
    val options = listOf<String?>(null).plus(form.groups.map { it.id }).map { id ->
        id to (form.groups.firstOrNull { it.id == id }?.name ?: "Sin grupo")
    }
    Picker(
        label = "Grupo",
        selected = options.firstOrNull { it.first == form.draft.groupId }?.second ?: "Sin grupo",
        options = options,
        onSelect = { id -> edit { it.copy(draft = it.draft.copy(groupId = id)) } },
    )
}

/** Los jump hosts, en orden de salto: se añaden desde un menú, se suben o se quitan. */
@Composable
private fun JumpHosts(form: HostForm, hosts: List<HostSummary>, edit: ((HostForm) -> HostForm) -> Unit) {
    val selected = form.draft.jumpHostIds
    val candidates = hosts.filter { host ->
        host.id != form.draft.id && host.id !in selected && (host.protocol == "SSH" || host.protocol == "Mosh")
    }
    Text("Saltar a través de", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
    selected.forEachIndexed { index, id ->
        ListItem(
            headlineContent = { Text(hosts.firstOrNull { it.id == id }?.label ?: "Host borrado") },
            leadingContent = { Text("${index + 1}.") },
            trailingContent = {
                androidx.compose.foundation.layout.Row {
                    if (index > 0) {
                        IconButton(onClick = { edit { it.withJumps(it.draft.jumpHostIds.moveUp(id)) } }) {
                            Icon(Icons.Filled.KeyboardArrowUp, contentDescription = "Saltar antes")
                        }
                    }
                    IconButton(onClick = { edit { it.withJumps(it.draft.jumpHostIds - id) } }) {
                        Icon(Icons.Filled.Close, contentDescription = "Quitar")
                    }
                }
            },
        )
    }
    if (candidates.isNotEmpty()) {
        Picker(
            label = "Añadir salto",
            selected = "",
            options = candidates.map { it.id to it.label },
            onSelect = { id -> edit { it.withJumps((it.draft.jumpHostIds - id) + id) } },
        )
    }
    Text(
        if (selected.isEmpty()) {
            "Para llegar a un servidor que solo es accesible desde otro (ProxyJump)."
        } else {
            "Se salta en este orden."
        },
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private fun HostForm.withJumps(ids: List<String>) = copy(draft = draft.copy(jumpHostIds = ids))

/** `id` un puesto antes (sobre la lista de ese momento, no la que se pintó). */
internal fun List<String>.moveUp(id: String): List<String> {
    val index = indexOf(id)
    if (index <= 0) return this
    return toMutableList().apply { add(index - 1, removeAt(index)) }
}

/** Un desplegable de solo lectura con las opciones. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun <T> Picker(label: String, selected: String, options: List<Pair<T, String>>, onSelect: (T) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = selected,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { (value, name) ->
                DropdownMenuItem(
                    text = { Text(name) },
                    onClick = {
                        expanded = false
                        onSelect(value)
                    },
                )
            }
        }
    }
}
