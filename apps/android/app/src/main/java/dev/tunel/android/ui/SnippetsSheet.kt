package dev.tunel.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.tunel.android.core.TerminalModel
import uniffi.tunel_mobile.SnippetSummary
import uniffi.tunel_mobile.snippetPreview

/** Elegir un snippet y enviarlo a la terminal. Si tiene variables, primero pide sus valores. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SnippetsSheet(model: TerminalModel, onDismiss: () -> Unit) {
    var chosen by remember { mutableStateOf<SnippetSummary?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(Modifier.padding(horizontal = 16.dp).padding(bottom = 16.dp)) {
            val snippet = chosen
            if (snippet == null) {
                SnippetList(model, error) { picked ->
                    if (picked.variables.isNotEmpty()) {
                        chosen = picked
                    } else {
                        model.run(picked).fold({ onDismiss() }, { error = it.message })
                    }
                }
            } else {
                VariablesForm(model, snippet, onBack = { chosen = null }, onSent = onDismiss)
            }
        }
    }
}

@Composable
private fun SnippetList(model: TerminalModel, error: String?, onPick: (SnippetSummary) -> Unit) {
    var query by remember { mutableStateOf("") }
    val snippets = remember(query) { model.snippets(query) }
    Text("Snippets", style = MaterialTheme.typography.titleLarge)
    OutlinedTextField(
        value = query,
        onValueChange = { query = it },
        placeholder = { Text("Buscar por nombre, comando o etiqueta") },
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { query = "" }) {
                    Icon(Icons.Filled.Clear, contentDescription = "Borrar la búsqueda")
                }
            }
        },
        singleLine = true,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
    )
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    if (snippets.isEmpty()) {
        Text(
            if (query.isEmpty()) {
                "Sin snippets. Los que crees en Túnel del escritorio llegan aquí al sincronizar."
            } else {
                "Ningún snippet coincide con «$query»."
            },
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(vertical = 24.dp),
        )
        return
    }
    LazyColumn(Modifier.heightIn(max = 480.dp)) {
        items(snippets, key = { it.id }) { snippet ->
            SnippetRow(snippet) { onPick(snippet) }
            HorizontalDivider()
        }
    }
}

@Composable
private fun SnippetRow(snippet: SnippetSummary, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                snippet.label,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f),
            )
            val badges = listOfNotNull(
                "Team".takeIf { snippet.team != null },
                "{ }".takeIf { snippet.variables.isNotEmpty() },
            )
            if (badges.isNotEmpty()) {
                Text(
                    badges.joinToString("  "),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(
            snippet.script,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** Una casilla por variable, con el último valor usado, y el comando tal como se enviará. */
@Composable
private fun VariablesForm(
    model: TerminalModel,
    snippet: SnippetSummary,
    onBack: () -> Unit,
    onSent: () -> Unit,
) {
    var error by remember { mutableStateOf<String?>(null) }
    val names = remember(snippet) { mutableStateListOf<String>() }
    val values = remember(snippet) { mutableStateListOf<String>() }
    val focus = remember { FocusRequester() }
    LaunchedEffect(snippet) {
        model.variables(snippet).fold(
            { variables ->
                names.addAll(variables.map { it.name })
                values.addAll(variables.map { it.value })
            },
            { error = it.message },
        )
    }
    val written = names.zip(values).toMap()
    val send = { model.run(snippet, written).fold({ onSent() }, { error = it.message }) }

    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Volver a la lista")
        }
        Text(snippet.label, style = MaterialTheme.typography.titleLarge)
    }
    names.forEachIndexed { index, name ->
        val last = index == names.lastIndex
        OutlinedTextField(
            value = values[index],
            onValueChange = { values[index] = it },
            label = { Text(name) },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(
                autoCorrectEnabled = false,
                imeAction = if (last) ImeAction.Send else ImeAction.Next,
            ),
            keyboardActions = KeyboardActions(onSend = { send() }),
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
                .let { if (index == 0) it.focusRequester(focus) else it },
        )
    }
    if (names.isNotEmpty()) LaunchedEffect(Unit) { focus.requestFocus() }
    Text(
        "Se enviará",
        style = MaterialTheme.typography.labelLarge,
        modifier = Modifier.padding(top = 12.dp),
    )
    Text(
        snippetPreview(snippet.script, written),
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace,
        modifier = Modifier.padding(vertical = 4.dp),
    )
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    Button(onClick = { send() }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        Text("Enviar")
    }
}
