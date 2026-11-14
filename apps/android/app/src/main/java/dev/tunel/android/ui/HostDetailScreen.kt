package dev.tunel.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.tunel_mobile.HostSummary

/** Lo que la terminal del móvil puede abrir; Mosh se abre por SSH. */
internal val HostSummary.canConnect: Boolean
    get() = protocol == "SSH" || protocol == "Mosh"

/** Los datos de un host y el botón para abrir su terminal. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostDetailScreen(
    host: HostSummary,
    onBack: () -> Unit,
    onConnect: () -> Unit,
    /** `null` si no se puede editar aquí (un host de Team). */
    onEdit: (() -> Unit)?,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(host.label) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Atrás")
                    }
                },
                actions = {
                    if (onEdit != null) {
                        IconButton(onClick = onEdit) {
                            Icon(Icons.Filled.Edit, contentDescription = "Editar")
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            Button(
                onClick = onConnect,
                enabled = host.canConnect,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                Text("  Conectar")
            }
            if (!host.canConnect) {
                Text(
                    "Los hosts ${host.protocol} todavía no se pueden abrir en este dispositivo.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            Field("Dirección", host.address)
            Field("Puerto", host.port.toString())
            Field("Protocolo", host.protocol)
            host.team?.let {
                Field("Team", it)
                Text(
                    "Los hosts de un Team se editan desde Túnel en el escritorio.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            if (host.tags.isNotEmpty()) Field("Etiquetas", host.tags.joinToString(" · "))
        }
    }
}

@Composable
private fun Field(name: String, value: String) {
    ListItem(overlineContent = { Text(name) }, headlineContent = { Text(value) })
}
