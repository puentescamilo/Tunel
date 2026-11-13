package dev.tunel.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import uniffi.tunel_mobile.HostSummary

/** Los datos de un host. Conectar llega con la terminal. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostDetailScreen(host: HostSummary, onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(host.label) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Atrás")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            Field("Dirección", host.address)
            Field("Puerto", host.port.toString())
            Field("Protocolo", host.protocol)
            host.team?.let { Field("Team", it) }
            if (host.tags.isNotEmpty()) Field("Etiquetas", host.tags.joinToString(" · "))
        }
    }
}

@Composable
private fun Field(name: String, value: String) {
    ListItem(overlineContent = { Text(name) }, headlineContent = { Text(value) })
}
