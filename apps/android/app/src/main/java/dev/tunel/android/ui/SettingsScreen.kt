package dev.tunel.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.tunel.android.core.BiometricState
import dev.tunel.android.core.VaultStore
import uniffi.tunel_mobile.coreVersion

/** El desbloqueo con huella y lo que hay que saber del bloqueo. */
class SecurityCallbacks(
    /** Si el teléfono tiene huella configurada. */
    val biometricAvailable: () -> Boolean,
    val onBiometricUnlock: () -> Unit,
    val onSetBiometric: (Boolean) -> Unit,
)

/** Seguridad del dispositivo y versión. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    biometric: BiometricState,
    isWorking: Boolean,
    errorMessage: String?,
    security: SecurityCallbacks,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Ajustes") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Volver")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState())) {
            SectionTitle("Seguridad")
            if (security.biometricAvailable()) {
                ListItem(
                    headlineContent = { Text("Desbloquear con huella") },
                    trailingContent = {
                        Switch(
                            checked = biometric.enabled,
                            onCheckedChange = security.onSetBiometric,
                            enabled = !isWorking,
                        )
                    },
                )
            } else {
                ListItem(
                    headlineContent = {
                        Text("Registra una huella en los ajustes del teléfono para abrir la bóveda sin contraseña.")
                    },
                )
            }
            errorMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(horizontal = 16.dp))
            }
            Text(
                "La primera vez de cada día se pide la contraseña maestra, para no olvidarla. " +
                    "La bóveda se bloquea si sales de Túnel más de " +
                    "${VaultStore.BACKGROUND_GRACE_MS / 60_000} minutos.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
            HorizontalDivider()
            SectionTitle("Acerca de")
            ListItem(overlineContent = { Text("Versión") }, headlineContent = { Text(coreVersion()) })
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}
