package dev.tunel.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import uniffi.tunel_mobile.minPasswordLength

/** Crear la bóveda la primera vez, o desbloquearla con la contraseña maestra. */
@Composable
fun LockScreen(
    isCreating: Boolean,
    isWorking: Boolean,
    errorMessage: String?,
    onUnlock: (String) -> Unit,
    onCreate: (String, String) -> Unit,
) {
    // `remember`, no `rememberSaveable`: la contraseña no se guarda en el estado de la app.
    var password by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    val canSubmit = !isWorking && password.isNotEmpty() && (!isCreating || confirmation.isNotEmpty())

    fun submit() {
        if (!canSubmit) return
        if (isCreating) onCreate(password, confirmation) else onUnlock(password)
        // La contraseña no se queda en la pantalla: ya va camino del núcleo.
        password = ""
        confirmation = ""
    }
    LaunchedEffect(Unit) { focus.requestFocus() }
    // Lo que se dejó escrito sin enviar tampoco se queda al salir de la app.
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) {
        password = ""
        confirmation = ""
    }

    Surface(Modifier.fillMaxSize()) {
        Box(
            Modifier
                .fillMaxSize()
                .imePadding()
                .verticalScroll(rememberScrollState()),
            contentAlignment = Alignment.Center,
        ) {
            Column(
                Modifier
                    .widthIn(max = 420.dp)
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(56.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
                Text(
                    if (isCreating) "Crea tu bóveda" else "Túnel está bloqueado",
                    style = MaterialTheme.typography.headlineSmall,
                )
                Text(
                    if (isCreating) {
                        "La contraseña maestra cifra tus hosts y credenciales en este dispositivo. Si la olvidas, no se puede recuperar."
                    } else {
                        "Escribe tu contraseña maestra."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Contraseña maestra") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = if (isCreating) ImeAction.Next else ImeAction.Go,
                    ),
                    keyboardActions = KeyboardActions(onGo = { submit() }),
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focus),
                )
                if (isCreating) {
                    OutlinedTextField(
                        value = confirmation,
                        onValueChange = { confirmation = it },
                        label = { Text("Repite la contraseña") },
                        supportingText = { Text("Al menos ${minPasswordLength()} caracteres.") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Go,
                        ),
                        keyboardActions = KeyboardActions(onGo = { submit() }),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (errorMessage != null) {
                    Text(
                        errorMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                    )
                }
                Button(
                    onClick = ::submit,
                    enabled = canSubmit,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (isWorking) {
                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    } else {
                        Text(if (isCreating) "Crear bóveda" else "Desbloquear")
                    }
                }
            }
        }
    }
}
