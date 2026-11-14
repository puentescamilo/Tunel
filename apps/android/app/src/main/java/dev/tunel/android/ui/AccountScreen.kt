package dev.tunel.android.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.Lifecycle
import dev.tunel.android.core.SignInState
import dev.tunel.android.core.SyncStatus
import uniffi.tunel_mobile.AccountInfo
import uniffi.tunel_mobile.SignInOptions

/** Lo que puede hacer la pantalla de la cuenta; lo resuelve la actividad. */
class AccountCallbacks(
    val lastServer: () -> String,
    val onLoadOptions: (server: String) -> Unit,
    val onForgetOptions: () -> Unit,
    val onSignIn: (server: String, email: String, password: String) -> Unit,
    val onProvider: (server: String, providerId: String) -> Unit,
    val onFinishProvider: (masterPassword: String) -> Unit,
    val onCancelProvider: () -> Unit,
    val onSync: () -> Unit,
    val onSignOut: () -> Unit,
)

/** Unir el dispositivo a la cuenta de Túnel, o ver con qué cuenta está unido. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountScreen(
    account: AccountInfo?,
    sync: SyncStatus,
    signIn: SignInState,
    callbacks: AccountCallbacks,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Cuenta de Túnel") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Volver")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (account != null) {
                AccountDetail(account, sync, signIn, callbacks)
            } else {
                SignInForm(signIn, callbacks)
            }
            if (signIn.isWorking) Working()
            signIn.errorMessage?.let { ErrorText(it) }
        }
    }
}

@Composable
private fun AccountDetail(
    account: AccountInfo,
    sync: SyncStatus,
    signIn: SignInState,
    callbacks: AccountCallbacks,
) {
    var confirmingSignOut by remember { mutableStateOf(false) }

    ListItem(headlineContent = { Text(account.email) }, overlineContent = { Text("Correo") })
    ListItem(headlineContent = { Text(account.server) }, overlineContent = { Text("Servidor") })
    ListItem(
        headlineContent = { Text(account.providerName ?: "Contraseña") },
        overlineContent = { Text("Entra con") },
    )
    HorizontalDivider()
    SectionTitle("Sincronización")
    SyncStatusText(sync)
    OutlinedButton(onClick = callbacks.onSync, enabled = sync != SyncStatus.Syncing) {
        Text("Sincronizar ahora")
    }
    if (account.teams.isNotEmpty()) {
        HorizontalDivider()
        SectionTitle("Teams")
        account.teams.forEach { Text(it) }
    }
    HorizontalDivider()
    // No mientras sincroniza: lo que trajera llegaría a una cuenta que ya no está.
    TextButton(
        onClick = { confirmingSignOut = true },
        enabled = !signIn.isWorking && sync != SyncStatus.Syncing,
    ) {
        Text("Salir de la cuenta", color = MaterialTheme.colorScheme.error)
    }
    Hint("Se borran de este dispositivo los hosts y credenciales de la cuenta. En tus otros equipos no cambia nada.")

    if (confirmingSignOut) {
        AlertDialog(
            onDismissRequest = { confirmingSignOut = false },
            title = { Text("¿Salir de la cuenta en este dispositivo?") },
            text = { Text("Se borra lo descargado de la cuenta.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmingSignOut = false
                    callbacks.onSignOut()
                }) { Text("Salir y borrar lo descargado", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmingSignOut = false }) { Text("Cancelar") }
            },
        )
    }
}

/** Cómo fue la última sincronización; también se muestra sobre la lista de hosts. */
@Composable
fun SyncStatusText(status: SyncStatus, modifier: Modifier = Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        when (status) {
            SyncStatus.Idle -> Hint("Sin sincronizar todavía")
            SyncStatus.Syncing -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                Text("  Sincronizando…", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            is SyncStatus.Synced -> {
                val now = System.currentTimeMillis()
                val ago = if (now - status.at < DateUtils.MINUTE_IN_MILLIS) {
                    "ahora mismo"
                } else {
                    DateUtils.getRelativeTimeSpanString(status.at, now, DateUtils.MINUTE_IN_MILLIS)
                }
                Hint("Sincronizado $ago")
                status.problems.forEach { Warning(it) }
                when (status.invitations) {
                    0 -> Unit
                    1 -> Hint("Tienes una invitación a un Team: acéptala desde Túnel en el escritorio.")
                    else -> Hint("Tienes ${status.invitations} invitaciones a Teams: acéptalas desde Túnel en el escritorio.")
                }
            }
            is SyncStatus.Failed -> Warning(status.message)
        }
    }
}

@Composable
private fun SignInForm(signIn: SignInState, callbacks: AccountCallbacks) {
    val email = signIn.providerEmail
    if (email != null) {
        MasterPasswordForm(email, signIn.isWorking, callbacks)
        return
    }
    // El servidor no es secreto: se guarda para la próxima vez.
    var server by rememberSaveable { mutableStateOf(callbacks.lastServer()) }
    OutlinedTextField(
        value = server,
        onValueChange = {
            server = it
            if (signIn.options != null) callbacks.onForgetOptions()
        },
        label = { Text("Servidor") },
        placeholder = { Text("https://tunel.ejemplo.com") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth(),
    )
    Hint("El mismo que tienes en Túnel en el escritorio, en Ajustes → Sincronización.")
    val options = signIn.options
    if (options == null) {
        Button(
            onClick = { callbacks.onLoadOptions(server) },
            enabled = server.isNotBlank() && !signIn.isWorking,
        ) { Text("Continuar") }
    } else {
        ProviderButtons(options, server, signIn.isWorking, callbacks)
        if (options.passwordLogin) PasswordForm(server, signIn.isWorking, callbacks)
    }
}

@Composable
private fun ProviderButtons(
    options: SignInOptions,
    server: String,
    isWorking: Boolean,
    callbacks: AccountCallbacks,
) {
    options.providers.forEach { provider ->
        Button(
            onClick = { callbacks.onProvider(server, provider.id) },
            enabled = !isWorking,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Entrar con ${provider.name}") }
    }
}

@Composable
private fun PasswordForm(server: String, isWorking: Boolean, callbacks: AccountCallbacks) {
    var email by rememberSaveable { mutableStateOf("") }
    // `remember`: la contraseña no va al estado que Android guarda, y se borra al salir.
    var password by remember { mutableStateOf("") }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { password = "" }

    HorizontalDivider()
    SectionTitle("Con correo y contraseña")
    OutlinedTextField(
        value = email,
        onValueChange = { email = it },
        label = { Text("Correo") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth(),
    )
    PasswordField(password, { password = it }, "Contraseña de la cuenta")
    Button(
        onClick = {
            callbacks.onSignIn(server, email, password)
            password = ""
        },
        enabled = email.isNotBlank() && password.isNotEmpty() && !isWorking,
    ) { Text("Entrar") }
}

@Composable
private fun MasterPasswordForm(email: String, isWorking: Boolean, callbacks: AccountCallbacks) {
    var password by remember { mutableStateOf("") }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { password = "" }

    SectionTitle(email)
    PasswordField(password, { password = it }, "Contraseña maestra")
    Hint("La contraseña maestra de tu cuenta de Túnel, la misma que usas en el escritorio. Con ella se descifran tus datos en este dispositivo; el servidor no la conoce.")
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = {
                callbacks.onFinishProvider(password)
                password = ""
            },
            enabled = password.isNotEmpty() && !isWorking,
        ) { Text("Unir este dispositivo") }
        TextButton(
            onClick = {
                password = ""
                callbacks.onCancelProvider()
            },
            enabled = !isWorking,
        ) { Text("Cancelar") }
    }
}

@Composable
private fun PasswordField(value: String, onChange: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun Working() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        Text("  Un momento…", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
}

@Composable
private fun Hint(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun Warning(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.Warning,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.tertiary,
            modifier = Modifier.size(16.dp),
        )
        Text("  $text", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ErrorText(text: String) {
    Text(text, color = MaterialTheme.colorScheme.error)
}
