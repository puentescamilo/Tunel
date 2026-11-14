package dev.tunel.android.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.tunel.android.core.TerminalModel
import dev.tunel.android.core.TerminalPhase
import dev.tunel.android.core.TerminalState
import dev.tunel.android.core.endpoint
import org.connectbot.terminal.ModifierManager
import org.connectbot.terminal.Terminal
import org.connectbot.terminal.TerminalEmulator
import org.connectbot.terminal.TerminalEmulatorFactory
import org.connectbot.terminal.VTermKey
import uniffi.tunel_mobile.HostKeyQuestion
import uniffi.tunel_mobile.LoginQuestion

/** El Ctrl en la máscara de modificadores de libvterm (Shift 1, Alt 2, Ctrl 4). */
private const val MODIFIER_CTRL = 4

private val TerminalBackground = Color(0xFF0E1413)
private val TerminalForeground = Color(0xFFE3EAE8)

/**
 * Lo que la pantalla de una sesión necesita y debe sobrevivir a un giro: la terminal con lo
 * que ya se ve y el Ctrl de la barra de teclas. Lo guarda el ViewModel.
 */
class TerminalScreenState(val model: TerminalModel) : AutoCloseable {
    /** El Ctrl de la barra: vale para la siguiente tecla, sea de la barra o del teclado. */
    var ctrl by mutableStateOf(false)
        private set

    val modifiers = object : ModifierManager {
        override fun isCtrlActive() = ctrl

        override fun isAltActive() = false

        override fun isShiftActive() = false

        override fun clearTransients() {
            ctrl = false
        }
    }

    val emulator: TerminalEmulator = TerminalEmulatorFactory.create(
        defaultForeground = TerminalForeground,
        defaultBackground = TerminalBackground,
        onKeyboardInput = model::send,
        onResize = { model.resize(it.columns, it.rows) },
    )

    init {
        model.onOutput = { emulator.writeInput(it) }
    }

    fun toggleCtrl() {
        ctrl = !ctrl
    }

    /** Una tecla de la barra, con el Ctrl si está puesto. */
    fun press(key: Int) {
        val mask = if (ctrl) MODIFIER_CTRL else 0
        emulator.dispatchKey(mask, key)
        ctrl = false
    }

    override fun close() {
        model.onOutput = null
        emulator.close()
    }
}

/** La terminal de un host, con una barra de teclas que el teclado del teléfono no tiene. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TerminalScreen(screen: TerminalScreenState, onBack: () -> Unit) {
    val model = screen.model
    val state by model.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    LaunchedEffect(model) { model.start() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(model.host.label) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Cerrar la sesión")
                    }
                },
                actions = {
                    if (state.phase is TerminalPhase.Closed) {
                        IconButton(onClick = model::connect) {
                            Icon(Icons.Filled.Refresh, contentDescription = "Reconectar")
                        }
                    }
                },
            )
        },
        containerColor = TerminalBackground,
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .consumeWindowInsets(padding)
                .imePadding()
                .fillMaxSize(),
        ) {
            Box(Modifier.weight(1f).fillMaxWidth()) {
                Terminal(
                    terminalEmulator = screen.emulator,
                    modifier = Modifier.fillMaxSize(),
                    initialFontSize = 13.sp,
                    backgroundColor = TerminalBackground,
                    foregroundColor = TerminalForeground,
                    keyboardEnabled = true,
                    showSoftKeyboard = true,
                    modifierManager = screen.modifiers,
                    // Solo enlaces web: un servidor no debe poder abrir otras apps.
                    onHyperlinkClick = { link -> openWebLink(context, link) },
                )
                StatusOverlay(state, model, Modifier.align(Alignment.Center))
            }
            KeyBar(screen)
        }
    }

    state.hostKey?.let { HostKeyDialog(it, model::answerHostKey) }
    state.login?.let { question -> LoginDialog(question) { model.answerLogin(it) } }
}

/** Esc, Ctrl, Tab y flechas: lo que falta en el teclado del teléfono. */
@Composable
private fun KeyBar(screen: TerminalScreenState) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        BarKey("Esc") { screen.press(VTermKey.ESCAPE) }
        FilterChip(
            selected = screen.ctrl,
            onClick = screen::toggleCtrl,
            label = { Text("Ctrl") },
        )
        BarKey("Tab") { screen.press(VTermKey.TAB) }
        BarKey("←") { screen.press(VTermKey.LEFT) }
        BarKey("↓") { screen.press(VTermKey.DOWN) }
        BarKey("↑") { screen.press(VTermKey.UP) }
        BarKey("→") { screen.press(VTermKey.RIGHT) }
    }
}

@Composable
private fun BarKey(label: String, onClick: () -> Unit) {
    TextButton(onClick = onClick) { Text(label, style = MaterialTheme.typography.titleMedium) }
}

/** Mientras conecta o cuando la sesión terminó, encima de la terminal. */
@Composable
private fun StatusOverlay(state: TerminalState, model: TerminalModel, modifier: Modifier) {
    val phase = state.phase
    val waitingForAnswer = state.hostKey != null || state.login != null
    if (phase is TerminalPhase.Connected || (phase is TerminalPhase.Connecting && waitingForAnswer)) return
    Surface(
        modifier = modifier.padding(24.dp),
        shape = RoundedCornerShape(12.dp),
        tonalElevation = 6.dp,
    ) {
        Column(
            Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (phase) {
                TerminalPhase.Connecting -> {
                    CircularProgressIndicator()
                    Text("Conectando con ${model.host.endpoint}…")
                }
                is TerminalPhase.Closed -> {
                    Text(phase.error ?: "Sesión cerrada", textAlign = TextAlign.Center)
                    Button(onClick = model::connect) { Text("Reconectar") }
                }
                TerminalPhase.Connected -> Unit
            }
        }
    }
}

@Composable
private fun HostKeyDialog(question: HostKeyQuestion, answer: (Boolean) -> Unit) {
    val changed = question.expected != null
    AlertDialog(
        // Cerrar sin elegir equivale a cancelar.
        onDismissRequest = { answer(false) },
        title = { Text(if (changed) "La clave del servidor ha cambiado" else "Primera conexión a este servidor") },
        text = { Text(hostKeyMessage(question)) },
        confirmButton = {
            TextButton(onClick = { answer(true) }) {
                Text(
                    if (changed) "Aceptar la clave nueva" else "Confiar y conectar",
                    color = if (changed) MaterialTheme.colorScheme.error else Color.Unspecified,
                )
            }
        },
        dismissButton = { TextButton(onClick = { answer(false) }) { Text("Cancelar") } },
    )
}

internal fun hostKeyMessage(question: HostKeyQuestion): String {
    val endpoint = if (question.port.toInt() == 22) question.host else "${question.host}:${question.port}"
    val presented = "$endpoint\n${question.algorithm}\n${question.fingerprint}"
    val expected = question.expected
        ?: return "Comprueba que la huella es la del servidor antes de confiar en ella.\n\n$presented"
    return "Alguien podría estar interceptando la conexión. Acepta solo si sabes que el servidor " +
        "se reinstaló o cambió de clave.\n\n$presented\n\nAntes:\n$expected"
}

/** El servidor pide datos para entrar: una casilla por pregunta. */
@Composable
private fun LoginDialog(question: LoginQuestion, answer: (List<String>?) -> Unit) {
    // `remember`: lo escrito (contraseñas, códigos) no va al estado que Android guarda.
    val answers = remember(question) { mutableStateListOf(*Array(question.prompts.size) { "" }) }
    AlertDialog(
        onDismissRequest = { answer(null) },
        title = { Text("Iniciar sesión") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(question.host, style = MaterialTheme.typography.labelLarge)
                if (question.instructions.isNotEmpty()) Text(question.instructions)
                question.prompts.forEachIndexed { index, prompt ->
                    OutlinedTextField(
                        value = answers[index],
                        onValueChange = { answers[index] = it },
                        label = { Text(prompt.text) },
                        singleLine = true,
                        visualTransformation = if (prompt.echo) {
                            androidx.compose.ui.text.input.VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = if (prompt.echo) KeyboardType.Text else KeyboardType.Password,
                            autoCorrectEnabled = false,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = { answer(answers.toList()) }) { Text("Entrar") } },
        dismissButton = { TextButton(onClick = { answer(null) }) { Text("Cancelar") } },
    )
}

private fun openWebLink(context: android.content.Context, link: String) {
    val uri = Uri.parse(link)
    if (uri.scheme?.lowercase() !in setOf("http", "https")) return
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, uri))
    } catch (_: ActivityNotFoundException) {
        // Sin navegador, el enlace no se abre.
    }
}
