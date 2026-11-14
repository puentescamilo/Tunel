package dev.tunel.android.ui

import androidx.compose.runtime.Composable
import dev.tunel.android.core.HostForm
import dev.tunel.android.core.VaultStore
import uniffi.tunel_mobile.HostSummary

/** La terminal abierta, si hay una, y cómo abrir o cerrar una. */
class TerminalCallbacks(
    val screen: TerminalScreenState?,
    val onConnect: (HostSummary) -> Unit,
    val onClose: () -> Unit,
    /** La pantalla de la sesión dejó de mostrarse. */
    val onLeft: (TerminalScreenState) -> Unit,
)

/** Bloqueo o lista de hosts, según el estado de la bóveda. */
@Composable
fun TunelApp(
    state: VaultStore.State,
    onUnlock: (String) -> Unit,
    onCreate: (String, String) -> Unit,
    onLock: () -> Unit,
    account: AccountCallbacks,
    terminal: TerminalCallbacks,
    security: SecurityCallbacks,
    editor: EditorCallbacks,
    form: HostForm?,
    editorNotice: String?,
) {
    when (state.phase) {
        VaultStore.Phase.NEEDS_SETUP, VaultStore.Phase.LOCKED -> LockScreen(
            isCreating = state.phase == VaultStore.Phase.NEEDS_SETUP,
            isWorking = state.isWorking,
            errorMessage = state.errorMessage,
            onUnlock = onUnlock,
            onCreate = onCreate,
            biometric = state.biometric,
            onBiometricUnlock = security.onBiometricUnlock,
        )
        VaultStore.Phase.UNLOCKED -> HostsScreen(state = state, onLock = onLock, account = account, terminal = terminal, security = security, editor = editor, form = form, editorNotice = editorNotice)
    }
}
