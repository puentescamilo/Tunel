package dev.tunel.android.ui

import androidx.compose.runtime.Composable
import dev.tunel.android.core.VaultStore

/** Bloqueo o lista de hosts, según el estado de la bóveda. */
@Composable
fun TunelApp(
    state: VaultStore.State,
    onUnlock: (String) -> Unit,
    onCreate: (String, String) -> Unit,
    onLock: () -> Unit,
    account: AccountCallbacks,
) {
    when (state.phase) {
        VaultStore.Phase.NEEDS_SETUP, VaultStore.Phase.LOCKED -> LockScreen(
            isCreating = state.phase == VaultStore.Phase.NEEDS_SETUP,
            isWorking = state.isWorking,
            errorMessage = state.errorMessage,
            onUnlock = onUnlock,
            onCreate = onCreate,
        )
        VaultStore.Phase.UNLOCKED -> HostsScreen(state = state, onLock = onLock, account = account)
    }
}
