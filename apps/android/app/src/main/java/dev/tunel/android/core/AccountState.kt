package dev.tunel.android.core

import uniffi.tunel_mobile.SignInOptions

/** Cómo fue la última sincronización, para mostrarlo bajo la lista. */
sealed interface SyncStatus {
    data object Idle : SyncStatus

    data object Syncing : SyncStatus

    data class Synced(
        /** Cuándo terminó, en milisegundos desde 1970. */
        val at: Long,
        /** Teams que no se pudieron recibir, con el motivo. */
        val problems: List<String>,
        /** Invitaciones a Teams pendientes: se aceptan desde el escritorio. */
        val invitations: Int,
    ) : SyncStatus

    data class Failed(val message: String) : SyncStatus
}

/** La pantalla de la cuenta: unirse, ver la cuenta o salir de ella. */
data class SignInState(
    /** Cómo se puede entrar en el servidor escrito; `null` hasta que se pregunta. */
    val options: SignInOptions? = null,
    /** Mientras se habla con el servidor: la interfaz desactiva los botones. */
    val isWorking: Boolean = false,
    val errorMessage: String? = null,
    /** Volvió el navegador de un proveedor con este correo: falta la contraseña maestra. */
    val providerEmail: String? = null,
)
