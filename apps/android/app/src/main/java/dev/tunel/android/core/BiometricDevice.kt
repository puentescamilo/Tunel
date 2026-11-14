package dev.tunel.android.core

/**
 * Dónde guarda la app la clave que abre la bóveda sin contraseña. En el teléfono, cifrada con
 * una clave del almacén de Android que solo se usa tras la huella; en las pruebas, en memoria.
 */
interface BiometricDevice {
    /** Si hay huella (u otra biometría fuerte) configurada. */
    val isAvailable: Boolean

    /** Pide la huella y guarda `key` con el nombre `id`, en lugar de cualquier otra. `false` si se cancela. */
    suspend fun save(id: String, key: ByteArray): Boolean

    /** Pide la huella y devuelve la clave `id`. `null` si se cancela. */
    suspend fun load(id: String): ByteArray?

    /** Si tiene guardada la clave `id` (sin pedir la huella). */
    fun has(id: String): Boolean

    fun removeAll()
}

/** La clave ya no está: se borró, o cambiaron las huellas registradas. */
class BiometricKeyMissing : Exception()

/** La huella falló por otro motivo (demasiados intentos, error del sistema…), con el mensaje del sistema. */
class BiometricFailure(message: String) : Exception(message)

/** Para un dispositivo sin huella, y para las pruebas que no la usan. */
object NoBiometrics : BiometricDevice {
    override val isAvailable = false

    override suspend fun save(id: String, key: ByteArray) = false

    override suspend fun load(id: String): ByteArray? = null

    override fun has(id: String) = false

    override fun removeAll() = Unit
}

/** Lo que la interfaz necesita saber del desbloqueo con huella. */
data class BiometricState(
    /** Abierta y con la huella activada. */
    val enabled: Boolean = false,
    /** Bloqueada, con la huella activada y hoy ya se entró con la contraseña: se puede ofrecer. */
    val ready: Boolean = false,
    /** La huella está activada, pero hoy aún no se entró con la contraseña maestra. */
    val waitsForPassword: Boolean = false,
    /**
     * Al aparecer la pantalla de bloqueo, pedir la huella sin esperar al botón. No tras
     * bloquear a mano: ahí se quiere ver la pantalla bloqueada.
     */
    val promptOnAppear: Boolean = false,
)
