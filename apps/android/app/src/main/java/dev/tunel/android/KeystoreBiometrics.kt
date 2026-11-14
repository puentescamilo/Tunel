package dev.tunel.android

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.tunel.android.core.BiometricDevice
import dev.tunel.android.core.BiometricFailure
import dev.tunel.android.core.BiometricKeyMissing
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.File
import java.lang.ref.WeakReference
import java.security.KeyStore
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * La clave del desbloqueo con huella, cifrada con una clave AES del almacén de Android que:
 * no sale del hardware, solo se usa tras una huella (biometría fuerte) para cada operación,
 * deja de servir si cambian las huellas registradas y exige el teléfono desbloqueado. Lo
 * cifrado se guarda fuera de las copias de seguridad.
 */
class KeystoreBiometrics(context: Context) : BiometricDevice {
    private val appContext = context.applicationContext
    private val folder = File(appContext.noBackupFilesDir, "biometria")

    /** La ventana sobre la que se muestra el diálogo de la huella. */
    private var activity = WeakReference<FragmentActivity>(null)

    fun attach(activity: FragmentActivity) {
        this.activity = WeakReference(activity)
    }

    override val isAvailable: Boolean
        get() = BiometricManager.from(appContext).canAuthenticate(BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    override suspend fun save(id: String, key: ByteArray): Boolean {
        val cipher = guarded(onKeyError = { BiometricFailure("el almacén de claves no respondió") }) {
            withContext(Dispatchers.IO) {
                removeAll()
                Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, newKey()) }
            }
        }
        val authorized = prompt(cipher, "Activar el desbloqueo con huella") ?: run {
            withContext(Dispatchers.IO) { removeAll() }
            return false
        }
        guarded(onKeyError = { BiometricFailure("no se pudo guardar la clave") }) {
            val sealed = authorized.iv + authorized.doFinal(key)
            withContext(Dispatchers.IO) { writeAtomically(file(id), sealed) }
        }
        return true
    }

    override suspend fun load(id: String): ByteArray? {
        val (sealed, cipher) = guarded(onKeyError = ::forgetAndReportMissing) {
            withContext(Dispatchers.IO) {
                val sealed = file(id).takeIf { it.exists() }?.readBytes()
                    ?.takeIf { it.size > IV_BYTES }
                    ?: throw BiometricKeyMissing()
                val key = keyStore().getKey(ALIAS, null) as? SecretKey ?: throw BiometricKeyMissing()
                // Si se registró o quitó una huella, aquí salta KeyPermanentlyInvalidatedException.
                val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES))
                }
                sealed to cipher
            }
        }
        val authorized = prompt(cipher, "Desbloquear Túnel") ?: return null
        // Un archivo dañado no pasa la etiqueta de GCM: se trata como clave perdida.
        return guarded(onKeyError = ::forgetAndReportMissing) {
            authorized.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
        }
    }

    override fun has(id: String): Boolean = runCatching {
        file(id).exists() && keyStore().containsAlias(ALIAS)
    }.getOrDefault(false)

    override fun removeAll() {
        folder.listFiles()?.forEach { it.delete() }
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    /**
     * Ejecuta `work` convirtiendo los fallos del almacén de claves y del disco en los errores
     * que entiende la app: si no, una clave estropeada tiraría la app al arrancar.
     */
    private inline fun <T> guarded(onKeyError: () -> Exception, work: () -> T): T = try {
        work()
    } catch (error: BiometricKeyMissing) {
        throw error
    } catch (error: BiometricFailure) {
        throw error
    } catch (error: CancellationException) {
        throw error
    } catch (_: GeneralSecurityException) {
        throw onKeyError()
    } catch (_: IOException) {
        throw onKeyError()
    } catch (_: ProviderException) {
        throw onKeyError()
    } catch (_: IllegalStateException) {
        throw onKeyError()
    }

    /** La clave ya no sirve (huellas cambiadas, archivo dañado): se borra y se dice. */
    private fun forgetAndReportMissing(): Exception {
        removeAll()
        return BiometricKeyMissing()
    }

    /** Escribe en un temporal y lo renombra: nunca queda un archivo a medias. */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        folder.mkdirs()
        val temporary = File(folder, "${target.name}.tmp")
        temporary.writeBytes(bytes)
        if (!temporary.renameTo(target)) {
            temporary.delete()
            throw IOException("no se pudo guardar la clave")
        }
    }

    private fun file(id: String): File {
        // El id lo da el núcleo (un UUID); aun así, nada de rutas.
        require(id.matches(Regex("[A-Za-z0-9-]+"))) { "Identificador no válido" }
        return File(folder, id)
    }

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun newKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .apply {
                // Cada uso de la clave pide la huella, no la contraseña del teléfono.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    /** Muestra el diálogo de la huella; devuelve el cifrado ya autorizado, o `null` si se cancela. */
    private suspend fun prompt(cipher: Cipher, title: String): Cipher? = withContext(Dispatchers.Main) {
        val host = activity.get() ?: throw BiometricFailure("la app no está en pantalla")
        suspendCancellableCoroutine { continuation ->
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authorized = result.cryptoObject?.cipher
                    if (authorized != null) {
                        continuation.resume(authorized)
                    } else {
                        continuation.resumeWithException(BiometricFailure("el sistema no autorizó la clave"))
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (code in CANCELLED) {
                        continuation.resume(null)
                    } else {
                        continuation.resumeWithException(BiometricFailure(message.toString()))
                    }
                }
                // Una huella no reconocida: el diálogo deja reintentar solo.
            }
            val prompt = BiometricPrompt(host, ContextCompat.getMainExecutor(host), callback)
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText("Usar la contraseña")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        }
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "tunel-biometria"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_BITS = 256
        const val TAG_BITS = 128
        const val IV_BYTES = 12
        val CANCELLED = setOf(
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED,
        )
    }
}
