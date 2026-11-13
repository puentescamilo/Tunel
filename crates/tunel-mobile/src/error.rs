//! Errores que ven las apps, con el mensaje listo para mostrar.

use tunel_core::StoreError;
use tunel_core::crypto::CryptoError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TunelError {
    #[error("Contraseña maestra incorrecta")]
    WrongPassword,
    #[error("La contraseña maestra debe tener al menos {min} caracteres")]
    WeakPassword { min: u32 },
    #[error("Ya hay una bóveda en este dispositivo")]
    AlreadyExists,
    #[error("La bóveda ya está abierta")]
    Locked,
    #[error("El archivo de la bóveda está dañado")]
    Corrupt,
    #[error("Esta bóveda es de una versión más nueva de Túnel; actualiza la app")]
    UnsupportedVersion,
    #[error("No se pudo leer o escribir la bóveda: {message}")]
    Io { message: String },
    #[error("La contraseña maestra no es la de esta cuenta")]
    WrongMasterPassword,
    #[error("No hay ninguna cuenta de Túnel de {email}; créala desde Túnel en el escritorio")]
    NoAccount { email: String },
    #[error("Este dispositivo no está unido a ninguna cuenta")]
    NotSignedIn,
    /// Un error de la red o del servidor, con el mensaje de la sincronización.
    #[error("{message}")]
    Sync { message: String },
    #[error("Ese host ya no está en la bóveda")]
    HostNotFound,
    #[error("Los hosts {name} todavía no se pueden abrir en este dispositivo")]
    UnsupportedProtocol { name: String },
    /// No se puede conectar con la configuración del host, con el motivo.
    #[error("{message}")]
    Connection { message: String },
}

impl From<StoreError> for TunelError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Crypto(CryptoError::Decryption) => Self::WrongPassword,
            StoreError::Crypto(_) | StoreError::Corrupt => Self::Corrupt,
            StoreError::WeakPassword => Self::WeakPassword {
                min: crate::min_password_length(),
            },
            StoreError::AlreadyExists(_) => Self::AlreadyExists,
            StoreError::Locked => Self::Locked,
            StoreError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            // En móvil no hay desbloqueo biométrico del núcleo: lo hace la app con el llavero.
            StoreError::PasswordRequired => Self::WrongPassword,
            StoreError::Io(e) => Self::Io {
                message: e.to_string(),
            },
        }
    }
}

/// El mensaje de un error para mostrarlo tal cual: así Swift y Kotlin no lo repiten.
#[uniffi::export]
pub fn error_message(error: TunelError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_includes_the_minimum_length() {
        let message = error_message(TunelError::WeakPassword { min: 8 });

        assert_eq!(
            message,
            "La contraseña maestra debe tener al menos 8 caracteres"
        );
    }
}
