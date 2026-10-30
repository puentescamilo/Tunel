//! Cliente de sincronización de Túnel.
//!
//! Crea o abre una cuenta en un servidor `tunel-server` y sincroniza con él la bóveda
//! local. Todo lo que sale del equipo va cifrado: el servidor solo ve registros con
//! identificadores opacos y una clave de acceso derivada de la contraseña.

pub mod account;
pub mod api;
mod keypair;
pub mod run;
mod session;
pub mod teams;

pub use account::{create_account, sign_in, sign_out};
pub use api::{ServerUrl, check_server_url};
pub use run::{SyncOutcome, TeamProblem, sync_once};

use tunel_core::sync::{KeyProblem, ManifestError, SyncCryptoError};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("servidor no válido: {0}")]
    InvalidServer(String),
    #[error("no se pudo conectar con el servidor: {0}")]
    Network(#[source] reqwest::Error),
    #[error("correo o contraseña incorrectos")]
    Unauthorized,
    #[error("ya existe una cuenta con ese correo en este servidor")]
    AccountExists,
    /// El servidor no admite la cuenta; el mensaje dice por qué (registro cerrado o
    /// dominio de correo no permitido).
    #[error("no se puede crear la cuenta: {0}")]
    RegistrationClosed(String),
    #[error("no permitido: {0}")]
    Forbidden(String),
    #[error("demasiados intentos; espera unos minutos")]
    TooManyAttempts,
    #[error("el servidor está ocupado; se reintentará")]
    Busy,
    #[error("la cuenta alcanzó su espacio máximo en el servidor")]
    QuotaExceeded,
    #[error("conflicto con el servidor: {0}")]
    Conflict(String),
    #[error("el servidor respondió con un error ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("el servidor pidió parámetros de cifrado más débiles de lo permitido")]
    WeakKdf,
    #[error("no se pudieron descifrar los datos: {0}")]
    Crypto(#[from] SyncCryptoError),
    #[error("el servidor devolvió datos incompletos o antiguos: {0}")]
    Integrity(#[from] ManifestError),
    #[error("datos de la bóveda no válidos: {0}")]
    Data(#[from] serde_json::Error),
    #[error("otros equipos suben cambios sin parar; se reintentará")]
    TooManyConflicts,
    #[error("el servidor respondió de forma incoherente: {0}")]
    Misbehaving(&'static str),
    #[error("la sincronización tardó demasiado; se reintentará")]
    Timeout,
    #[error("error interno: {0}")]
    Internal(String),
    #[error("no encontrado: {0}")]
    NotFound(String),
    #[error("la cuenta todavía no tiene claves para Teams; sincroniza primero")]
    NoKeypair,
    #[error(transparent)]
    Key(#[from] KeyProblem),
    #[error(
        "hay registros del Team que esta versión de Túnel no reconoce; actualízala antes de renovar la clave"
    )]
    RejectedRecords,
    #[error("la clave del Team cambió; se actualizará en la próxima sincronización")]
    StaleKey,
    #[error("el servidor devolvió una clave del Team anterior a la que ya se tenía")]
    KeyRollback,
    #[error("alguien salió del Team y un administrador tiene que renovar la clave")]
    RekeyNeeded,
    #[error("el nombre del Team no puede estar vacío ni pasar de 60 caracteres")]
    InvalidName,
}

impl SyncError {
    /// Merece la pena reintentar más tarde sin que el usuario haga nada.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Network(_)
                | Self::Busy
                | Self::TooManyConflicts
                | Self::TooManyAttempts
                | Self::Timeout
                | Self::StaleKey
        ) || matches!(self, Self::Server { status, .. } if *status >= 500)
    }
}

impl From<tunel_core::crypto::CryptoError> for SyncError {
    fn from(e: tunel_core::crypto::CryptoError) -> Self {
        Self::Crypto(SyncCryptoError::Crypto(e))
    }
}

/// Hora actual en milisegundos desde 1970, para el reloj de la sincronización.
pub(crate) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
