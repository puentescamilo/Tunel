//! Cliente de Vaultwarden (y Bitwarden) para Túnel.
//!
//! Inicia sesión con la cuenta de cada persona, descarga y descifra en el equipo sus
//! elementos y los de sus organizaciones, y crea elementos nuevos. El servidor nunca ve las
//! contraseñas. Es opcional: el resto de Túnel no depende de este crate. El diseño está en
//! `docs/vaultwarden.md`.

pub mod api;
pub mod crypto;
mod session;
pub mod vault;
mod wire;

pub use api::{Device, ServerUrl, TwoFactorProvider, check_server_url};
pub use crypto::{CryptoError, SymmetricKey};
pub use session::{Credentials, Place, SecondFactor, Session};
pub use vault::{Collection, Content, Field, Item, NewLogin, Organization, Unreadable, Vault};

#[derive(Debug, thiserror::Error)]
pub enum VwError {
    #[error("servidor de Vaultwarden no válido: {0}")]
    InvalidServer(String),
    #[error("no se pudo conectar con Vaultwarden: {0}")]
    Network(#[source] reqwest::Error),
    #[error("la cuenta pide el segundo factor")]
    TwoFactorRequired(Vec<TwoFactorProvider>),
    #[error("Vaultwarden rechazó el inicio de sesión: {0}")]
    Rejected(String),
    #[error("la sesión de Vaultwarden caducó; vuelve a iniciar sesión")]
    SessionExpired,
    #[error("demasiados intentos en Vaultwarden; espera un minuto y vuelve a probar")]
    TooManyAttempts,
    #[error("Vaultwarden respondió con un error ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("Vaultwarden respondió algo que Túnel no esperaba")]
    Unexpected,
    #[error("Túnel aún no admite {0}")]
    Unsupported(String),
    #[error(
        "esta cuenta entra sin contraseña maestra (SSO con dispositivos de confianza); Túnel aún no lo admite"
    )]
    NoMasterPassword,
    #[error("{0}")]
    InvalidRequest(&'static str),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
