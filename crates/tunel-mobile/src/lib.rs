//! Núcleo de Túnel para las apps móviles: lo que Swift (iOS y iPadOS) y Kotlin (Android) ven
//! del núcleo en Rust, a través de UniFFI.
//!
//! La interfaz es nativa en cada sistema; el formato de la bóveda, el cifrado, SSH y la
//! sincronización salen de aquí, igual que en el escritorio.

mod account;
mod biometric;
mod error;
mod runtime;
mod terminal;
mod vault;

pub use account::{
    AccountInfo, Provider, ProviderSignIn, SignInOptions, SyncReport, sign_in_options,
};
pub use biometric::{BiometricKey, biometric_id, biometric_ready};
pub use error::{TunelError, error_message};
pub use terminal::{
    HostKeyQuestion, LoginPrompt, LoginQuestion, TerminalListener, TerminalSession,
};
pub use vault::{GroupSummary, HostSummary, Vault, vault_exists};

uniffi::setup_scaffolding!();

/// Versión del núcleo, para mostrarla en Ajustes.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Mínimo de caracteres de la contraseña maestra, el mismo que en el escritorio.
#[uniffi::export]
pub fn min_password_length() -> u32 {
    tunel_core::store::MIN_PASSWORD_LEN as u32
}
