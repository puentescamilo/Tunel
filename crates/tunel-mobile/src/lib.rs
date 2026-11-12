//! Núcleo de Túnel para las apps móviles: lo que Swift (iOS y iPadOS) y Kotlin (Android) ven
//! del núcleo en Rust, a través de UniFFI.
//!
//! La interfaz es nativa en cada sistema; el formato de la bóveda, el cifrado y, más
//! adelante, SSH y la sincronización salen de aquí, igual que en el escritorio.

mod error;
mod vault;

pub use error::TunelError;
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
