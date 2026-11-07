//! Núcleo de Túnel: modelos de dominio, bóveda cifrada y verificación de known_hosts.

pub mod biometric;
pub mod cloud;
pub mod containers;
pub mod crypto;
pub mod history;
pub mod io;
pub mod model;
pub mod password;
pub mod share;
pub mod ssh_config;
pub mod store;
pub mod sync;
pub mod template;
pub mod theme;
pub mod vault;
pub mod vaultwarden;
pub mod vaultwarden_import;
#[cfg(windows)]
mod windows_acl;
pub mod workspace;

pub use model::*;
pub use store::{PasswordCheck, StoreError, UnlockedVault};
pub use vault::{HostKeyStatus, ResolveError, ResolvedHost, VaultData};
