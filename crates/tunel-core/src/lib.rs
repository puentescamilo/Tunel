//! Núcleo de Túnel: modelos de dominio, bóveda cifrada y verificación de known_hosts.

pub mod crypto;
pub mod io;
pub mod model;
pub mod ssh_config;
pub mod store;
pub mod sync;
pub mod theme;
pub mod vault;

pub use model::*;
pub use store::{StoreError, UnlockedVault};
pub use vault::{HostKeyStatus, ResolveError, ResolvedHost, VaultData};
