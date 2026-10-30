//! Configuración de la sincronización de este equipo: a qué servidor y cuenta está unido,
//! las claves para hablar con él y el estado de la sincronización.
//!
//! Se guarda junto a la bóveda y cifrada con la misma clave maestra, porque contiene la
//! clave de bóveda y la clave de acceso. Con ella el equipo sincroniza sin volver a pedir
//! la contraseña de la cuenta.

use super::keys::VaultKey;
use super::state::SyncState;
use super::team::AccountKeypair;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
pub struct SyncLocal {
    /// URL base del servidor, sin barra final.
    pub server: String,
    pub email: String,
    /// Clave de acceso en base64; permite renovar la sesión sin la contraseña.
    pub auth: Zeroizing<String>,
    pub vault_key: VaultKey,
    /// Token de la sesión actual, si hay una.
    pub token: Option<Zeroizing<String>>,
    pub state: SyncState,
    /// Par de claves de la cuenta para los equipos; `None` hasta recuperarlo o crearlo.
    #[serde(default)]
    pub keypair: Option<AccountKeypair>,
}

/// Lleva claves: solo se muestra a qué servidor y cuenta está unido el equipo.
impl fmt::Debug for SyncLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncLocal")
            .field("server", &self.server)
            .field("email", &self.email)
            .field("pending", &self.state.pending.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample() -> SyncLocal {
        SyncLocal {
            server: "https://tunel.ejemplo.com".into(),
            email: "ana@ejemplo.com".into(),
            auth: Zeroizing::new("Y2xhdmUtZGUtYWNjZXNv".into()),
            vault_key: VaultKey::generate(),
            token: Some(Zeroizing::new("token-secreto".into())),
            state: SyncState::new(Uuid::from_u128(1)),
            keypair: Some(AccountKeypair::generate()),
        }
    }

    #[test]
    fn round_trips_through_json_keeping_the_vault_key() {
        let local = sample();
        let json = serde_json::to_string(&local).unwrap();
        let back: SyncLocal = serde_json::from_str(&json).unwrap();
        let key = super::super::RecordKey::new(super::super::RecordKind::Host, "x");
        assert_eq!(
            back.vault_key.record_id(&key),
            local.vault_key.record_id(&key)
        );
        assert_eq!(back.state, local.state);
        assert_eq!(
            back.keypair.map(|k| k.public()),
            local.keypair.map(|k| k.public())
        );
        assert_eq!(
            back.token.as_deref().map(String::as_str),
            Some("token-secreto")
        );
    }

    #[test]
    fn configurations_saved_before_teams_still_load() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json.as_object_mut().unwrap().remove("keypair");
        let back: SyncLocal = serde_json::from_value(json).unwrap();
        assert!(back.keypair.is_none());
    }

    #[test]
    fn debug_hides_keys_and_tokens() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("token-secreto"));
        assert!(!shown.contains("Y2xhdmUt"));
        assert!(shown.contains("tunel.ejemplo.com"));
    }
}
