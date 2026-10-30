//! Configuración de la sincronización de este equipo: a qué servidor y cuenta está unido,
//! las claves para hablar con él y el estado de la sincronización.
//!
//! Se guarda junto a la bóveda y cifrada con la misma clave maestra, porque contiene la
//! clave de bóveda y la clave de acceso. Con ella el equipo sincroniza sin volver a pedir
//! la contraseña de la cuenta.

use super::keys::VaultKey;
use super::protocol::TeamRole;
use super::space::{Space, partition};
use super::state::SyncState;
use super::team::{AccountKeypair, PublicKey};
use crate::vault::VaultData;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    /// Par de claves de la cuenta para los Teams; `None` hasta recuperarlo o crearlo.
    #[serde(default)]
    pub keypair: Option<AccountKeypair>,
    /// Teams de los que la cuenta es miembro, con su clave y su estado.
    #[serde(default)]
    pub teams: Vec<TeamLocal>,
    /// Invitaciones a Teams sin responder.
    #[serde(default)]
    pub invitations: Vec<Invitation>,
    /// Clave pública de cada cuenta con la que se comparte algo, fijada la primera vez
    /// que se vio. Si el servidor entrega otra, alguien intenta suplantarla.
    #[serde(default)]
    pub contacts: BTreeMap<String, Contact>,
}

/// Un Team visto desde este equipo.
#[derive(Clone, Serialize, Deserialize)]
pub struct TeamLocal {
    pub id: String,
    pub name: String,
    pub role: TeamRole,
    /// Época de `key`; nunca retrocede.
    pub epoch: u64,
    pub key: VaultKey,
    pub state: SyncState,
    /// Alguien salió y la clave está pendiente de renovar.
    #[serde(default)]
    pub rekey_needed: bool,
}

/// Lleva la clave del Team: no se muestra.
impl fmt::Debug for TeamLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamLocal")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Invitación pendiente: de qué Team y quién invita, con la clave que el servidor da
/// para esa persona. El nombre del Team no se conoce hasta aceptar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub team: String,
    pub from: String,
    /// Su huella se muestra antes de aceptar: aceptar es confiar en ella.
    pub from_key: PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub key: PublicKey,
    /// La persona comparó la huella en persona.
    #[serde(default)]
    pub verified: bool,
}

/// Una clave pública que no se puede usar sin que la persona intervenga.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyProblem {
    /// El servidor entregó otra clave que la fijada.
    #[error("la clave de {0} no es la que se conocía; puede ser una suplantación")]
    Changed(String),
    /// Nunca se confirmó la clave de esta cuenta.
    #[error("confirma la clave de {0} comparando su huella")]
    Unconfirmed(String),
}

/// Los correos se comparan en minúsculas y sin espacios, como los guarda el servidor.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

impl SyncLocal {
    /// Anota los cambios locales de `old` a `new` en el espacio al que pertenece cada uno.
    pub fn record_local(
        &self,
        old: &VaultData,
        new: &VaultData,
        wall_millis: u64,
    ) -> Result<Self, serde_json::Error> {
        let state = self.state.record_local(
            &partition(old, Space::Personal),
            &partition(new, Space::Personal),
            wall_millis,
        )?;
        let teams = self
            .teams
            .iter()
            .map(|team| {
                let space = Space::Team(&team.id);
                let state = team.state.record_local(
                    &partition(old, space),
                    &partition(new, space),
                    wall_millis,
                )?;
                Ok(TeamLocal {
                    state,
                    ..team.clone()
                })
            })
            .collect::<Result<_, serde_json::Error>>()?;
        Ok(Self {
            state,
            teams,
            ..self.clone()
        })
    }

    /// Cambios de todos los espacios que esperan a subir.
    pub fn pending(&self) -> usize {
        self.state.pending.len()
            + self
                .teams
                .iter()
                .map(|t| t.state.pending.len())
                .sum::<usize>()
    }

    pub fn team(&self, id: &str) -> Option<&TeamLocal> {
        self.teams.iter().find(|t| t.id == id)
    }

    /// Comprueba que la clave que da el servidor para `email` es la fijada (o, para la
    /// propia cuenta, la de su par de claves). No fija nada: una cuenta nueva es un error.
    pub fn check_key(&self, email: &str, key: PublicKey) -> Result<(), KeyProblem> {
        let email = normalize_email(email);
        if email == normalize_email(&self.email) {
            return match &self.keypair {
                Some(own) if own.public() == key => Ok(()),
                _ => Err(KeyProblem::Changed(email)),
            };
        }
        match self.contacts.get(&email) {
            Some(contact) if contact.key == key => Ok(()),
            Some(_) => Err(KeyProblem::Changed(email)),
            None => Err(KeyProblem::Unconfirmed(email)),
        }
    }

    /// Fija la clave de `email` porque la persona lo decidió (al invitar o al aceptar una
    /// invitación). Si ya había otra fijada, falla: cambiarla es [`Self::replace_key`].
    pub fn pin(&self, email: &str, key: PublicKey) -> Result<Self, KeyProblem> {
        match self.check_key(email, key) {
            Ok(()) => Ok(self.clone()),
            Err(KeyProblem::Unconfirmed(email)) => Ok(self.with_contact(email, key, false)),
            Err(changed) => Err(changed),
        }
    }

    /// La persona comparó la huella y acepta esta clave para `email`, aunque sustituya a
    /// la fijada.
    pub fn replace_key(&self, email: &str, key: PublicKey) -> Self {
        self.with_contact(normalize_email(email), key, true)
    }

    /// Marca como comparada en persona la huella ya fijada de `email`.
    pub fn mark_verified(&self, email: &str) -> Self {
        match self.contacts.get(&normalize_email(email)) {
            Some(contact) => self.with_contact(normalize_email(email), contact.key, true),
            None => self.clone(),
        }
    }

    fn with_contact(&self, email: String, key: PublicKey, verified: bool) -> Self {
        let mut contacts = self.contacts.clone();
        contacts.insert(email, Contact { key, verified });
        Self {
            contacts,
            ..self.clone()
        }
    }
}

/// Lleva claves: solo se muestra a qué servidor y cuenta está unido el equipo.
impl fmt::Debug for SyncLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncLocal")
            .field("server", &self.server)
            .field("email", &self.email)
            .field("pending", &self.pending())
            .field("teams", &self.teams.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Host;
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
            teams: Vec::new(),
            invitations: Vec::new(),
            contacts: BTreeMap::new(),
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

    fn with_team(local: SyncLocal) -> SyncLocal {
        SyncLocal {
            teams: vec![TeamLocal {
                id: TEAM.into(),
                name: "Infra".into(),
                role: TeamRole::Member,
                epoch: 0,
                key: VaultKey::generate(),
                state: SyncState::new(Uuid::from_u128(1)),
                rekey_needed: false,
            }],
            ..local
        }
    }

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    #[test]
    fn each_change_is_queued_in_its_own_space() {
        let local = with_team(sample());
        let old = VaultData::default();
        let mut shared = Host::new("compartido", "2.2.2.2");
        shared.team = Some(TEAM.into());
        let new = old
            .with_host(Host::new("personal", "1.1.1.1"))
            .with_host(shared);
        let next = local.record_local(&old, &new, 10).unwrap();
        assert_eq!(next.state.pending.len(), 1);
        assert_eq!(next.teams[0].state.pending.len(), 1);
        assert_eq!(next.pending(), 2);
    }

    #[test]
    fn moving_a_host_into_a_team_deletes_it_from_the_personal_space() {
        let local = with_team(sample());
        let host = Host::new("web", "1.1.1.1");
        let old = VaultData::default().with_host(host.clone());
        let moved = Host {
            team: Some(TEAM.into()),
            ..host
        };
        let new = VaultData::default().with_host(moved);
        let next = local.record_local(&old, &new, 10).unwrap();
        let personal = next
            .state
            .outgoing(&partition(&new, Space::Personal))
            .unwrap();
        assert!(personal[0].value.is_none());
        let team = next.teams[0]
            .state
            .outgoing(&partition(&new, Space::Team(TEAM)))
            .unwrap();
        assert!(team[0].value.is_some());
    }

    #[test]
    fn keys_are_pinned_on_request_and_changes_are_refused() {
        let local = sample();
        let bob = AccountKeypair::generate().public();
        assert_eq!(
            local.check_key("bob@ejemplo.com", bob),
            Err(KeyProblem::Unconfirmed("bob@ejemplo.com".into()))
        );
        let pinned = local.pin("bob@ejemplo.com", bob).unwrap();
        assert_eq!(pinned.contacts["bob@ejemplo.com"].key, bob);
        assert!(pinned.check_key("Bob@Ejemplo.com ", bob).is_ok());
        let impostor = AccountKeypair::generate().public();
        assert!(pinned.pin("bob@ejemplo.com", impostor).is_err());
        let replaced = pinned.replace_key("bob@ejemplo.com", impostor);
        assert!(replaced.contacts["bob@ejemplo.com"].verified);
        assert!(replaced.check_key("bob@ejemplo.com", impostor).is_ok());

        // La propia cuenta se comprueba contra su par de claves, escrita como sea.
        let own = local.keypair.as_ref().unwrap().public();
        assert!(local.check_key("ana@ejemplo.com", own).is_ok());
        assert!(local.check_key("ANA@ejemplo.com", impostor).is_err());
        assert!(local.pin("Ana@ejemplo.com", impostor).is_err());
    }

    #[test]
    fn debug_hides_keys_and_tokens() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("token-secreto"));
        assert!(!shown.contains("Y2xhdmUt"));
        assert!(shown.contains("tunel.ejemplo.com"));
    }
}
