//! Lista de miembros de un Team, cifrada con su clave.
//!
//! El servidor dice quién es miembro y quién envolvió cada clave, pero podría mentir:
//! volver a meter a alguien que se sacó, para que la siguiente clave le llegue, o hacer
//! pasar por admin a cualquier contacto fijado para que cuele una clave suya. Por eso los
//! admins guardan junto al Team la lista de miembros, con su clave pública y su rol,
//! cifrada con la clave del Team: el servidor no la puede leer ni cambiar.
//!
//! - Una clave nueva del Team solo se acepta si la envolvió un admin de la lista.
//! - Al renovar la clave, solo se envuelve para quien está en la lista.
//!
//! Cada cambio sube su versión; un equipo nunca acepta una versión anterior a la que ya
//! tiene. Los Teams creados antes de que existiera no tienen lista hasta que un admin
//! invita, cambia un rol o renueva la clave: mientras tanto se confía como antes, en los
//! contactos fijados.

use super::keys::{SealedBlob, SyncCryptoError, VaultKey};
use super::protocol::{TeamMember, TeamRole};
use super::team::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const AAD_ROSTER: &[u8] = b"tunel-equipo-miembros-v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMember {
    pub key: PublicKey,
    pub role: TeamRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Roster {
    /// Crece con cada cambio.
    pub version: u64,
    /// Por correo, en minúsculas.
    pub members: BTreeMap<String, RosterMember>,
}

fn aad(team: &str, epoch: u64) -> Vec<u8> {
    [AAD_ROSTER, team.as_bytes(), b":", &epoch.to_be_bytes()].concat()
}

impl Roster {
    /// La lista que da el servidor, sin comprobar: para empezar la de un Team que no la
    /// tenía.
    pub fn trusting(members: &[TeamMember]) -> Self {
        Self {
            version: 1,
            members: members
                .iter()
                .map(|m| {
                    let member = RosterMember {
                        key: m.public_key,
                        role: m.role,
                    };
                    (m.email.clone(), member)
                })
                .collect(),
        }
    }

    /// La lista con `email` añadido o cambiado.
    pub fn with(&self, email: &str, member: RosterMember) -> Self {
        let mut members = self.members.clone();
        members.insert(email.to_string(), member);
        Self {
            version: self.version + 1,
            members,
        }
    }

    /// `email`, con la clave `key`, es admin según la lista.
    pub fn is_admin(&self, email: &str, key: &PublicKey) -> bool {
        self.members
            .get(email)
            .is_some_and(|m| m.key == *key && m.role == TeamRole::Admin)
    }

    /// `email`, con la clave `key`, está en la lista.
    pub fn has(&self, email: &str, key: &PublicKey) -> bool {
        self.members.get(email).is_some_and(|m| m.key == *key)
    }

    /// Cifrada con la clave del Team en la época `epoch`.
    pub fn seal(
        &self,
        key: &VaultKey,
        team: &str,
        epoch: u64,
    ) -> Result<SealedBlob, SyncCryptoError> {
        let plain = serde_json::to_vec(self).map_err(|_| SyncCryptoError::Corrupt)?;
        key.seal_blob(&plain, &aad(team, epoch))
    }

    pub fn open(
        blob: &SealedBlob,
        key: &VaultKey,
        team: &str,
        epoch: u64,
    ) -> Result<Self, SyncCryptoError> {
        let plain = key.open_blob(blob, &aad(team, epoch))?;
        serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::AccountKeypair;

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn member(role: TeamRole) -> RosterMember {
        RosterMember {
            key: AccountKeypair::generate().public(),
            role,
        }
    }

    #[test]
    fn the_roster_is_bound_to_its_team_and_epoch() {
        let key = VaultKey::generate();
        let roster = Roster::default().with("ana@x.test", member(TeamRole::Admin));
        let sealed = roster.seal(&key, TEAM, 2).unwrap();
        assert_eq!(Roster::open(&sealed, &key, TEAM, 2).unwrap(), roster);
        assert!(Roster::open(&sealed, &key, TEAM, 1).is_err());
        assert!(Roster::open(&sealed, &key, "otro", 2).is_err());
        assert!(Roster::open(&sealed, &VaultKey::generate(), TEAM, 2).is_err());
    }

    #[test]
    fn only_listed_admins_with_their_key_count() {
        let ana = member(TeamRole::Admin);
        let bob = member(TeamRole::Member);
        let roster = Roster::default()
            .with("ana@x.test", ana)
            .with("bob@x.test", bob);
        assert_eq!(roster.version, 2);
        assert!(roster.is_admin("ana@x.test", &ana.key));
        assert!(!roster.is_admin("ana@x.test", &bob.key), "otra clave");
        assert!(!roster.is_admin("bob@x.test", &bob.key), "no es admin");
        assert!(roster.has("bob@x.test", &bob.key));
        assert!(!roster.is_admin("carol@x.test", &ana.key));
    }
}
