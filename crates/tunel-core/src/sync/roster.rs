//! Lista de miembros de un Team, firmada por un admin y cifrada con la clave del Team.
//!
//! El servidor dice quién es miembro y quién envolvió cada clave, pero podría mentir:
//! volver a meter a alguien que se sacó, para que la siguiente clave le llegue, o hacer
//! pasar por admin a cualquier contacto fijado para que cuele una clave suya. Por eso los
//! admins guardan junto al Team la lista de miembros, con su clave pública y su rol:
//!
//! - Va cifrada con la clave del Team, así el servidor no la lee.
//! - La firma el admin que la escribe con su clave de cuenta (ver [`super::signature`]).
//!   Tener la clave del Team no basta para cambiarla: un miembro, o alguien a quien se va
//!   a sacar, no puede hacerse admin ni volver a ponerse en ella.
//! - Cada versión la firma un admin de la anterior, y la versión siempre crece, también al
//!   renovar la clave: el servidor no puede devolver una antigua.
//!
//! Con ella, una clave nueva del Team solo se acepta si la envolvió un admin de la lista,
//! y al renovarla solo se envuelve para quien está en ella.
//!
//! Los Teams creados antes de que existiera no tienen lista hasta que un admin invita,
//! cambia un rol o renueva la clave: mientras tanto se confía como antes, en los contactos
//! fijados.

use super::keys::{SyncCryptoError, VaultKey};
use super::protocol::{RosterBlob, TeamMember, TeamRole};
use super::team::{AccountKeypair, PublicKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const AAD_ROSTER: &[u8] = b"tunel-equipo-miembros-v1:";
const SIGNATURE_DOMAIN: &[u8] = b"tunel-equipo-miembros-firma-v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMember {
    pub key: PublicKey,
    pub role: TeamRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Roster {
    /// Crece con cada cambio, también al renovar la clave.
    pub version: u64,
    /// Por correo, en minúsculas.
    pub members: BTreeMap<String, RosterMember>,
    /// Se graban las sesiones con los hosts del Team (ver [`super::recording`]). Va aquí,
    /// firmado por un admin, para que ni el servidor ni un miembro lo puedan apagar.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record_sessions: bool,
}

/// Lo que se firma: la lista ligada a su Team, su época y quien la escribe.
#[derive(Serialize, Deserialize)]
struct Payload {
    team: String,
    epoch: u64,
    author: String,
    roster: Roster,
}

/// Lo que va cifrado: la lista tal como se firmó y la firma.
#[derive(Serialize, Deserialize)]
struct Signed {
    payload: String,
    signature: String,
}

/// Una lista descifrada cuya firma falta por comprobar: quien llama decide con qué clave.
pub struct Unverified {
    pub roster: Roster,
    /// Quien dice haberla escrito.
    pub author: String,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl Unverified {
    /// La firmó el dueño de `key`.
    pub fn signed_by(&self, key: &PublicKey) -> bool {
        key.verify(&self.message, &self.signature)
    }
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
            record_sessions: false,
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
            record_sessions: self.record_sessions,
        }
    }

    /// La lista con la grabación de sesiones encendida o apagada.
    pub fn recording(&self, on: bool) -> Self {
        Self {
            version: self.version + 1,
            record_sessions: on,
            ..self.clone()
        }
    }

    /// La clave de `email` si es admin según la lista.
    pub fn admin_key(&self, email: &str) -> Option<PublicKey> {
        self.members
            .get(email)
            .filter(|m| m.role == TeamRole::Admin)
            .map(|m| m.key)
    }

    /// `email`, con la clave `key`, es admin según la lista.
    pub fn is_admin(&self, email: &str, key: &PublicKey) -> bool {
        self.admin_key(email).is_some_and(|k| k == *key)
    }

    /// `email`, con la clave `key`, está en la lista.
    pub fn has(&self, email: &str, key: &PublicKey) -> bool {
        self.members.get(email).is_some_and(|m| m.key == *key)
    }

    /// Firmada por `author` con `pair` y cifrada con la clave del Team en la época `epoch`.
    pub fn seal(
        &self,
        key: &VaultKey,
        team: &str,
        epoch: u64,
        author: &str,
        pair: &AccountKeypair,
    ) -> Result<RosterBlob, SyncCryptoError> {
        let payload = Payload {
            team: team.to_string(),
            epoch,
            author: author.to_string(),
            roster: self.clone(),
        };
        let payload = serde_json::to_string(&payload).map_err(|_| SyncCryptoError::Corrupt)?;
        let message = [SIGNATURE_DOMAIN, payload.as_bytes()].concat();
        let signed = Signed {
            signature: B64.encode(pair.sign(&message)),
            payload,
        };
        let plain = serde_json::to_vec(&signed).map_err(|_| SyncCryptoError::Corrupt)?;
        Ok(RosterBlob {
            version: self.version,
            blob: key.seal_blob(&plain, &aad(team, epoch))?,
        })
    }

    /// Descifra la lista y comprueba que es de este Team, de esta época y de la versión que
    /// dice el servidor. La firma la comprueba quien llama, con [`Unverified::signed_by`].
    pub fn open(
        sealed: &RosterBlob,
        key: &VaultKey,
        team: &str,
        epoch: u64,
    ) -> Result<Unverified, SyncCryptoError> {
        let plain = key.open_blob(&sealed.blob, &aad(team, epoch))?;
        let signed: Signed =
            serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)?;
        let payload: Payload =
            serde_json::from_str(&signed.payload).map_err(|_| SyncCryptoError::Corrupt)?;
        if payload.team != team
            || payload.epoch != epoch
            || payload.roster.version != sealed.version
        {
            return Err(SyncCryptoError::Mismatch);
        }
        Ok(Unverified {
            roster: payload.roster,
            author: payload.author,
            message: [SIGNATURE_DOMAIN, signed.payload.as_bytes()].concat(),
            signature: B64
                .decode(&signed.signature)
                .map_err(|_| SyncCryptoError::Corrupt)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn member(pair: &AccountKeypair, role: TeamRole) -> RosterMember {
        RosterMember {
            key: pair.public(),
            role,
        }
    }

    #[test]
    fn the_roster_is_bound_to_its_team_epoch_and_version() {
        let key = VaultKey::generate();
        let ana = AccountKeypair::generate();
        let roster = Roster::default().with("ana@x.test", member(&ana, TeamRole::Admin));
        let sealed = roster.seal(&key, TEAM, 2, "ana@x.test", &ana).unwrap();
        let opened = Roster::open(&sealed, &key, TEAM, 2).unwrap();
        assert_eq!(opened.roster, roster);
        assert_eq!(opened.author, "ana@x.test");
        assert!(opened.signed_by(&ana.public()));
        assert!(Roster::open(&sealed, &key, TEAM, 1).is_err());
        assert!(Roster::open(&sealed, &key, "otro", 2).is_err());
        assert!(Roster::open(&sealed, &VaultKey::generate(), TEAM, 2).is_err());
        let relabeled = RosterBlob {
            version: 7,
            ..sealed
        };
        assert!(Roster::open(&relabeled, &key, TEAM, 2).is_err());
    }

    #[test]
    fn holding_the_team_key_is_not_enough_to_write_the_roster() {
        let key = VaultKey::generate();
        let ana = AccountKeypair::generate();
        let bob = AccountKeypair::generate();
        // Bob, que tiene la clave del Team, firma una lista en la que es admin.
        let forged = Roster::default()
            .with("ana@x.test", member(&ana, TeamRole::Admin))
            .with("bob@x.test", member(&bob, TeamRole::Admin));
        let sealed = forged.seal(&key, TEAM, 0, "ana@x.test", &bob).unwrap();
        let opened = Roster::open(&sealed, &key, TEAM, 0).unwrap();
        assert!(
            !opened.signed_by(&ana.public()),
            "dice ser de ana, pero no lo es"
        );
        // Y sin firma no llega ni a abrirse.
        let raw = key
            .seal_blob(&serde_json::to_vec(&forged).unwrap(), &aad(TEAM, 0))
            .unwrap();
        let unsigned = RosterBlob {
            version: forged.version,
            blob: raw,
        };
        assert!(Roster::open(&unsigned, &key, TEAM, 0).is_err());
    }

    #[test]
    fn only_listed_admins_with_their_key_count() {
        let (ana, bob) = (AccountKeypair::generate(), AccountKeypair::generate());
        let roster = Roster::default()
            .with("ana@x.test", member(&ana, TeamRole::Admin))
            .with("bob@x.test", member(&bob, TeamRole::Member));
        assert_eq!(roster.version, 2);
        assert!(roster.is_admin("ana@x.test", &ana.public()));
        assert!(!roster.is_admin("ana@x.test", &bob.public()), "otra clave");
        assert!(!roster.is_admin("bob@x.test", &bob.public()), "no es admin");
        assert!(roster.has("bob@x.test", &bob.public()));
        assert!(!roster.is_admin("carol@x.test", &ana.public()));
    }
}
