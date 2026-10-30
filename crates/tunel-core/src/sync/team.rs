//! Claves de los equipos: bóvedas compartidas entre varias cuentas del mismo servidor.
//!
//! - Cada cuenta tiene un par de claves X25519. La privada se guarda en el servidor
//!   cifrada con la clave de la bóveda personal, así cualquier equipo ya unido a la
//!   cuenta la recupera sin volver a pedir la contraseña; la pública la ve cualquiera.
//! - Cada equipo tiene su propia clave de bóveda, que cifra sus registros igual que la
//!   bóveda personal. Un administrador la envuelve para cada miembro con una clave que
//!   sale del intercambio X25519 entre su clave privada y la pública del miembro: así el
//!   miembro sabe que la envolvió ese administrador y no el servidor.
//! - El servidor podría entregar una clave pública falsa al invitar a alguien. Por eso
//!   cada clave pública tiene una huella que las personas pueden comparar en persona.
//! - Al sacar a un miembro, un administrador genera una clave nueva (la época siguiente)
//!   y vuelve a cifrar todo el equipo con ella.

use super::keys::{SealedBlob, SyncCryptoError, VaultKey, expand};
use crate::crypto::{self, KEY_LEN, MasterKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

const AAD_PRIVATE_KEY: &[u8] = b"tunel-sync-clave-privada-v1:";
const INFO_TEAM_WRAP: &[u8] = b"tunel-equipo-envoltura-v1";
const AAD_TEAM_KEY: &[u8] = b"tunel-equipo-clave-v1:";
const AAD_TEAM_NAME: &[u8] = b"tunel-equipo-nombre-v1:";
const FINGERPRINT_DOMAIN: &[u8] = b"tunel-huella-v1";
/// Bytes de la huella: 128 bits, en 8 grupos de 4 cifras hexadecimales.
const FINGERPRINT_LEN: usize = 16;
/// Tope del nombre de un equipo, en bytes.
pub const MAX_TEAM_NAME: usize = 100;

/// Clave pública X25519 de una cuenta.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Huella para comprobar en persona que la clave es la de quien dice ser,
    /// por ejemplo `3F2A 9C01 …` (8 grupos).
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::new()
            .chain_update(FINGERPRINT_DOMAIN)
            .chain_update(self.0)
            .finalize();
        digest[..FINGERPRINT_LEN]
            .chunks(2)
            .map(|pair| format!("{:02X}{:02X}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn from_base64(text: &str) -> Option<Self> {
        let bytes: [u8; KEY_LEN] = B64.decode(text).ok()?.try_into().ok()?;
        Some(Self(bytes))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_base64(&text).ok_or_else(|| serde::de::Error::custom("clave pública no válida"))
    }
}

/// Par de claves X25519 de la cuenta.
pub struct AccountKeypair {
    secret: Zeroizing<[u8; KEY_LEN]>,
    public: PublicKey,
}

/// Lleva la clave privada: solo se muestra la huella de la pública.
impl fmt::Debug for AccountKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Clone for AccountKeypair {
    fn clone(&self) -> Self {
        Self::from_secret(Zeroizing::new(*self.secret))
    }
}

impl AccountKeypair {
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        rand::rng().fill_bytes(secret.as_mut());
        Self::from_secret(secret)
    }

    fn from_secret(secret: Zeroizing<[u8; KEY_LEN]>) -> Self {
        let public = PublicKey(MontgomeryPoint::mul_base_clamped(*secret).to_bytes());
        Self { secret, public }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// Cifra la clave privada con la de la bóveda personal para guardarla en el servidor.
    pub fn seal(&self, vault: &VaultKey) -> Result<SealedBlob, SyncCryptoError> {
        vault.seal_blob(self.secret.as_ref(), &private_aad(&self.public))
    }

    /// Recupera el par guardado en el servidor y comprueba que la clave privada
    /// corresponde a la pública que publica, para que el servidor no pueda cambiarla.
    pub fn open(
        blob: &SealedBlob,
        public: &PublicKey,
        vault: &VaultKey,
    ) -> Result<Self, SyncCryptoError> {
        let plain = vault.open_blob(blob, &private_aad(public))?;
        let secret: [u8; KEY_LEN] = plain
            .as_slice()
            .try_into()
            .map_err(|_| SyncCryptoError::Corrupt)?;
        let pair = Self::from_secret(Zeroizing::new(secret));
        if pair.public != *public {
            return Err(SyncCryptoError::Mismatch);
        }
        Ok(pair)
    }

    /// Clave que comparten esta cuenta y `peer`, distinta para cada uso (`domain`) y cada
    /// sentido: `sender → recipient`.
    pub(super) fn wrapping_key(
        &self,
        domain: &[u8],
        peer: &PublicKey,
        sender: &PublicKey,
        recipient: &PublicKey,
    ) -> Result<MasterKey, SyncCryptoError> {
        let shared = Zeroizing::new(MontgomeryPoint(peer.0).mul_clamped(*self.secret).to_bytes());
        // Una clave pública de orden pequeño da un secreto nulo: no aporta nada.
        if shared.iter().all(|b| *b == 0) {
            return Err(SyncCryptoError::Corrupt);
        }
        let info = [domain, sender.as_bytes(), recipient.as_bytes()].concat();
        Ok(MasterKey::from_bytes(expand(shared.as_ref(), &info)))
    }
}

fn private_aad(public: &PublicKey) -> Vec<u8> {
    [AAD_PRIVATE_KEY, public.as_bytes()].concat()
}

/// Solo para guardarlo en la configuración local, que va cifrada con la clave maestra.
impl Serialize for AccountKeypair {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(B64.encode(self.secret.as_ref()));
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for AccountKeypair {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        let bytes = Zeroizing::new(
            B64.decode(text.as_bytes())
                .map_err(serde::de::Error::custom)?,
        );
        let secret: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("clave privada de longitud incorrecta"))?;
        Ok(Self::from_secret(Zeroizing::new(secret)))
    }
}

/// A qué equipo y época pertenece una clave de equipo envuelta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeamKeyContext<'a> {
    pub team: &'a str,
    pub epoch: u64,
}

impl TeamKeyContext<'_> {
    fn aad(&self) -> Vec<u8> {
        [
            AAD_TEAM_KEY,
            self.team.as_bytes(),
            b":",
            &self.epoch.to_be_bytes(),
        ]
        .concat()
    }
}

/// Envuelve la clave del equipo para `recipient`; la puede abrir solo él, y sabiendo
/// que la envolvió el dueño de `sender`.
pub fn wrap_team_key(
    key: &VaultKey,
    context: TeamKeyContext<'_>,
    sender: &AccountKeypair,
    recipient: &PublicKey,
) -> Result<SealedBlob, SyncCryptoError> {
    let wrapping = sender.wrapping_key(INFO_TEAM_WRAP, recipient, &sender.public, recipient)?;
    let sealed = crypto::seal(&wrapping, key.as_bytes(), &context.aad())?;
    Ok(SealedBlob::from_sealed(&sealed))
}

/// Abre la clave del equipo que `sender` envolvió para esta cuenta.
pub fn unwrap_team_key(
    blob: &SealedBlob,
    context: TeamKeyContext<'_>,
    recipient: &AccountKeypair,
    sender: &PublicKey,
) -> Result<VaultKey, SyncCryptoError> {
    let wrapping = recipient.wrapping_key(INFO_TEAM_WRAP, sender, sender, &recipient.public)?;
    let plain = crypto::open(&wrapping, &blob.to_sealed()?, &context.aad())?;
    let bytes: [u8; KEY_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| SyncCryptoError::Corrupt)?;
    Ok(VaultKey::from_bytes(Zeroizing::new(bytes)))
}

fn name_aad(team: &str) -> Vec<u8> {
    [AAD_TEAM_NAME, team.as_bytes()].concat()
}

/// Cifra el nombre del equipo; el servidor no lo ve.
pub fn seal_team_name(
    key: &VaultKey,
    team: &str,
    name: &str,
) -> Result<SealedBlob, SyncCryptoError> {
    key.seal_blob(name.as_bytes(), &name_aad(team))
}

pub fn open_team_name(
    key: &VaultKey,
    team: &str,
    blob: &SealedBlob,
) -> Result<String, SyncCryptoError> {
    let plain = key.open_blob(blob, &name_aad(team))?;
    if plain.len() > MAX_TEAM_NAME {
        return Err(SyncCryptoError::Corrupt);
    }
    String::from_utf8(plain.to_vec()).map_err(|_| SyncCryptoError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{RecordKey, RecordKind};

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn context(epoch: u64) -> TeamKeyContext<'static> {
        TeamKeyContext { team: TEAM, epoch }
    }

    fn same_key(a: &VaultKey, b: &VaultKey) -> bool {
        let key = RecordKey::new(RecordKind::Host, "x");
        a.record_id(&key) == b.record_id(&key)
    }

    #[test]
    fn the_private_key_round_trips_through_the_server() {
        let vault = VaultKey::generate();
        let pair = AccountKeypair::generate();
        let sealed = pair.seal(&vault).unwrap();
        let back = AccountKeypair::open(&sealed, &pair.public(), &vault).unwrap();
        assert_eq!(back.public(), pair.public());
        assert!(AccountKeypair::open(&sealed, &pair.public(), &VaultKey::generate()).is_err());
    }

    #[test]
    fn the_server_cannot_swap_the_public_key() {
        let vault = VaultKey::generate();
        let pair = AccountKeypair::generate();
        let sealed = pair.seal(&vault).unwrap();
        let fake = AccountKeypair::generate().public();
        assert!(AccountKeypair::open(&sealed, &fake, &vault).is_err());
    }

    #[test]
    fn a_member_opens_the_team_key_wrapped_by_an_admin() {
        let admin = AccountKeypair::generate();
        let member = AccountKeypair::generate();
        let key = VaultKey::generate();
        let wrapped = wrap_team_key(&key, context(3), &admin, &member.public()).unwrap();
        let opened = unwrap_team_key(&wrapped, context(3), &member, &admin.public()).unwrap();
        assert!(same_key(&key, &opened));
    }

    #[test]
    fn an_admin_can_wrap_the_team_key_for_itself() {
        let admin = AccountKeypair::generate();
        let key = VaultKey::generate();
        let wrapped = wrap_team_key(&key, context(0), &admin, &admin.public()).unwrap();
        let opened = unwrap_team_key(&wrapped, context(0), &admin, &admin.public()).unwrap();
        assert!(same_key(&key, &opened));
    }

    #[test]
    fn a_wrapped_key_is_bound_to_its_team_epoch_and_sender() {
        let admin = AccountKeypair::generate();
        let member = AccountKeypair::generate();
        let impostor = AccountKeypair::generate();
        let key = VaultKey::generate();
        let wrapped = wrap_team_key(&key, context(1), &admin, &member.public()).unwrap();
        assert!(unwrap_team_key(&wrapped, context(2), &member, &admin.public()).is_err());
        let other_team = TeamKeyContext {
            team: "otro",
            epoch: 1,
        };
        assert!(unwrap_team_key(&wrapped, other_team, &member, &admin.public()).is_err());
        // Quien no la envolvió no puede hacerse pasar por el administrador.
        assert!(unwrap_team_key(&wrapped, context(1), &member, &impostor.public()).is_err());
        // Ni otro miembro puede abrirla.
        assert!(unwrap_team_key(&wrapped, context(1), &impostor, &admin.public()).is_err());
    }

    #[test]
    fn a_low_order_public_key_is_rejected() {
        let admin = AccountKeypair::generate();
        let zero = PublicKey::from_bytes([0; KEY_LEN]);
        assert!(wrap_team_key(&VaultKey::generate(), context(0), &admin, &zero).is_err());
    }

    #[test]
    fn the_team_name_is_encrypted_and_bound_to_the_team() {
        let key = VaultKey::generate();
        let sealed = seal_team_name(&key, TEAM, "Infraestructura").unwrap();
        assert!(!sealed.ciphertext.contains("Infraestructura"));
        assert_eq!(
            open_team_name(&key, TEAM, &sealed).unwrap(),
            "Infraestructura"
        );
        assert!(open_team_name(&key, "otro", &sealed).is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let a = AccountKeypair::generate().public();
        let b = AccountKeypair::generate().public();
        assert_eq!(a.fingerprint(), a.fingerprint());
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().split(' ').count(), 8);
    }

    #[test]
    fn public_keys_serialize_as_base64_and_reject_bad_lengths() {
        let key = AccountKeypair::generate().public();
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), key);
        assert!(serde_json::from_str::<PublicKey>("\"AAAA\"").is_err());
    }

    #[test]
    fn the_key_pair_round_trips_through_local_storage() {
        let pair = AccountKeypair::generate();
        let json = serde_json::to_string(&pair).unwrap();
        let back: AccountKeypair = serde_json::from_str(&json).unwrap();
        assert_eq!(back.public(), pair.public());
        assert!(serde_json::from_str::<AccountKeypair>("\"AAAA\"").is_err());
    }

    #[test]
    fn debug_never_shows_the_private_key() {
        let pair = AccountKeypair::generate();
        let shown = format!("{pair:?}");
        assert!(shown.contains(&pair.public().fingerprint()));
        assert!(!shown.contains(&B64.encode(*pair.secret)));
    }
}
