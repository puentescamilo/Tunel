//! Claves de la sincronización. El servidor solo recibe datos cifrados.
//!
//! - De la contraseña maestra (Argon2id) salen, con HKDF, la clave de cifrado, que nunca
//!   sale del equipo, y la clave de acceso, lo único que se envía al servidor.
//! - Una clave de bóveda aleatoria cifra los registros. El servidor la guarda envuelta con
//!   la clave de cifrado para que un equipo nuevo pueda recuperarla.
//! - Los registros viajan con un identificador opaco (HMAC) para que el servidor no sepa
//!   de qué tipo son ni a qué host se refieren.

use super::hlc::Hlc;
use super::record::RecordKey;
use crate::crypto::{self, CryptoError, KEY_LEN, KdfParams, MasterKey, NONCE_LEN, Sealed};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

const INFO_ENCRYPTION: &[u8] = b"tunel-sync-cifrado-v1";
const INFO_AUTH: &[u8] = b"tunel-sync-acceso-v1";
const INFO_RECORD_ID: &[u8] = b"tunel-sync-id-v1";
const AAD_VAULT_KEY: &[u8] = b"tunel-sync-clave-boveda-v1";
const AAD_RECORD: &[u8] = b"tunel-sync-registro-v1:";

/// Mínimos de Argon2id para la cuenta (OWASP: 19 MiB y 2 pasadas). El servidor entrega
/// estos parámetros al iniciar sesión; sin un mínimo podría rebajarlos para luego probar
/// contraseñas a bajo coste con la clave de acceso que recibe.
pub const MIN_KDF_MEMORY_KIB: u32 = 19 * 1024;
pub const MIN_KDF_ITERATIONS: u32 = 2;
pub const MIN_SALT_LEN: usize = 16;
/// Tope del texto cifrado de un registro en base64; se comprueba antes de decodificarlo.
pub const MAX_RECORD_CIPHERTEXT: usize = 1024 * 1024;
/// El texto en claro se rellena hasta un múltiplo de este tamaño para no revelar al
/// servidor la longitud exacta de cada registro.
const PADDING_BLOCK: usize = 256;
/// Un identificador de registro es un HMAC-SHA256 en hexadecimal.
pub const RECORD_ID_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum SyncCryptoError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("registro sincronizado dañado")]
    Corrupt,
    #[error("el registro no corresponde a su identificador")]
    Mismatch,
    #[error("parámetros de cifrado de la cuenta demasiado débiles")]
    WeakKdf,
    #[error("falta, sobra o se repite un fotograma de la sesión compartida")]
    Replayed,
}

pub(super) fn expand(root: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, root);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info, out.as_mut())
        .expect("KEY_LEN es una longitud válida para HKDF-SHA256");
    out
}

/// Claves que salen de la contraseña maestra de la cuenta.
pub struct AccountKeys {
    /// Envuelve la clave de bóveda; nunca sale del equipo.
    encryption: MasterKey,
    /// Lo que el equipo presenta al servidor para identificarse.
    auth: Zeroizing<[u8; KEY_LEN]>,
    /// Contexto de la derivación; se ata a la clave de bóveda envuelta.
    context: Vec<u8>,
}

/// Parámetros de Argon2id y sal aceptables para una cuenta: ni por debajo de los mínimos
/// ni tan altos que derivar la clave agote la memoria.
pub fn kdf_is_strong(salt: &[u8], params: KdfParams) -> bool {
    salt.len() >= MIN_SALT_LEN
        && params.memory_kib >= MIN_KDF_MEMORY_KIB
        && params.iterations >= MIN_KDF_ITERATIONS
        && crate::store::kdf_within_limits(params)
}

impl AccountKeys {
    /// Deriva las claves; rechaza parámetros por debajo de los mínimos o desorbitados.
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        params: KdfParams,
    ) -> Result<Self, SyncCryptoError> {
        if !kdf_is_strong(salt, params) {
            return Err(SyncCryptoError::WeakKdf);
        }
        Ok(Self::derive_unchecked(password, salt, params)?)
    }

    /// Sin comprobar los mínimos: solo para pruebas, con parámetros baratos.
    #[cfg(any(test, feature = "test-kdf"))]
    pub fn derive_for_tests(password: &[u8], salt: &[u8]) -> Self {
        Self::derive_unchecked(password, salt, KdfParams::FAST_FOR_TESTS)
            .expect("los parámetros de prueba son válidos")
    }

    fn derive_unchecked(
        password: &[u8],
        salt: &[u8],
        params: KdfParams,
    ) -> Result<Self, CryptoError> {
        let root = MasterKey::derive(password, salt, params)?;
        let context = [
            salt,
            &params.memory_kib.to_be_bytes(),
            &params.iterations.to_be_bytes(),
            &params.parallelism.to_be_bytes(),
        ]
        .concat();
        Ok(Self {
            encryption: MasterKey::from_bytes(expand(root.as_bytes(), INFO_ENCRYPTION)),
            auth: expand(root.as_bytes(), INFO_AUTH),
            context,
        })
    }

    /// Clave de acceso en base64, tal como se envía al servidor.
    pub fn auth_token(&self) -> Zeroizing<String> {
        Zeroizing::new(B64.encode(self.auth.as_ref()))
    }

    fn wrap_aad(&self) -> Vec<u8> {
        [AAD_VAULT_KEY, &self.context].concat()
    }
}

/// Clave aleatoria que cifra los registros de la bóveda sincronizada.
pub struct VaultKey(MasterKey);

impl Clone for VaultKey {
    fn clone(&self) -> Self {
        Self(MasterKey::from_bytes(Zeroizing::new(*self.0.as_bytes())))
    }
}

/// Solo para guardarla en la configuración local, que va cifrada con la clave maestra.
impl Serialize for VaultKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(B64.encode(self.0.as_bytes()));
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for VaultKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        let bytes = Zeroizing::new(
            B64.decode(text.as_bytes())
                .map_err(serde::de::Error::custom)?,
        );
        if bytes.len() != KEY_LEN {
            return Err(serde::de::Error::custom(
                "clave de bóveda de longitud incorrecta",
            ));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&bytes);
        Ok(Self(MasterKey::from_bytes(key)))
    }
}

/// Datos cifrados tal como los guarda el servidor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedBlob {
    pub(super) fn from_sealed(sealed: &Sealed) -> Self {
        Self {
            nonce: B64.encode(sealed.nonce),
            ciphertext: B64.encode(&sealed.ciphertext),
        }
    }

    pub(super) fn to_sealed(&self) -> Result<Sealed, SyncCryptoError> {
        if self.ciphertext.len() > MAX_RECORD_CIPHERTEXT || self.nonce.len() > NONCE_LEN * 2 {
            return Err(SyncCryptoError::Corrupt);
        }
        let nonce: [u8; NONCE_LEN] = B64
            .decode(&self.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or(SyncCryptoError::Corrupt)?;
        let ciphertext = B64
            .decode(&self.ciphertext)
            .map_err(|_| SyncCryptoError::Corrupt)?;
        Ok(Sealed { nonce, ciphertext })
    }
}

/// Registro cifrado: el servidor solo ve el identificador opaco y el texto cifrado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRecord {
    pub id: String,
    #[serde(flatten)]
    pub blob: SealedBlob,
}

/// Contenido de un registro sincronizado, antes de cifrarlo.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordEnvelope {
    pub key: RecordKey,
    pub hlc: Hlc,
    /// `None` si el registro se borró.
    pub value: Option<Value>,
}

/// El contenido puede llevar contraseñas y claves privadas: no se muestra.
impl std::fmt::Debug for RecordEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordEnvelope")
            .field("key", &self.key)
            .field("hlc", &self.hlc)
            .field("deleted", &self.value.is_none())
            .finish_non_exhaustive()
    }
}

/// Rellena con espacios hasta un múltiplo de `PADDING_BLOCK`; JSON los admite al final.
fn pad(mut plain: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let padded = plain.len().div_ceil(PADDING_BLOCK).max(1) * PADDING_BLOCK;
    plain.resize(padded, b' ');
    plain
}

impl VaultKey {
    pub fn generate() -> Self {
        Self(MasterKey::random())
    }

    pub(super) fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(MasterKey::from_bytes(bytes))
    }

    pub(super) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_bytes()
    }

    /// Cifra la clave con la de la cuenta para guardarla en el servidor.
    pub fn wrap(&self, account: &AccountKeys) -> Result<SealedBlob, CryptoError> {
        let sealed = crypto::seal(&account.encryption, self.0.as_bytes(), &account.wrap_aad())?;
        Ok(SealedBlob::from_sealed(&sealed))
    }

    pub fn unwrap(blob: &SealedBlob, account: &AccountKeys) -> Result<Self, SyncCryptoError> {
        let plain = crypto::open(&account.encryption, &blob.to_sealed()?, &account.wrap_aad())?;
        if plain.len() != KEY_LEN {
            return Err(SyncCryptoError::Corrupt);
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        bytes.copy_from_slice(&plain);
        Ok(Self(MasterKey::from_bytes(bytes)))
    }

    /// Cifra datos sueltos de la bóveda sincronizada, como el manifiesto.
    pub(crate) fn seal_blob(
        &self,
        plain: &[u8],
        aad: &[u8],
    ) -> Result<SealedBlob, SyncCryptoError> {
        Ok(SealedBlob::from_sealed(&crypto::seal(&self.0, plain, aad)?))
    }

    pub(crate) fn open_blob(
        &self,
        blob: &SealedBlob,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SyncCryptoError> {
        Ok(crypto::open(&self.0, &blob.to_sealed()?, aad)?)
    }

    /// Identificador opaco y estable de un registro.
    pub fn record_id(&self, key: &RecordKey) -> String {
        let subkey = expand(self.0.as_bytes(), INFO_RECORD_ID);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(subkey.as_ref())
            .expect("HMAC acepta claves de cualquier longitud");
        mac.update(key.to_string().as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn record_aad(id: &str) -> Vec<u8> {
        [AAD_RECORD, id.as_bytes()].concat()
    }

    pub fn seal_record(&self, envelope: &RecordEnvelope) -> Result<SealedRecord, SyncCryptoError> {
        let id = self.record_id(&envelope.key);
        let plain = pad(Zeroizing::new(
            serde_json::to_vec(envelope).map_err(|_| SyncCryptoError::Corrupt)?,
        ));
        let sealed = crypto::seal(&self.0, &plain, &Self::record_aad(&id))?;
        Ok(SealedRecord {
            id,
            blob: SealedBlob::from_sealed(&sealed),
        })
    }

    /// Descifra un registro y comprueba que su contenido corresponde a su identificador,
    /// para que el servidor no pueda cambiar un registro por otro.
    pub fn open_record(&self, record: &SealedRecord) -> Result<RecordEnvelope, SyncCryptoError> {
        if record.id.len() != RECORD_ID_LEN {
            return Err(SyncCryptoError::Mismatch);
        }
        let plain = crypto::open(
            &self.0,
            &record.blob.to_sealed()?,
            &Self::record_aad(&record.id),
        )?;
        let envelope: RecordEnvelope =
            serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)?;
        if self.record_id(&envelope.key) != record.id {
            return Err(SyncCryptoError::Mismatch);
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::record::RecordKind;
    use uuid::Uuid;

    fn account(password: &str) -> AccountKeys {
        AccountKeys::derive_for_tests(password.as_bytes(), b"sal-de-prueba-16")
    }

    fn envelope(id: &str) -> RecordEnvelope {
        RecordEnvelope {
            key: RecordKey::new(RecordKind::Host, id),
            hlc: Hlc::zero(Uuid::from_u128(1)).tick(1000),
            value: Some(serde_json::json!({"label": "web"})),
        }
    }

    #[test]
    fn encryption_and_auth_keys_are_different_and_deterministic() {
        let a = account("contraseña-larga");
        let b = account("contraseña-larga");
        assert_eq!(a.auth, b.auth);
        assert_eq!(a.encryption.as_bytes(), b.encryption.as_bytes());
        assert_ne!(a.auth.as_ref(), a.encryption.as_bytes());
        assert_ne!(account("otra-contraseña").auth, a.auth);
    }

    #[test]
    fn vault_key_unwraps_only_with_the_right_password() {
        let vault = VaultKey::generate();
        let wrapped = vault.wrap(&account("contraseña-larga")).unwrap();
        let back = VaultKey::unwrap(&wrapped, &account("contraseña-larga")).unwrap();
        assert_eq!(back.0.as_bytes(), vault.0.as_bytes());
        assert!(VaultKey::unwrap(&wrapped, &account("equivocada")).is_err());
    }

    #[test]
    fn record_ids_are_opaque_stable_and_per_vault() {
        let vault = VaultKey::generate();
        let key = RecordKey::new(RecordKind::KnownHost, "produccion.ejemplo.com:22");
        let id = vault.record_id(&key);
        assert_eq!(id, vault.record_id(&key));
        assert_eq!(id.len(), 64);
        assert!(!id.contains("produccion"));
        assert_ne!(id, VaultKey::generate().record_id(&key));
    }

    #[test]
    fn records_round_trip() {
        let vault = VaultKey::generate();
        let original = envelope("a");
        let sealed = vault.seal_record(&original).unwrap();
        assert!(!sealed.blob.ciphertext.contains("web"));
        assert_eq!(vault.open_record(&sealed).unwrap(), original);
    }

    #[test]
    fn swapping_ids_between_records_is_detected() {
        let vault = VaultKey::generate();
        let a = vault.seal_record(&envelope("a")).unwrap();
        let b = vault.seal_record(&envelope("b")).unwrap();
        let swapped = SealedRecord {
            id: b.id,
            blob: a.blob,
        };
        assert!(vault.open_record(&swapped).is_err());
    }

    #[test]
    fn weak_or_absurd_kdf_parameters_are_rejected() {
        let weak = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let absurd = KdfParams {
            memory_kib: u32::MAX,
            ..KdfParams::RECOMMENDED
        };
        let salt = [7u8; MIN_SALT_LEN];
        for (salt, params) in [
            (&salt[..], weak),
            (&salt[..], absurd),
            (&salt[..4], KdfParams::RECOMMENDED),
        ] {
            assert!(matches!(
                AccountKeys::derive(b"contrasena", salt, params),
                Err(SyncCryptoError::WeakKdf)
            ));
        }
    }

    #[test]
    fn wrapped_vault_key_is_bound_to_the_salt() {
        let vault = VaultKey::generate();
        let wrapped = vault.wrap(&account("contraseña-larga")).unwrap();
        let other_salt =
            AccountKeys::derive_for_tests("contraseña-larga".as_bytes(), b"otra-sal-de-16-b");
        assert!(VaultKey::unwrap(&wrapped, &other_salt).is_err());
    }

    #[test]
    fn plaintext_length_is_padded() {
        let vault = VaultKey::generate();
        let short = vault.seal_record(&envelope("a")).unwrap();
        let longer = RecordEnvelope {
            value: Some(serde_json::json!({"label": "un nombre algo más largo"})),
            ..envelope("a")
        };
        let longer = vault.seal_record(&longer).unwrap();
        assert_eq!(short.blob.ciphertext.len(), longer.blob.ciphertext.len());
    }

    #[test]
    fn oversized_or_malformed_records_are_rejected_before_decoding() {
        let vault = VaultKey::generate();
        let sealed = vault.seal_record(&envelope("a")).unwrap();
        let huge = SealedRecord {
            blob: SealedBlob {
                ciphertext: "A".repeat(MAX_RECORD_CIPHERTEXT + 4),
                ..sealed.blob.clone()
            },
            ..sealed.clone()
        };
        let short_id = SealedRecord {
            id: "abc".into(),
            ..sealed
        };
        assert!(vault.open_record(&huge).is_err());
        assert!(matches!(
            vault.open_record(&short_id),
            Err(SyncCryptoError::Mismatch)
        ));
    }

    #[test]
    fn debug_output_hides_record_contents() {
        let shown = format!("{:?}", envelope("a"));
        assert!(!shown.contains("web"), "{shown}");
    }

    #[test]
    fn records_from_another_vault_are_rejected() {
        let sealed = VaultKey::generate().seal_record(&envelope("a")).unwrap();
        assert!(VaultKey::generate().open_record(&sealed).is_err());
    }
}
