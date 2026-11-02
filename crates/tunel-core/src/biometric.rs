//! Desbloqueo con Touch ID o Windows Hello.
//!
//! La clave de la bóveda se guarda junto a ella (`<bóveda>.biometria`) sellada con una clave
//! de envoltura que solo da el sistema tras la huella o el PIN: en macOS, un secreto del
//! llavero; en Windows, lo que sale de firmar un reto con la clave de Windows Hello. Sin ese
//! paso, el archivo no sirve para nada.

use crate::crypto::{self, KEY_LEN, MasterKey, NONCE_LEN, SALT_LEN, Sealed};
use crate::store::{StoreError, UnlockedVault, decode, side_path, write_atomically};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const FILE: &str = ".biometria";
const VERSION: u32 = 1;
const AAD_PREFIX: &[u8] = b"tunel-biometria-v1:";
const ID_LEN: usize = 16;
pub const CHALLENGE_LEN: usize = 32;

/// Clave de envoltura que entrega el sistema tras la huella o el PIN.
pub type WrappingKey = Zeroizing<[u8; KEY_LEN]>;

/// Una clave de envoltura nueva, para el sistema que la guarda tal cual (el llavero de macOS).
pub fn random_wrapping_key() -> WrappingKey {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rng().fill_bytes(key.as_mut());
    key
}

/// Si la bóveda de `vault` tiene activado el desbloqueo biométrico.
pub fn is_enabled(vault: &Path) -> bool {
    file_path(vault).is_file()
}

/// Lo que el sistema necesita para dar la clave de envoltura: un nombre para su llavero y
/// el reto que firma Windows Hello. Ninguno de los dos es secreto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    id: String,
    challenge: [u8; CHALLENGE_LEN],
}

impl Enrollment {
    pub fn new() -> Self {
        let mut id = [0u8; ID_LEN];
        let mut challenge = [0u8; CHALLENGE_LEN];
        rand::rng().fill_bytes(&mut id);
        rand::rng().fill_bytes(&mut challenge);
        Self {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            challenge,
        }
    }

    /// Solo dígitos hexadecimales en minúscula: sirve tal cual como nombre en el llavero.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn challenge(&self) -> &[u8; CHALLENGE_LEN] {
        &self.challenge
    }

    /// Todo lo del archivo y la sal de la bóveda: si algo cambia, el sello no se abre.
    fn aad(&self, vault_salt: &[u8; SALT_LEN]) -> Vec<u8> {
        [
            AAD_PREFIX,
            &VERSION.to_be_bytes(),
            self.id.as_bytes(),
            &self.challenge,
            vault_salt,
        ]
        .concat()
    }
}

impl Default for Enrollment {
    fn default() -> Self {
        Self::new()
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN * 2 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Serialize, Deserialize)]
struct BiometricFile {
    version: u32,
    id: String,
    challenge: String,
    nonce: String,
    ciphertext: String,
}

fn file_path(vault: &Path) -> PathBuf {
    side_path(vault, FILE)
}

fn read(vault: &Path) -> Result<Option<(Enrollment, Sealed)>, StoreError> {
    let raw = match std::fs::read(file_path(vault)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file: BiometricFile = serde_json::from_slice(&raw).map_err(|_| StoreError::Corrupt)?;
    if file.version != VERSION {
        return Err(StoreError::UnsupportedVersion(file.version));
    }
    if !valid_id(&file.id) {
        return Err(StoreError::Corrupt);
    }
    let enrollment = Enrollment {
        id: file.id,
        challenge: decode(&file.challenge)?,
    };
    let nonce: [u8; NONCE_LEN] = decode(&file.nonce)?;
    let ciphertext = B64
        .decode(&file.ciphertext)
        .map_err(|_| StoreError::Corrupt)?;
    Ok(Some((enrollment, Sealed { nonce, ciphertext })))
}

/// El alta guardada para la bóveda de `vault`, si la hay.
pub fn enrollment(vault: &Path) -> Result<Option<Enrollment>, StoreError> {
    Ok(read(vault)?.map(|(enrollment, _)| enrollment))
}

/// Quita el desbloqueo biométrico de la bóveda. El secreto que guarda el sistema lo borra
/// quien lo creó.
pub fn forget(vault: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(file_path(vault)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

impl UnlockedVault {
    /// Guarda la clave de la bóveda sellada con `wrapping`, para abrirla sin contraseña.
    pub fn enable_biometric(
        &self,
        enrollment: &Enrollment,
        wrapping: &WrappingKey,
    ) -> Result<(), StoreError> {
        let wrapping = MasterKey::from_bytes(wrapping.clone());
        let aad = enrollment.aad(self.salt());
        let sealed = crypto::seal(&wrapping, self.key().as_bytes(), &aad)?;
        let file = BiometricFile {
            version: VERSION,
            id: enrollment.id.clone(),
            challenge: B64.encode(enrollment.challenge),
            nonce: B64.encode(sealed.nonce),
            ciphertext: B64.encode(&sealed.ciphertext),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(|_| StoreError::Corrupt)?;
        write_atomically(&file_path(self.path()), &json)
    }

    /// Abre la bóveda con la clave guardada por [`UnlockedVault::enable_biometric`]. Si
    /// `wrapping` no es la buena, el archivo se manipuló o la contraseña cambió después, da
    /// un error de cifrado.
    pub fn unlock_biometric(
        path: impl Into<PathBuf>,
        wrapping: &WrappingKey,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        let (enrollment, sealed) = read(&path)?.ok_or(StoreError::Corrupt)?;
        let wrapping = MasterKey::from_bytes(wrapping.clone());
        Self::unlock_with(path, |salt, _| {
            let opened = crypto::open(&wrapping, &sealed, &enrollment.aad(salt))?;
            if opened.len() != KEY_LEN {
                return Err(StoreError::Corrupt);
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&opened);
            Ok(MasterKey::from_bytes(key))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, KdfParams};
    use crate::model::Host;

    const PW: &str = "contraseña-larga";

    fn wrapping(byte: u8) -> WrappingKey {
        Zeroizing::new([byte; KEY_LEN])
    }

    fn vault_with_host(dir: &tempfile::TempDir) -> (PathBuf, UnlockedVault) {
        let path = dir.path().join("vault.json");
        let mut vault = UnlockedVault::create(&path, PW, KdfParams::FAST_FOR_TESTS).unwrap();
        vault
            .commit(vault.data.with_host(Host::new("web", "web.example.com")))
            .unwrap();
        (path, vault)
    }

    #[test]
    fn the_saved_key_opens_the_vault_only_with_the_same_wrapping_key() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = vault_with_host(&dir);
        assert_eq!(enrollment(&path).unwrap(), None);
        let enrollment_made = Enrollment::new();
        vault
            .enable_biometric(&enrollment_made, &wrapping(7))
            .unwrap();
        drop(vault);

        assert_eq!(enrollment(&path).unwrap(), Some(enrollment_made));
        let raw = std::fs::read_to_string(file_path(&path)).unwrap();
        assert!(!raw.contains("web.example.com"));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(8)),
            Err(StoreError::Crypto(CryptoError::Decryption))
        ));
        let reopened = UnlockedVault::unlock_biometric(&path, &wrapping(7)).unwrap();
        assert_eq!(reopened.data.hosts[0].label, "web");
    }

    #[test]
    fn changing_the_master_password_forgets_the_saved_key() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut vault) = vault_with_host(&dir);
        vault
            .enable_biometric(&Enrollment::new(), &wrapping(7))
            .unwrap();
        vault.change_password("otra-contraseña-larga").unwrap();
        assert_eq!(enrollment(&path).unwrap(), None);
        drop(vault);
        assert!(UnlockedVault::unlock_biometric(&path, &wrapping(7)).is_err());
        forget(&path).unwrap();
    }

    #[test]
    fn a_tampered_file_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = vault_with_host(&dir);
        vault
            .enable_biometric(&Enrollment::new(), &wrapping(7))
            .unwrap();
        drop(vault);
        let edit_field = |field: &str, value: &str| {
            let raw = std::fs::read_to_string(file_path(&path)).unwrap();
            let mut file: serde_json::Value = serde_json::from_str(&raw).unwrap();
            file[field] = value.into();
            std::fs::write(file_path(&path), file.to_string()).unwrap();
        };
        let edit = |id: &str| edit_field("id", id);
        let original = std::fs::read(file_path(&path)).unwrap();
        // El reto también está atado: con otro, Windows Hello firmaría lo que eligiera otro.
        edit_field("challenge", &B64.encode([9u8; CHALLENGE_LEN]));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(7)),
            Err(StoreError::Crypto(_))
        ));
        std::fs::write(file_path(&path), &original).unwrap();
        assert!(UnlockedVault::unlock_biometric(&path, &wrapping(7)).is_ok());
        // Otro nombre válido: el sello está atado al nombre.
        edit(&"ab".repeat(ID_LEN));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(7)),
            Err(StoreError::Crypto(_))
        ));
        // Un nombre que no es hexadecimal no llega al llavero.
        edit("x; rm -rf /");
        assert!(matches!(enrollment(&path), Err(StoreError::Corrupt)));
    }

    #[test]
    fn each_enrollment_has_its_own_hex_name_and_challenge() {
        let (a, b) = (Enrollment::new(), Enrollment::new());
        assert!(valid_id(a.id()));
        assert_ne!(a.id(), b.id());
        assert_ne!(a.challenge(), b.challenge());
    }
}
