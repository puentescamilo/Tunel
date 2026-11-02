//! Desbloqueo con Touch ID o Windows Hello.
//!
//! La clave de la bóveda se guarda junto a ella (`<bóveda>.biometria`) sellada con una clave
//! de envoltura que solo da el sistema tras la huella o el PIN: en macOS, un secreto del
//! llavero; en Windows, lo que sale de firmar un reto con la clave de Windows Hello. Sin ese
//! paso, el archivo no sirve para nada.
//!
//! La primera vez de cada día hay que entrar con la contraseña maestra, para no olvidarla:
//! el archivo guarda el último día en que se usó, firmado con la clave de la bóveda, y la
//! huella solo abre la bóveda ese mismo día.

use crate::crypto::{self, KEY_LEN, MasterKey, NONCE_LEN, SALT_LEN, Sealed};
use crate::store::{StoreError, UnlockedVault, decode, side_path, write_atomically};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::NaiveDate;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) const FILE: &str = ".biometria";
const VERSION: u32 = 1;
const AAD_PREFIX: &[u8] = b"tunel-biometria-v1:";
const DAY_AAD_PREFIX: &[u8] = b"tunel-biometria-dia-v1:";
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
    password_day: DayStamp,
}

/// El último día en que se entró con la contraseña maestra. La etiqueta solo la puede hacer
/// quien tiene la clave de la bóveda: cambiar la fecha a mano no sirve.
#[derive(Serialize, Deserialize)]
struct DayStamp {
    day: String,
    nonce: String,
    tag: String,
}

fn day_aad(id: &str, day: NaiveDate) -> Vec<u8> {
    [
        DAY_AAD_PREFIX,
        id.as_bytes(),
        b":",
        day.to_string().as_bytes(),
    ]
    .concat()
}

impl DayStamp {
    fn new(key: &MasterKey, id: &str, day: NaiveDate) -> Result<Self, StoreError> {
        let sealed = crypto::seal(key, &[], &day_aad(id, day))?;
        Ok(Self {
            day: day.to_string(),
            nonce: B64.encode(sealed.nonce),
            tag: B64.encode(&sealed.ciphertext),
        })
    }

    fn is_for(&self, day: NaiveDate) -> bool {
        self.day == day.to_string()
    }

    fn is_valid(&self, key: &MasterKey, id: &str, day: NaiveDate) -> bool {
        let (Ok(nonce), Ok(ciphertext)) = (decode(&self.nonce), B64.decode(&self.tag)) else {
            return false;
        };
        self.is_for(day)
            && crypto::open(key, &Sealed { nonce, ciphertext }, &day_aad(id, day)).is_ok()
    }
}

fn file_path(vault: &Path) -> PathBuf {
    side_path(vault, FILE)
}

fn read(vault: &Path) -> Result<Option<BiometricFile>, StoreError> {
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
    Ok(Some(file))
}

fn write(vault: &Path, file: &BiometricFile) -> Result<(), StoreError> {
    let json = serde_json::to_vec_pretty(file).map_err(|_| StoreError::Corrupt)?;
    write_atomically(&file_path(vault), &json)
}

impl BiometricFile {
    fn enrollment(&self) -> Result<Enrollment, StoreError> {
        Ok(Enrollment {
            id: self.id.clone(),
            challenge: decode(&self.challenge)?,
        })
    }

    fn sealed(&self) -> Result<Sealed, StoreError> {
        let nonce: [u8; NONCE_LEN] = decode(&self.nonce)?;
        let ciphertext = B64
            .decode(&self.ciphertext)
            .map_err(|_| StoreError::Corrupt)?;
        Ok(Sealed { nonce, ciphertext })
    }
}

/// El alta guardada para la bóveda de `vault`, si la hay.
pub fn enrollment(vault: &Path) -> Result<Option<Enrollment>, StoreError> {
    read(vault)?.map(|file| file.enrollment()).transpose()
}

/// Si `day` ya se entró con la contraseña maestra, así que se puede usar la huella. Solo
/// sirve para la interfaz: la fecha se comprueba de verdad al abrir la bóveda.
pub fn password_entered_on(vault: &Path, day: NaiveDate) -> bool {
    matches!(read(vault), Ok(Some(file)) if file.password_day.is_for(day))
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
    /// `today` cuenta como día en que ya se entró con la contraseña.
    pub fn enable_biometric(
        &self,
        enrollment: &Enrollment,
        wrapping: &WrappingKey,
        today: NaiveDate,
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
            password_day: DayStamp::new(self.key(), &enrollment.id, today)?,
        };
        write(self.path(), &file)
    }

    /// Anota que `today` se entró con la contraseña maestra: desde ahora, y hasta que acabe
    /// el día, sirve la huella. Sin desbloqueo biométrico activado no hace nada.
    pub fn record_password_unlock(&self, today: NaiveDate) -> Result<(), StoreError> {
        let Some(file) = read(self.path())? else {
            return Ok(());
        };
        let password_day = DayStamp::new(self.key(), &file.id, today)?;
        write(
            self.path(),
            &BiometricFile {
                password_day,
                ..file
            },
        )
    }

    /// Abre la bóveda con la clave guardada por [`UnlockedVault::enable_biometric`]. Si
    /// `today` aún no se entró con la contraseña maestra, da [`StoreError::PasswordRequired`];
    /// si `wrapping` no es la buena, el archivo se manipuló o la contraseña cambió después,
    /// un error de cifrado.
    pub fn unlock_biometric(
        path: impl Into<PathBuf>,
        wrapping: &WrappingKey,
        today: NaiveDate,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        let file = read(&path)?.ok_or(StoreError::Corrupt)?;
        if !file.password_day.is_for(today) {
            return Err(StoreError::PasswordRequired);
        }
        let (enrollment, sealed) = (file.enrollment()?, file.sealed()?);
        let wrapping = MasterKey::from_bytes(wrapping.clone());
        Self::unlock_with(path, |salt, _| {
            let opened = crypto::open(&wrapping, &sealed, &enrollment.aad(salt))?;
            if opened.len() != KEY_LEN {
                return Err(StoreError::Corrupt);
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&opened);
            let key = MasterKey::from_bytes(key);
            // Una fecha cambiada a mano no lleva una etiqueta válida.
            if !file.password_day.is_valid(&key, &file.id, today) {
                return Err(StoreError::PasswordRequired);
            }
            Ok(key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, KdfParams};
    use crate::model::Host;

    const PW: &str = "contraseña-larga";
    const DAY: NaiveDate = NaiveDate::from_ymd_opt(2026, 11, 2).unwrap();
    const NEXT_DAY: NaiveDate = NaiveDate::from_ymd_opt(2026, 11, 3).unwrap();

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
            .enable_biometric(&enrollment_made, &wrapping(7), DAY)
            .unwrap();
        drop(vault);

        assert_eq!(enrollment(&path).unwrap(), Some(enrollment_made));
        let raw = std::fs::read_to_string(file_path(&path)).unwrap();
        assert!(!raw.contains("web.example.com"));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(8), DAY),
            Err(StoreError::Crypto(CryptoError::Decryption))
        ));
        let reopened = UnlockedVault::unlock_biometric(&path, &wrapping(7), DAY).unwrap();
        assert_eq!(reopened.data.hosts[0].label, "web");
    }

    #[test]
    fn changing_the_master_password_forgets_the_saved_key() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut vault) = vault_with_host(&dir);
        vault
            .enable_biometric(&Enrollment::new(), &wrapping(7), DAY)
            .unwrap();
        vault.change_password("otra-contraseña-larga").unwrap();
        assert_eq!(enrollment(&path).unwrap(), None);
        drop(vault);
        assert!(UnlockedVault::unlock_biometric(&path, &wrapping(7), DAY).is_err());
        forget(&path).unwrap();
    }

    #[test]
    fn a_tampered_file_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = vault_with_host(&dir);
        vault
            .enable_biometric(&Enrollment::new(), &wrapping(7), DAY)
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
            UnlockedVault::unlock_biometric(&path, &wrapping(7), DAY),
            Err(StoreError::Crypto(_))
        ));
        std::fs::write(file_path(&path), &original).unwrap();
        assert!(UnlockedVault::unlock_biometric(&path, &wrapping(7), DAY).is_ok());
        // Otro nombre válido: el sello está atado al nombre.
        edit(&"ab".repeat(ID_LEN));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(7), DAY),
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

    #[test]
    fn the_first_unlock_of_each_day_needs_the_master_password() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = vault_with_host(&dir);
        vault
            .enable_biometric(&Enrollment::new(), &wrapping(7), DAY)
            .unwrap();
        drop(vault);
        assert!(password_entered_on(&path, DAY));
        assert!(UnlockedVault::unlock_biometric(&path, &wrapping(7), DAY).is_ok());

        assert!(!password_entered_on(&path, NEXT_DAY));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(7), NEXT_DAY),
            Err(StoreError::PasswordRequired)
        ));
        let vault = UnlockedVault::unlock(&path, PW).unwrap();
        vault.record_password_unlock(NEXT_DAY).unwrap();
        drop(vault);
        assert!(password_entered_on(&path, NEXT_DAY));
        assert!(UnlockedVault::unlock_biometric(&path, &wrapping(7), NEXT_DAY).is_ok());
    }

    #[test]
    fn changing_the_day_by_hand_does_not_skip_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = vault_with_host(&dir);
        vault
            .enable_biometric(&Enrollment::new(), &wrapping(7), DAY)
            .unwrap();
        drop(vault);
        let raw = std::fs::read_to_string(file_path(&path)).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&raw).unwrap();
        file["password_day"]["day"] = NEXT_DAY.to_string().into();
        std::fs::write(file_path(&path), file.to_string()).unwrap();

        assert!(password_entered_on(&path, NEXT_DAY));
        assert!(matches!(
            UnlockedVault::unlock_biometric(&path, &wrapping(7), NEXT_DAY),
            Err(StoreError::PasswordRequired)
        ));
    }

    #[test]
    fn recording_a_password_unlock_without_biometrics_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = vault_with_host(&dir);
        vault.record_password_unlock(DAY).unwrap();
        assert!(!is_enabled(&path));
    }
}
