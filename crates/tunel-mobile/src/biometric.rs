//! Desbloqueo con Face ID o Touch ID.
//!
//! Es el mismo archivo que usa el escritorio (`<bóveda>.biometria`): la clave de la bóveda,
//! sellada con una clave de envoltura. Aquí la clave de envoltura la genera el núcleo y la app
//! la guarda en el llavero de iOS protegida con biometría; el llavero solo la devuelve tras
//! Face ID o Touch ID.
//!
//! La primera vez de cada día hay que entrar con la contraseña maestra, para no olvidarla.

use crate::{TunelError, Vault};
use chrono::NaiveDate;
use std::path::Path;
use std::sync::Arc;
use tunel_core::biometric::{self as core, Enrollment, WrappingKey};
use tunel_core::{StoreError, UnlockedVault};
use zeroize::Zeroizing;

/// Lo que la app guarda en el llavero al activar el desbloqueo: `key` con el nombre `id`.
#[derive(uniffi::Record)]
pub struct BiometricKey {
    /// Nombre del elemento del llavero; no es secreto.
    pub id: String,
    pub key: Vec<u8>,
}

/// El día de hoy en la hora local del dispositivo.
pub(crate) fn today() -> NaiveDate {
    chrono::Local::now().date_naive()
}

/// El nombre en el llavero de la clave de la bóveda de `path`, si tiene el desbloqueo
/// activado.
#[uniffi::export]
pub fn biometric_id(path: String) -> Option<String> {
    core::enrollment(Path::new(&path))
        .ok()
        .flatten()
        .map(|enrollment| enrollment.id().to_string())
}

/// Si se puede ofrecer Face ID: está activado y hoy ya se entró con la contraseña maestra.
/// Solo sirve para la interfaz; al abrir se comprueba de verdad.
#[uniffi::export]
pub fn biometric_ready(path: String) -> bool {
    ready_on(Path::new(&path), today())
}

pub(crate) fn ready_on(path: &Path, day: NaiveDate) -> bool {
    core::is_enabled(path) && core::password_entered_on(path, day)
}

#[uniffi::export]
impl Vault {
    /// Abre la bóveda con la clave que dio el llavero tras Face ID o Touch ID.
    #[uniffi::constructor]
    pub fn unlock_biometric(path: String, key: Vec<u8>) -> Result<Arc<Self>, TunelError> {
        unlock_on(Path::new(&path), &key, today()).map(Self::wrap)
    }

    /// Activa el desbloqueo biométrico: devuelve la clave que la app debe guardar en el
    /// llavero. Si ya estaba activado, la clave anterior deja de servir.
    pub fn enable_biometric(&self) -> Result<BiometricKey, TunelError> {
        self.enable_on(today())
    }

    /// Lo quita. El elemento del llavero lo borra la app.
    pub fn disable_biometric(&self) -> Result<(), TunelError> {
        Ok(core::forget(self.lock().path())?)
    }

    pub fn biometric_enabled(&self) -> bool {
        core::is_enabled(self.lock().path())
    }
}

impl Vault {
    pub(crate) fn enable_on(&self, day: NaiveDate) -> Result<BiometricKey, TunelError> {
        let enrollment = Enrollment::new();
        let wrapping = core::random_wrapping_key();
        self.lock().enable_biometric(&enrollment, &wrapping, day)?;
        Ok(BiometricKey {
            id: enrollment.id().to_string(),
            key: wrapping.to_vec(),
        })
    }

    /// Anota que `day` se entró con la contraseña maestra. Si no se puede, mañana se volverá a
    /// pedir: no impide abrir.
    pub(crate) fn record_password_unlock(&self, day: NaiveDate) {
        let _ = self.lock().record_password_unlock(day);
    }
}

pub(crate) fn unlock_on(
    path: &Path,
    key: &[u8],
    day: NaiveDate,
) -> Result<UnlockedVault, TunelError> {
    if !core::is_enabled(path) {
        return Err(TunelError::BiometricInvalid);
    }
    let wrapping: WrappingKey =
        Zeroizing::new(key.try_into().map_err(|_| TunelError::BiometricInvalid)?);
    match UnlockedVault::unlock_biometric(path, &wrapping, day) {
        Ok(vault) => Ok(vault),
        // La clave no abre el sello: el llavero y el archivo ya no casan (otra activación,
        // otra contraseña). No se desactiva solo: lo decide quien usa la app.
        Err(StoreError::Crypto(_)) => Err(TunelError::BiometricInvalid),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::crypto::{KEY_LEN, KdfParams};

    const PASSWORD: &str = "correcta-caballo";
    const DAY: NaiveDate = NaiveDate::from_ymd_opt(2026, 11, 12).unwrap();
    const NEXT_DAY: NaiveDate = NaiveDate::from_ymd_opt(2026, 11, 13).unwrap();

    fn new_vault() -> (tempfile::TempDir, std::path::PathBuf, Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let vault = UnlockedVault::create(&path, PASSWORD, KdfParams::FAST_FOR_TESTS).unwrap();
        (dir, path, Vault::wrap(vault))
    }

    #[test]
    fn the_key_from_enabling_opens_the_vault_the_same_day() {
        let (_dir, path, vault) = new_vault();
        let saved = vault.enable_on(DAY).unwrap();
        drop(vault);

        let reopened = unlock_on(&path, &saved.key, DAY);

        assert!(reopened.is_ok());
        assert_eq!(saved.key.len(), KEY_LEN);
        assert_eq!(biometric_id(path.to_string_lossy().into()), Some(saved.id));
    }

    #[test]
    fn the_next_day_asks_for_the_password_first() {
        let (_dir, path, vault) = new_vault();
        let saved = vault.enable_on(DAY).unwrap();
        drop(vault);

        assert!(!ready_on(&path, NEXT_DAY));
        let error = unlock_on(&path, &saved.key, NEXT_DAY).err().unwrap();
        assert!(matches!(error, TunelError::PasswordRequired));
    }

    #[test]
    fn entering_the_password_allows_face_id_again_that_day() {
        let (_dir, path, vault) = new_vault();
        let saved = vault.enable_on(DAY).unwrap();

        vault.record_password_unlock(NEXT_DAY);
        drop(vault);

        assert!(ready_on(&path, NEXT_DAY));
        assert!(unlock_on(&path, &saved.key, NEXT_DAY).is_ok());
    }

    #[test]
    fn unlocking_with_the_password_records_the_day() {
        let (_dir, path, vault) = new_vault();
        vault.enable_biometric().unwrap();
        drop(vault);
        // Como si se hubiera activado ayer: hoy aún no se ha entrado con la contraseña.
        let day_before = today().pred_opt().unwrap();
        let stale = Vault::wrap(UnlockedVault::unlock(&path, PASSWORD).unwrap());
        stale.lock().record_password_unlock(day_before).unwrap();
        drop(stale);
        assert!(!biometric_ready(path.to_string_lossy().into()));

        let _vault = Vault::unlock(path.to_string_lossy().into(), PASSWORD.into()).unwrap();

        assert!(biometric_ready(path.to_string_lossy().into()));
    }

    #[test]
    fn a_wrong_or_malformed_key_is_reported_as_invalid() {
        let (_dir, path, vault) = new_vault();
        vault.enable_on(DAY).unwrap();
        drop(vault);

        let wrong = unlock_on(&path, &[7; KEY_LEN], DAY).err().unwrap();
        let short = unlock_on(&path, &[7; 4], DAY).err().unwrap();

        assert!(matches!(wrong, TunelError::BiometricInvalid));
        assert!(matches!(short, TunelError::BiometricInvalid));
    }

    #[test]
    fn enabling_again_invalidates_the_previous_key() {
        let (_dir, path, vault) = new_vault();
        let first = vault.enable_on(DAY).unwrap();
        let second = vault.enable_on(DAY).unwrap();
        drop(vault);

        assert_ne!(first.id, second.id);
        assert!(unlock_on(&path, &first.key, DAY).is_err());
        assert!(unlock_on(&path, &second.key, DAY).is_ok());
    }

    #[test]
    fn disabling_removes_it() {
        let (_dir, path, vault) = new_vault();
        let saved = vault.enable_on(DAY).unwrap();

        vault.disable_biometric().unwrap();

        assert!(!vault.biometric_enabled());
        assert_eq!(biometric_id(path.to_string_lossy().into()), None);
        drop(vault);
        let error = unlock_on(&path, &saved.key, DAY).err().unwrap();
        assert!(matches!(error, TunelError::BiometricInvalid));
    }
}
