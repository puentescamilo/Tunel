//! Persistencia de la bóveda en un único archivo JSON cifrado.

use crate::crypto::{self, CryptoError, KdfParams, MasterKey, NONCE_LEN, SALT_LEN, Sealed};
use crate::sync::SyncLocal;
use crate::vault::VaultData;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

const FORMAT_VERSION: u32 = 1;
const AAD: &[u8] = b"tunel-vault-v1";
const SYNC_AAD: &[u8] = b"tunel-sync-local-v1";
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no se pudo leer o escribir la bóveda: {0}")]
    Io(#[from] std::io::Error),
    #[error("el archivo de bóveda está dañado")]
    Corrupt,
    #[error("versión de bóveda no soportada: {0}")]
    UnsupportedVersion(u32),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("la contraseña maestra debe tener al menos {MIN_PASSWORD_LEN} caracteres")]
    WeakPassword,
    #[error("ya existe una bóveda en {0}")]
    AlreadyExists(PathBuf),
    #[error("la bóveda ya está abierta en otra ventana de Túnel")]
    Locked,
}

/// Configuración de sincronización cifrada, en un archivo junto a la bóveda.
#[derive(Serialize, Deserialize)]
struct SyncFile {
    version: u32,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Bóveda desbloqueada: contenido en claro y clave derivada para volver a guardarlo.
pub struct UnlockedVault {
    path: PathBuf,
    /// Cerrojo exclusivo: impide que dos instancias guarden cambios a la vez y se pisen.
    _lock: std::fs::File,
    key: MasterKey,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    pub data: VaultData,
}

/// Límites para los parámetros leídos del archivo: evitan que uno manipulado agote la memoria.
const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_KDF_ITERATIONS: u32 = 10;
const MAX_KDF_PARALLELISM: u32 = 8;

pub(crate) fn kdf_within_limits(kdf: KdfParams) -> bool {
    kdf.memory_kib <= MAX_KDF_MEMORY_KIB
        && (1..=MAX_KDF_ITERATIONS).contains(&kdf.iterations)
        && (1..=MAX_KDF_PARALLELISM).contains(&kdf.parallelism)
}

fn validate_password(password: &str) -> Result<(), StoreError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(StoreError::WeakPassword);
    }
    Ok(())
}

fn decode<const N: usize>(text: &str) -> Result<[u8; N], StoreError> {
    let bytes = B64.decode(text).map_err(|_| StoreError::Corrupt)?;
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    path.with_file_name(name)
}

fn sync_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".sync");
    path.with_file_name(name)
}

fn acquire_lock(path: &Path) -> Result<std::fs::File, StoreError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(path))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(StoreError::Locked),
        Err(std::fs::TryLockError::Error(e)) => Err(StoreError::Io(e)),
    }
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        self.data.wipe_secrets();
    }
}

impl UnlockedVault {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    pub fn create(
        path: impl Into<PathBuf>,
        password: &str,
        kdf: KdfParams,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        if path.exists() {
            return Err(StoreError::AlreadyExists(path));
        }
        validate_password(password)?;
        let lock = acquire_lock(&path)?;
        let salt = crypto::random_salt();
        let key = MasterKey::derive(password.as_bytes(), &salt, kdf)?;
        let vault = Self {
            path,
            _lock: lock,
            key,
            salt,
            kdf,
            data: VaultData::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: impl Into<PathBuf>, password: &str) -> Result<Self, StoreError> {
        let path = path.into();
        let lock = acquire_lock(&path)?;
        let raw = std::fs::read(&path)?;
        let file: VaultFile = serde_json::from_slice(&raw).map_err(|_| StoreError::Corrupt)?;
        if file.version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion(file.version));
        }
        if !kdf_within_limits(file.kdf) {
            return Err(StoreError::Corrupt);
        }
        let salt: [u8; SALT_LEN] = decode(&file.salt)?;
        let nonce: [u8; NONCE_LEN] = decode(&file.nonce)?;
        let ciphertext = B64
            .decode(&file.ciphertext)
            .map_err(|_| StoreError::Corrupt)?;
        let key = MasterKey::derive(password.as_bytes(), &salt, file.kdf)?;
        let plaintext = crypto::open(&key, &Sealed { nonce, ciphertext }, AAD)?;
        let data = serde_json::from_slice(&plaintext).map_err(|_| StoreError::Corrupt)?;
        Ok(Self {
            path,
            _lock: lock,
            key,
            salt,
            kdf: file.kdf,
            data,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sustituye el contenido y lo guarda; si falla la escritura, se conserva el anterior.
    pub fn commit(&mut self, data: VaultData) -> Result<(), StoreError> {
        let previous = std::mem::replace(&mut self.data, data);
        self.save().inspect_err(|_| self.data = previous.clone())
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<(), StoreError> {
        validate_password(new_password)?;
        let salt = crypto::random_salt();
        let key = MasterKey::derive(new_password.as_bytes(), &salt, self.kdf)?;
        // Una configuración de sincronización ilegible no impide cambiar la contraseña:
        // se pierde (habrá que volver a unir el equipo), pero la bóveda es lo importante.
        let sync = self.load_sync().unwrap_or_else(|e| {
            eprintln!("aviso: se descarta la configuración de sincronización ilegible: {e}");
            None
        });
        // Guardar primero con la clave nueva; solo si funciona se adopta en memoria, y desde
        // ese momento, para que memoria y disco usen siempre la misma clave.
        write_sealed(&self.path, &self.data, &key, &salt, self.kdf)?;
        self.key = key;
        self.salt = salt;
        match &sync {
            Some(sync) => write_sync(&self.path, sync, &self.key),
            None => self.delete_sync(),
        }
    }

    /// Configuración de sincronización de este equipo, si está unido a una cuenta.
    pub fn load_sync(&self) -> Result<Option<SyncLocal>, StoreError> {
        let raw = match std::fs::read(sync_path(&self.path)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let file: SyncFile = serde_json::from_slice(&raw).map_err(|_| StoreError::Corrupt)?;
        if file.version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion(file.version));
        }
        let nonce: [u8; NONCE_LEN] = decode(&file.nonce)?;
        let ciphertext = B64
            .decode(&file.ciphertext)
            .map_err(|_| StoreError::Corrupt)?;
        let plaintext = crypto::open(&self.key, &Sealed { nonce, ciphertext }, SYNC_AAD)?;
        serde_json::from_slice(&plaintext)
            .map(Some)
            .map_err(|_| StoreError::Corrupt)
    }

    pub fn save_sync(&self, sync: &SyncLocal) -> Result<(), StoreError> {
        write_sync(&self.path, sync, &self.key)
    }

    /// Desvincula el equipo de la cuenta; la bóveda local no cambia.
    pub fn delete_sync(&self) -> Result<(), StoreError> {
        match std::fs::remove_file(sync_path(&self.path)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    fn save(&self) -> Result<(), StoreError> {
        write_sealed(&self.path, &self.data, &self.key, &self.salt, self.kdf)
    }
}

fn write_sealed(
    path: &Path,
    data: &VaultData,
    key: &MasterKey,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<(), StoreError> {
    {
        let plaintext =
            zeroize::Zeroizing::new(serde_json::to_vec(data).map_err(|_| StoreError::Corrupt)?);
        let sealed = crypto::seal(key, &plaintext, AAD)?;
        let file = VaultFile {
            version: FORMAT_VERSION,
            kdf,
            salt: B64.encode(salt),
            nonce: B64.encode(sealed.nonce),
            ciphertext: B64.encode(&sealed.ciphertext),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(|_| StoreError::Corrupt)?;
        write_atomically(path, &json)
    }
}

fn write_sync(path: &Path, sync: &SyncLocal, key: &MasterKey) -> Result<(), StoreError> {
    let plaintext =
        zeroize::Zeroizing::new(serde_json::to_vec(sync).map_err(|_| StoreError::Corrupt)?);
    let sealed = crypto::seal(key, &plaintext, SYNC_AAD)?;
    let file = SyncFile {
        version: FORMAT_VERSION,
        nonce: B64.encode(sealed.nonce),
        ciphertext: B64.encode(&sealed.ciphertext),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|_| StoreError::Corrupt)?;
    write_atomically(&sync_path(path), &json)
}

/// Escribe en un archivo temporal privado, lo sincroniza a disco y lo renombra,
/// para que un corte de luz no deje la bóveda vacía o a medias.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".vault-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    restrict_permissions(tmp.path())?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| StoreError::Io(e.error))?;
    sync_dir(dir);
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
        // El renombrado ya se hizo; solo se pierde la garantía ante un corte inmediato.
        eprintln!("aviso: no se pudo sincronizar {}: {e}", dir.display());
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Host;

    const PW: &str = "contraseña-larga";

    fn vault_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("vault.json")
    }

    #[test]
    fn create_commit_and_unlock_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        let data = vault.data.with_host(Host::new("web", "web.example.com"));
        vault.commit(data).unwrap();
        drop(vault);

        let reopened = UnlockedVault::unlock(vault_path(&dir), PW).unwrap();
        assert_eq!(reopened.data.hosts[0].label, "web");
    }

    #[test]
    fn file_on_disk_does_not_contain_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        vault
            .commit(vault.data.with_host(Host::new("secreto-visible", "x")))
            .unwrap();
        let raw = std::fs::read_to_string(vault_path(&dir)).unwrap();
        assert!(!raw.contains("secreto-visible"));
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        let err = UnlockedVault::unlock(vault_path(&dir), "otra-contraseña")
            .err()
            .unwrap();
        assert!(matches!(err, StoreError::Crypto(CryptoError::Decryption)));
    }

    #[test]
    fn create_rejects_short_password() {
        let dir = tempfile::tempdir().unwrap();
        let err = UnlockedVault::create(vault_path(&dir), "corta", KdfParams::FAST_FOR_TESTS)
            .err()
            .unwrap();
        assert!(matches!(err, StoreError::WeakPassword));
    }

    #[test]
    fn create_refuses_to_overwrite_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        let err = UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS)
            .err()
            .unwrap();
        assert!(matches!(err, StoreError::AlreadyExists(_)));
    }

    #[test]
    fn change_password_requires_new_password_to_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        vault.change_password("nueva-contraseña").unwrap();
        drop(vault);
        assert!(UnlockedVault::unlock(vault_path(&dir), PW).is_err());
        assert!(UnlockedVault::unlock(vault_path(&dir), "nueva-contraseña").is_ok());
    }

    fn sync_config() -> SyncLocal {
        SyncLocal {
            server: "https://tunel.ejemplo.com".into(),
            email: "ana@ejemplo.com".into(),
            auth: zeroize::Zeroizing::new("clave".into()),
            vault_key: crate::sync::VaultKey::generate(),
            token: None,
            state: crate::sync::SyncState::new(uuid::Uuid::from_u128(1)),
            keypair: None,
        }
    }

    #[test]
    fn sync_config_is_saved_encrypted_and_survives_password_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        assert!(vault.load_sync().unwrap().is_none());
        vault.save_sync(&sync_config()).unwrap();
        let raw = std::fs::read_to_string(sync_path(&vault_path(&dir))).unwrap();
        assert!(!raw.contains("ana@ejemplo.com"));

        vault.change_password("nueva-contraseña").unwrap();
        drop(vault);
        let vault = UnlockedVault::unlock(vault_path(&dir), "nueva-contraseña").unwrap();
        assert_eq!(vault.load_sync().unwrap().unwrap().email, "ana@ejemplo.com");

        vault.delete_sync().unwrap();
        assert!(vault.load_sync().unwrap().is_none());
        vault.delete_sync().unwrap();
    }

    #[test]
    fn a_corrupt_sync_config_does_not_block_a_password_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        std::fs::write(sync_path(&vault_path(&dir)), b"{basura").unwrap();
        vault.change_password("nueva-contraseña").unwrap();
        assert!(vault.load_sync().unwrap().is_none());
    }

    #[test]
    fn unlock_reports_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(vault_path(&dir), b"{no es json").unwrap();
        assert!(matches!(
            UnlockedVault::unlock(vault_path(&dir), PW).err().unwrap(),
            StoreError::Corrupt
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_private_to_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        let mode = std::fs::metadata(vault_path(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    fn rewrite_header(path: &std::path::Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        edit(&mut json);
        std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    }

    #[test]
    fn unlock_rejects_absurd_kdf_params_before_deriving() {
        let dir = tempfile::tempdir().unwrap();
        UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        rewrite_header(&vault_path(&dir), |j| {
            j["kdf"]["memory_kib"] = serde_json::json!(u32::MAX)
        });
        assert!(matches!(
            UnlockedVault::unlock(vault_path(&dir), PW).err().unwrap(),
            StoreError::Corrupt
        ));
    }

    #[test]
    fn save_leaves_no_temporary_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        vault
            .commit(vault.data.with_host(Host::new("a", "b")))
            .unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| !n.to_string_lossy().ends_with(".lock"))
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("vault.json")]);
    }

    #[test]
    fn second_instance_cannot_open_the_same_vault() {
        let dir = tempfile::tempdir().unwrap();
        let first = UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        let err = UnlockedVault::unlock(vault_path(&dir), PW).err().unwrap();
        assert!(matches!(err, StoreError::Locked), "{err}");
        drop(first);
        assert!(UnlockedVault::unlock(vault_path(&dir), PW).is_ok());
    }
}
