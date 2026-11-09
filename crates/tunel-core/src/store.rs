//! Persistencia de la bóveda en un único archivo JSON cifrado.

use crate::crypto::{self, CryptoError, KdfParams, MasterKey, NONCE_LEN, SALT_LEN, Sealed};
use crate::history::CommandHistory;
use crate::sync::SyncLocal;
use crate::vault::VaultData;
use crate::vaultwarden::VaultwardenLocal;
use crate::workspace::Workspace;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

const FORMAT_VERSION: u32 = 1;
const AAD: &[u8] = b"tunel-vault-v1";
const SYNC_AAD: &[u8] = b"tunel-sync-local-v1";
const WORKSPACE_AAD: &[u8] = b"tunel-workspace-v1";
const HISTORY_AAD: &[u8] = b"tunel-history-v1";
const VAULTWARDEN_AAD: &[u8] = b"tunel-vaultwarden-v1";
/// Archivos cifrados junto a la bóveda, solo de este equipo: sufijo y datos asociados.
const SYNC_FILE: (&str, &[u8]) = (".sync", SYNC_AAD);
const WORKSPACE_FILE: (&str, &[u8]) = (".pestanas", WORKSPACE_AAD);
const HISTORY_FILE: (&str, &[u8]) = (".historial", HISTORY_AAD);
const VAULTWARDEN_FILE: (&str, &[u8]) = (".vaultwarden", VAULTWARDEN_AAD);
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
    #[error("la primera vez de cada día se entra con la contraseña maestra")]
    PasswordRequired,
}

/// Un archivo cifrado junto a la bóveda: la configuración de sincronización o las
/// pestañas abiertas.
#[derive(Serialize, Deserialize)]
struct SideFile {
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

/// Comprueba si una contraseña es la maestra de una bóveda (ver
/// [`UnlockedVault::password_check`]). Deriva la clave con Argon2id: tarda.
pub struct PasswordCheck {
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    key: zeroize::Zeroizing<[u8; crypto::KEY_LEN]>,
}

impl PasswordCheck {
    pub fn matches(&self, password: &str) -> bool {
        MasterKey::derive(password.as_bytes(), &self.salt, self.kdf)
            .is_ok_and(|key| key.as_bytes() == &*self.key)
    }
}

fn validate_password(password: &str) -> Result<(), StoreError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(StoreError::WeakPassword);
    }
    Ok(())
}

pub(crate) fn decode<const N: usize>(text: &str) -> Result<[u8; N], StoreError> {
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

/// Una bóveda de una versión anterior pudo quedar, con sus archivos laterales, con los permisos
/// de su carpeta: se corrigen al abrirla.
fn restrict_existing(vault: &Path) {
    let side = [
        SYNC_FILE.0,
        WORKSPACE_FILE.0,
        HISTORY_FILE.0,
        VAULTWARDEN_FILE.0,
        crate::biometric::FILE,
    ];
    let paths = [vault.to_path_buf(), lock_path(vault)]
        .into_iter()
        .chain(side.map(|s| side_path(vault, s)));
    for path in paths.filter(|p| p.exists()) {
        if let Err(e) = restrict_permissions(&path) {
            eprintln!(
                "aviso: no se pudieron restringir los permisos de {}: {e}",
                path.display()
            );
        }
    }
}

pub(crate) fn side_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
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
        Self::unlock_with(path.into(), |salt, kdf| {
            Ok(MasterKey::derive(password.as_bytes(), salt, kdf)?)
        })
    }

    /// Abre la bóveda con la clave que da `key` a partir de su sal y parámetros: la que
    /// se deriva de la contraseña o la guardada para el desbloqueo biométrico.
    pub(crate) fn unlock_with(
        path: PathBuf,
        key: impl FnOnce(&[u8; SALT_LEN], KdfParams) -> Result<MasterKey, StoreError>,
    ) -> Result<Self, StoreError> {
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
        let key = key(&salt, file.kdf)?;
        let plaintext = crypto::open(&key, &Sealed { nonce, ciphertext }, AAD)?;
        let data = serde_json::from_slice(&plaintext).map_err(|_| StoreError::Corrupt)?;
        restrict_existing(&path);
        Ok(Self {
            path,
            _lock: lock,
            key,
            salt,
            kdf: file.kdf,
            data,
        })
    }

    pub(crate) fn key(&self) -> &MasterKey {
        &self.key
    }

    pub(crate) fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lo necesario para comprobar más tarde, fuera de este hilo, si una contraseña es la
    /// maestra de esta bóveda.
    pub fn password_check(&self) -> PasswordCheck {
        PasswordCheck {
            salt: self.salt,
            kdf: self.kdf,
            key: zeroize::Zeroizing::new(*self.key.as_bytes()),
        }
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
        let workspace = self.load_workspace().unwrap_or(None);
        let history = self.load_history().unwrap_or(None);
        let vaultwarden = self.load_vaultwarden().unwrap_or(None);
        // Guardar primero con la clave nueva; solo si funciona se adopta en memoria, y desde
        // ese momento, para que memoria y disco usen siempre la misma clave.
        write_sealed(&self.path, &self.data, &key, &salt, self.kdf)?;
        self.key = key;
        self.salt = salt;
        // El desbloqueo biométrico guarda la clave anterior: deja de servir.
        let _ = crate::biometric::forget(&self.path);
        // Las pestañas no son importantes: si no se pueden volver a cifrar, se pierden.
        let _ = match &workspace {
            Some(workspace) => self.save_workspace(workspace),
            None => self.delete_workspace(),
        };
        // La cuenta de Vaultwarden se puede volver a conectar: si falla, se avisa.
        if let Err(e) = match &vaultwarden {
            Some(vaultwarden) => self.save_vaultwarden(vaultwarden),
            None => self.delete_vaultwarden(),
        } {
            eprintln!("aviso: no se pudo volver a cifrar la cuenta de Vaultwarden: {e}");
        }
        // El historial tampoco, pero se avisa: el anterior queda cifrado con la otra clave.
        if let Err(e) = match &history {
            Some(history) => self.save_history(history),
            None => self.delete_history(),
        } {
            eprintln!("aviso: no se pudo volver a cifrar el historial de comandos: {e}");
        }
        match &sync {
            Some(sync) => self.save_sync(sync),
            None => self.delete_sync(),
        }
    }

    /// Configuración de sincronización de este equipo, si está unido a una cuenta.
    pub fn load_sync(&self) -> Result<Option<SyncLocal>, StoreError> {
        self.read_side(SYNC_FILE)
    }

    pub fn save_sync(&self, sync: &SyncLocal) -> Result<(), StoreError> {
        self.write_side(SYNC_FILE, sync)
    }

    /// Desvincula el equipo de la cuenta; la bóveda local no cambia.
    pub fn delete_sync(&self) -> Result<(), StoreError> {
        self.delete_side(SYNC_FILE)
    }

    /// Pestañas que quedaron abiertas en este equipo, si se guardaron.
    pub fn load_workspace(&self) -> Result<Option<Workspace>, StoreError> {
        self.read_side(WORKSPACE_FILE)
    }

    pub fn save_workspace(&self, workspace: &Workspace) -> Result<(), StoreError> {
        self.write_side(WORKSPACE_FILE, workspace)
    }

    pub fn delete_workspace(&self) -> Result<(), StoreError> {
        self.delete_side(WORKSPACE_FILE)
    }

    /// Comandos ejecutados en este equipo, para el autocompletado.
    pub fn load_history(&self) -> Result<Option<CommandHistory>, StoreError> {
        self.read_side(HISTORY_FILE)
    }

    pub fn save_history(&self, history: &CommandHistory) -> Result<(), StoreError> {
        self.write_side(HISTORY_FILE, history)
    }

    pub fn delete_history(&self) -> Result<(), StoreError> {
        self.delete_side(HISTORY_FILE)
    }

    /// Cuenta de Vaultwarden de este equipo, si se conectó una.
    pub fn load_vaultwarden(&self) -> Result<Option<VaultwardenLocal>, StoreError> {
        self.read_side(VAULTWARDEN_FILE)
    }

    pub fn save_vaultwarden(&self, local: &VaultwardenLocal) -> Result<(), StoreError> {
        self.write_side(VAULTWARDEN_FILE, local)
    }

    /// Desconecta Vaultwarden: se borran la sesión y la copia de los secretos.
    pub fn delete_vaultwarden(&self) -> Result<(), StoreError> {
        self.delete_side(VAULTWARDEN_FILE)
    }

    fn read_side<T: serde::de::DeserializeOwned>(
        &self,
        (suffix, aad): (&str, &[u8]),
    ) -> Result<Option<T>, StoreError> {
        let raw = match std::fs::read(side_path(&self.path, suffix)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let file: SideFile = serde_json::from_slice(&raw).map_err(|_| StoreError::Corrupt)?;
        if file.version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion(file.version));
        }
        let nonce: [u8; NONCE_LEN] = decode(&file.nonce)?;
        let ciphertext = B64
            .decode(&file.ciphertext)
            .map_err(|_| StoreError::Corrupt)?;
        let plaintext =
            zeroize::Zeroizing::new(crypto::open(&self.key, &Sealed { nonce, ciphertext }, aad)?);
        serde_json::from_slice(&plaintext)
            .map(Some)
            .map_err(|_| StoreError::Corrupt)
    }

    fn write_side<T: Serialize>(
        &self,
        (suffix, aad): (&str, &[u8]),
        value: &T,
    ) -> Result<(), StoreError> {
        let plaintext = crate::crypto::secret_json(value).map_err(|_| StoreError::Corrupt)?;
        let sealed = crypto::seal(&self.key, &plaintext, aad)?;
        let file = SideFile {
            version: FORMAT_VERSION,
            nonce: B64.encode(sealed.nonce),
            ciphertext: B64.encode(&sealed.ciphertext),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(|_| StoreError::Corrupt)?;
        write_atomically(&side_path(&self.path, suffix), &json)
    }

    fn delete_side(&self, (suffix, _): (&str, &[u8])) -> Result<(), StoreError> {
        match std::fs::remove_file(side_path(&self.path, suffix)) {
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
        let plaintext = crate::crypto::secret_json(data).map_err(|_| StoreError::Corrupt)?;
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

/// Escribe en un archivo temporal privado, lo sincroniza a disco y lo renombra,
/// para que un corte de luz no deje la bóveda vacía o a medias.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
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

/// En un volumen sin permisos (FAT32, exFAT, algunas carpetas de red) no se puede: se avisa y
/// se guarda igual, como antes.
#[cfg(windows)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    if let Err(e) = crate::windows_acl::restrict(path) {
        eprintln!(
            "aviso: no se pudieron restringir los permisos de {}: {e}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
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
    fn the_password_check_recognizes_only_the_master_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut vault =
            UnlockedVault::create(path, "contraseña-larga", KdfParams::FAST_FOR_TESTS).unwrap();
        let check = vault.password_check();
        assert!(check.matches("contraseña-larga"));
        assert!(!check.matches("otra-contraseña"));
        vault.change_password("nueva-contraseña").unwrap();
        assert!(vault.password_check().matches("nueva-contraseña"));
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
            teams: Vec::new(),
            invitations: Vec::new(),
            contacts: Default::default(),
            oauth: None,
            audit_queue: Vec::new(),
        }
    }

    #[test]
    fn sync_config_is_saved_encrypted_and_survives_password_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        assert!(vault.load_sync().unwrap().is_none());
        vault.save_sync(&sync_config()).unwrap();
        let raw = std::fs::read_to_string(side_path(&vault_path(&dir), ".sync")).unwrap();
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
    fn open_tabs_are_saved_encrypted_apart_from_sync_and_survive_password_changes() {
        use crate::workspace::{SavedTab, SavedTabKind, Workspace};
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        assert!(vault.load_workspace().unwrap().is_none());
        let workspace = Workspace {
            tabs: vec![SavedTab {
                kind: SavedTabKind::Local,
                title: "producción-secreta".into(),
            }],
            active: Some(0),
        };
        vault.save_workspace(&workspace).unwrap();
        let raw = std::fs::read_to_string(side_path(&vault_path(&dir), ".pestanas")).unwrap();
        assert!(!raw.contains("producción"));
        // Un archivo no se puede hacer pasar por el otro.
        std::fs::copy(
            side_path(&vault_path(&dir), ".pestanas"),
            side_path(&vault_path(&dir), ".sync"),
        )
        .unwrap();
        assert!(vault.load_sync().is_err());
        vault.delete_sync().unwrap();

        let history = CommandHistory::default().record(None, "cat /etc/secreto");
        vault.save_history(&history).unwrap();
        let raw = std::fs::read_to_string(side_path(&vault_path(&dir), ".historial")).unwrap();
        assert!(!raw.contains("secreto"));
        vault.change_password("nueva-contraseña").unwrap();
        drop(vault);
        let vault = UnlockedVault::unlock(vault_path(&dir), "nueva-contraseña").unwrap();
        assert_eq!(vault.load_workspace().unwrap(), Some(workspace));
        assert_eq!(vault.load_history().unwrap(), Some(history));
        vault.delete_history().unwrap();
        assert!(vault.load_history().unwrap().is_none());
        vault.delete_workspace().unwrap();
        assert!(vault.load_workspace().unwrap().is_none());
    }

    #[test]
    fn the_vaultwarden_account_is_saved_encrypted_and_survives_password_changes() {
        use crate::vaultwarden::{ExternalSecret, VaultwardenLocal};
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        assert!(vault.load_vaultwarden().unwrap().is_none());
        let secret = ExternalSecret {
            name: "SW-Core".into(),
            organization_id: None,
            username: Some("admin".into()),
            password: Some("cisco-secreta".into()),
            private_key: None,
            enable: None,
        };
        let mut local = VaultwardenLocal::default().with_cache(vec![("i".into(), secret)], 5);
        local.email = "ana@ejemplo.com".into();
        local.refresh_token = Some("token-de-refresco".into());
        vault.save_vaultwarden(&local).unwrap();
        let raw = std::fs::read_to_string(side_path(&vault_path(&dir), ".vaultwarden")).unwrap();
        for secret in ["cisco-secreta", "token-de-refresco", "ana@ejemplo.com"] {
            assert!(!raw.contains(secret), "{secret} en claro");
        }
        std::fs::copy(
            side_path(&vault_path(&dir), ".vaultwarden"),
            side_path(&vault_path(&dir), ".sync"),
        )
        .unwrap();
        assert!(
            vault.load_sync().is_err(),
            "no se hace pasar por otro archivo"
        );
        vault.delete_sync().unwrap();

        vault.change_password("nueva-contraseña").unwrap();
        drop(vault);
        let vault = UnlockedVault::unlock(vault_path(&dir), "nueva-contraseña").unwrap();
        assert_eq!(vault.load_vaultwarden().unwrap(), Some(local));
        vault.delete_vaultwarden().unwrap();
        assert!(vault.load_vaultwarden().unwrap().is_none());
        vault.delete_vaultwarden().unwrap();
    }

    #[test]
    fn a_corrupt_sync_config_does_not_block_a_password_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        std::fs::write(side_path(&vault_path(&dir), ".sync"), b"{basura").unwrap();
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

    #[cfg(windows)]
    #[test]
    fn vault_file_is_private_to_owner_on_windows() {
        use crate::windows_acl::{private_sddl, tests::dacl_of};
        let dir = tempfile::tempdir().unwrap();
        let vault = UnlockedVault::create(vault_path(&dir), PW, KdfParams::FAST_FOR_TESTS).unwrap();
        assert_eq!(dacl_of(&vault_path(&dir)), private_sddl().unwrap());
        drop(vault);

        // Una bóveda anterior, con los permisos heredados, se corrige al abrirla.
        let inherited = dir.path().join("otra.json");
        std::fs::write(&inherited, std::fs::read(vault_path(&dir)).unwrap()).unwrap();
        let side = side_path(&inherited, ".pestanas");
        std::fs::write(&side, b"{}").unwrap();
        assert_ne!(dacl_of(&inherited), private_sddl().unwrap());
        UnlockedVault::unlock(&inherited, PW).unwrap();
        assert_eq!(dacl_of(&inherited), private_sddl().unwrap());
        assert_eq!(dacl_of(&side), private_sddl().unwrap());
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
