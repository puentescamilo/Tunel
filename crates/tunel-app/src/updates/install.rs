//! Instalar una versión nueva: descarga el instalador de este sistema, comprueba que su
//! SHA-256 está en `SHA256SUMS.txt` y que esa lista la firmó quien publica Túnel, y lo abre.
//!
//! La firma es de `ssh-keygen -Y sign` con una clave Ed25519 cuya parte pública va en la
//! app. Sin la privada nadie puede colar un instalador, aunque controle la descarga.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::oneshot;

/// Clave pública de las versiones. La privada solo la tiene quien publica
/// (`scripts/firmar-version.sh`).
pub const RELEASE_SIGNING_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCS2FWpfpcSAR4yJoLkulFre1dI6FN3kG1WqTblGnJ7 firma de versiones de Túnel";
/// Uso de la firma (`ssh-keygen -n`): una firma hecha con esta clave para otra cosa no vale.
pub const SIGNATURE_NAMESPACE: &str = "tunel-versiones";
pub const SUMS_FILE: &str = "SHA256SUMS.txt";
pub const SIGNATURE_FILE: &str = "SHA256SUMS.txt.sig";

const MAX_SUMS_BYTES: usize = 64 * 1024;
/// Los instaladores ocupan unas decenas de MiB.
const MAX_INSTALLER_BYTES: usize = 512 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Sin recibir nada en este tiempo, la descarga se da por perdida.
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FILE_NAME: usize = 128;

/// El instalador de este sistema en una versión, con la lista firmada de sumas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installer {
    pub name: String,
    pub url: String,
    pub sums_url: String,
    pub signature_url: String,
}

/// El nombre se usa para guardar el archivo: nada de rutas ni nombres ocultos.
pub fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn decode_hash(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut hash = [0u8; 32];
    for (byte, pair) in hash.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(hash)
}

/// El SHA-256 de `name` en una lista de `shasum -a 256`.
fn expected_hash(sums: &str, name: &str) -> Option<[u8; 32]> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        // `shasum -b` marca los archivos binarios con `*`.
        let file = file.trim_start();
        let file = file.strip_prefix('*').unwrap_or(file);
        (file == name).then(|| decode_hash(hash)).flatten()
    })
}

/// Comprueba la firma de la lista con `key` y devuelve el SHA-256 que debe tener `name`.
fn signed_hash(key: &str, sums: &[u8], signature: &str, name: &str) -> Result<[u8; 32], String> {
    tunel_ssh::file_signature::verify(key, SIGNATURE_NAMESPACE, sums, signature)
        .map_err(|e| format!("la firma de la versión no es válida: {e}"))?;
    let sums = std::str::from_utf8(sums).map_err(|_| "lista de sumas no válida".to_string())?;
    expected_hash(sums, name).ok_or_else(|| format!("{name} no está en la lista firmada"))
}

fn check_installer(expected: &[u8; 32], installer: &[u8]) -> Result<(), String> {
    if Sha256::digest(installer).as_slice() == expected {
        Ok(())
    } else {
        Err("el instalador descargado no coincide con el publicado".into())
    }
}

async fn fetch(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("sin conexión con GitHub ({e})"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GitHub respondió {status}"));
    }
    super::read_limited(response, limit).await
}

/// Carpeta donde se deja el instalador: Descargas o, si no la hay, la temporal.
fn download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|d| d.download_dir().map(Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir)
}

/// Descarga el instalador, lo comprueba y lo guarda. Devuelve dónde quedó.
pub async fn download(installer: Installer) -> Result<PathBuf, String> {
    if !is_safe_file_name(&installer.name) {
        return Err("nombre de instalador no válido".into());
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .user_agent(format!("Tunel/{}", super::CURRENT_VERSION))
        .build()
        .map_err(|e| e.to_string())?;
    let sums = fetch(&client, &installer.sums_url, MAX_SUMS_BYTES).await?;
    let signature = fetch(&client, &installer.signature_url, MAX_SUMS_BYTES).await?;
    let signature = String::from_utf8(signature).map_err(|_| "firma no válida".to_string())?;
    // Primero la firma: si no vale, ni se descarga el instalador.
    let expected = signed_hash(RELEASE_SIGNING_KEY, &sums, &signature, &installer.name)?;
    let bytes = fetch(&client, &installer.url, MAX_INSTALLER_BYTES).await?;
    check_installer(&expected, &bytes)?;
    let dir = download_dir();
    let path = dir.join(&installer.name);
    let partial = dir.join(format!("{}.part", installer.name));
    let saved = async {
        tokio::fs::write(&partial, &bytes).await?;
        tokio::fs::rename(&partial, &path).await
    };
    saved.await.map_err(|e| {
        let _ = std::fs::remove_file(&partial);
        format!("no se pudo guardar en {} ({e})", dir.display())
    })?;
    Ok(path)
}

/// Abre el instalador con el programa del sistema. No espera a que termine.
pub fn open(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(path);
        c
    };
    #[cfg(windows)]
    let mut command = if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("msi"))
    {
        let mut c = std::process::Command::new("msiexec");
        c.arg("/i").arg(path);
        c
    } else {
        std::process::Command::new(path)
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(path);
        c
    };
    let mut child = command.spawn()?;
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// Qué hacer después de abrir el instalador.
pub fn next_step(path: &Path) -> String {
    if cfg!(target_os = "macos") {
        "Arrastra Túnel a Aplicaciones para reemplazar esta versión y vuelve a abrirlo".into()
    } else if cfg!(windows) {
        "Sigue el instalador; si te pide cerrar Túnel, ciérralo".into()
    } else {
        format!(
            "Si no se abre el instalador de paquetes: sudo apt install {}",
            path.display()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStatus {
    Idle,
    Downloading,
    Ready(PathBuf),
    Failed(String),
}

type Pending = oneshot::Receiver<Result<PathBuf, String>>;

/// La descarga de la versión nueva, de una en una.
pub struct UpdateInstall {
    pub status: InstallStatus,
    pending: Option<Pending>,
}

impl Default for UpdateInstall {
    fn default() -> Self {
        Self {
            status: InstallStatus::Idle,
            pending: None,
        }
    }
}

impl UpdateInstall {
    pub fn start(&mut self, start: impl FnOnce() -> Pending) {
        if self.pending.is_some() {
            return;
        }
        self.pending = Some(start());
        self.status = InstallStatus::Downloading;
    }

    pub fn running(&self) -> bool {
        self.pending.is_some()
    }

    /// El resultado de la descarga, la vez que llega.
    pub fn collect(&mut self) -> Option<Result<PathBuf, String>> {
        let result = match self.pending.as_mut()?.try_recv() {
            Ok(result) => result,
            Err(oneshot::error::TryRecvError::Empty) => return None,
            Err(oneshot::error::TryRecvError::Closed) => Err("descarga interrumpida".into()),
        };
        self.pending = None;
        self.status = match &result {
            Ok(path) => InstallStatus::Ready(path.clone()),
            Err(error) => InstallStatus::Failed(error.clone()),
        };
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEB: &str = "tunel_0.9.0_amd64.deb";

    fn sha256_hex(data: &[u8]) -> String {
        Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Una clave de prueba y su firma de `sums`, como las de `ssh-keygen -Y sign`.
    fn signed(sums: &str) -> (String, String) {
        use russh::keys::ssh_key::{HashAlg, LineEnding, PrivateKey};
        let generated = tunel_ssh::keygen::generate(Default::default(), "", None).unwrap();
        let key = PrivateKey::from_openssh(&generated.private_key).unwrap();
        let signature = key
            .sign(SIGNATURE_NAMESPACE, HashAlg::Sha512, sums.as_bytes())
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        (generated.public_key, signature)
    }

    #[test]
    fn the_release_key_is_a_valid_ed25519_key() {
        assert!(RELEASE_SIGNING_KEY.starts_with("ssh-ed25519 "));
        let (_, signature) = signed("x");
        let error = tunel_ssh::file_signature::verify(
            RELEASE_SIGNING_KEY,
            SIGNATURE_NAMESPACE,
            b"x",
            &signature,
        )
        .unwrap_err();
        assert_eq!(error, "la firma no corresponde a la clave");
    }

    #[test]
    fn the_installer_hash_comes_from_the_signed_list() {
        let installer = b"contenido del paquete";
        let sums = format!(
            "{}  tunel_0.9.0_universal.dmg\n{} *{DEB}\n",
            sha256_hex(b"otro"),
            sha256_hex(installer)
        );
        let (key, signature) = signed(&sums);
        let expected = signed_hash(&key, sums.as_bytes(), &signature, DEB).unwrap();
        assert_eq!(check_installer(&expected, installer), Ok(()));
        assert!(check_installer(&expected, b"paquete cambiado").is_err());
        assert!(signed_hash(&key, sums.as_bytes(), &signature, "tunel_0.9.0_arm64.deb").is_err());
    }

    #[test]
    fn a_list_changed_after_signing_is_rejected() {
        let sums = format!("{}  {DEB}\n", sha256_hex(b"bueno"));
        let (key, signature) = signed(&sums);
        let tampered = format!("{}  {DEB}\n", sha256_hex(b"malo"));
        let error = signed_hash(&key, tampered.as_bytes(), &signature, DEB).unwrap_err();
        assert!(
            error.starts_with("la firma de la versión no es válida"),
            "{error}"
        );
        let (other_key, _) = signed(&sums);
        assert!(signed_hash(&other_key, sums.as_bytes(), &signature, DEB).is_err());
    }

    #[test]
    fn malformed_hashes_are_ignored() {
        assert_eq!(expected_hash(&format!("zz  {DEB}\n"), DEB), None);
        assert_eq!(
            expected_hash(&format!("{}  {DEB}", "g".repeat(64)), DEB),
            None
        );
        assert_eq!(expected_hash("", DEB), None);
        let hash = sha256_hex(b"x");
        assert!(expected_hash(&format!("{hash}  {DEB}.part"), DEB).is_none());
        assert!(expected_hash(&format!("{hash}  {DEB}"), DEB).is_some());
    }

    #[test]
    fn only_plain_file_names_are_saved() {
        assert!(is_safe_file_name(DEB));
        assert!(is_safe_file_name("tunel_0.9.0_x64_es-ES.msi"));
        for bad in [
            "",
            ".bashrc",
            "../tunel.deb",
            "a/b.deb",
            "a\\b.exe",
            "Túnel.dmg",
            "a b",
        ] {
            assert!(!is_safe_file_name(bad), "{bad}");
        }
        assert!(!is_safe_file_name(&"a".repeat(MAX_FILE_NAME + 1)));
    }

    #[test]
    fn one_download_at_a_time_and_its_result_is_kept() {
        let mut install = UpdateInstall::default();
        let (tx, rx) = oneshot::channel();
        install.start(|| rx);
        assert_eq!(install.status, InstallStatus::Downloading);
        install.start(|| panic!("ya hay una descarga en curso"));
        assert_eq!(install.collect(), None);
        tx.send(Ok(PathBuf::from("/tmp/x.deb"))).unwrap();
        assert_eq!(install.collect(), Some(Ok(PathBuf::from("/tmp/x.deb"))));
        assert_eq!(install.status, InstallStatus::Ready("/tmp/x.deb".into()));
        assert!(!install.running());

        let (tx, rx) = oneshot::channel();
        install.start(|| rx);
        drop(tx);
        assert!(matches!(install.collect(), Some(Err(_))));
        assert!(matches!(install.status, InstallStatus::Failed(_)));
    }
}
