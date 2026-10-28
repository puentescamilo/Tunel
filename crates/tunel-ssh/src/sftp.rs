//! Navegador SFTP: listar, subir, descargar, renombrar y borrar.

use crate::client::{SshConnection, SshError};
use russh_sftp::client::SftpSession;
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SftpError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error("SFTP: {0}")]
    Protocol(#[from] russh_sftp::client::error::Error),
    #[error("E/S local: {0}")]
    Io(#[from] std::io::Error),
    #[error("el servidor envió un nombre de archivo no válido: {0:?}")]
    UnsafeName(String),
}

impl From<russh::Error> for SftpError {
    fn from(e: russh::Error) -> Self {
        Self::Ssh(SshError::Russh(e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub permissions: Option<u32>,
    pub modified: Option<std::time::SystemTime>,
}

/// Ordena carpetas primero y luego por nombre, sin distinguir mayúsculas.
pub fn sort_entries(entries: Vec<RemoteEntry>) -> Vec<RemoteEntry> {
    let mut sorted = entries;
    sorted.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    sorted
}

/// Une una ruta remota POSIX con un nombre, resolviendo `..`.
pub fn join_remote(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    let mut parts: Vec<&str> = base.split('/').filter(|p| !p.is_empty()).collect();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Ruta local donde guardar una entrada remota dentro de `dir`.
///
/// El nombre lo envía el servidor, así que solo se acepta un único componente
/// normal: nada de separadores, `..`, rutas absolutas ni unidades de Windows.
pub fn local_target(dir: &Path, name: &str) -> Result<PathBuf, SftpError> {
    let unsafe_name = || SftpError::UnsafeName(name.to_string());
    if name.contains(['/', '\\', '\0']) || (cfg!(windows) && name.contains(':')) {
        return Err(unsafe_name());
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(part)), None) if part == name => Ok(dir.join(part)),
        _ => Err(unsafe_name()),
    }
}

pub struct SftpClient {
    session: SftpSession,
}

impl SftpClient {
    pub async fn open(conn: &SshConnection) -> Result<Self, SftpError> {
        let channel = conn.handle().channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let session = SftpSession::new(channel.into_stream()).await?;
        Ok(Self { session })
    }

    pub async fn home(&self) -> Result<String, SftpError> {
        Ok(self.session.canonicalize(".").await?)
    }

    pub async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, SftpError> {
        let entries = self
            .session
            .read_dir(path)
            .await?
            .map(|entry| {
                let meta = entry.metadata();
                RemoteEntry {
                    name: entry.file_name(),
                    is_dir: meta.is_dir(),
                    is_symlink: meta.is_symlink(),
                    size: meta.len(),
                    permissions: meta.permissions,
                    modified: meta.modified().ok(),
                }
            })
            .filter(|e| e.name != "." && e.name != "..")
            .collect();
        Ok(sort_entries(entries))
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), SftpError> {
        Ok(self.session.create_dir(path).await?)
    }

    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<(), SftpError> {
        if is_dir {
            Ok(self.session.remove_dir(path).await?)
        } else {
            Ok(self.session.remove_file(path).await?)
        }
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), SftpError> {
        Ok(self.session.rename(from, to).await?)
    }

    /// Descarga un archivo, informando del progreso en bytes.
    pub async fn download(
        &self,
        remote: &str,
        local: &Path,
        mut progress: impl FnMut(u64),
    ) -> Result<u64, SftpError> {
        let mut source = self.session.open(remote).await?;
        let mut target = tokio::fs::File::create(local).await?;
        copy_with_progress(&mut source, &mut target, &mut progress).await
    }

    /// Sube un archivo, informando del progreso en bytes.
    pub async fn upload(
        &self,
        local: &Path,
        remote: &str,
        mut progress: impl FnMut(u64),
    ) -> Result<u64, SftpError> {
        let mut source = tokio::fs::File::open(local).await?;
        let mut target = self.session.create(remote).await?;
        let total = copy_with_progress(&mut source, &mut target, &mut progress).await?;
        target.shutdown().await?;
        Ok(total)
    }
}

async fn copy_with_progress<R, W>(
    source: &mut R,
    target: &mut W,
    progress: &mut impl FnMut(u64),
) -> Result<u64, SftpError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = source.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        target.write_all(&buffer[..n]).await?;
        total += n as u64;
        progress(total);
    }
    target.flush().await?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, is_dir: bool) -> RemoteEntry {
        RemoteEntry {
            name: name.into(),
            is_dir,
            is_symlink: false,
            size: 0,
            permissions: None,
            modified: None,
        }
    }

    #[test]
    fn sort_puts_directories_first_then_alphabetical() {
        let sorted = sort_entries(vec![
            entry("b.txt", false),
            entry("Zeta", true),
            entry("a.txt", false),
            entry("alfa", true),
        ]);
        let names: Vec<&str> = sorted.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alfa", "Zeta", "a.txt", "b.txt"]);
    }

    #[test]
    fn join_remote_handles_relative_parent_and_absolute() {
        assert_eq!(join_remote("/home/ana", "docs"), "/home/ana/docs");
        assert_eq!(join_remote("/home/ana", ".."), "/home");
        assert_eq!(join_remote("/", ".."), "/");
        assert_eq!(join_remote("/home/ana", "/etc"), "/etc");
        assert_eq!(join_remote("/home/ana/", "./a/../b"), "/home/ana/b");
    }

    #[test]
    fn local_target_accepts_plain_names() {
        let dir = Path::new("/descargas");
        assert_eq!(
            local_target(dir, "informe.pdf").unwrap(),
            dir.join("informe.pdf")
        );
        assert_eq!(local_target(dir, "..oculto").unwrap(), dir.join("..oculto"));
    }

    #[test]
    fn local_target_rejects_names_that_escape_the_folder() {
        let dir = Path::new("/descargas");
        for name in [
            "",
            ".",
            "..",
            "../x",
            "a/../../x",
            "/etc/passwd",
            "a/b",
            "..\\x",
            "C:\\x",
            "a\0b",
        ] {
            assert!(
                matches!(local_target(dir, name), Err(SftpError::UnsafeName(_))),
                "{name:?}"
            );
        }
    }

    #[tokio::test]
    async fn copy_with_progress_reports_cumulative_bytes() {
        let data = vec![7u8; CHUNK + 10];
        let mut source = data.as_slice();
        let mut target = Vec::new();
        let mut seen = Vec::new();
        let total = copy_with_progress(&mut source, &mut target, &mut |n| seen.push(n))
            .await
            .unwrap();
        assert_eq!(total, (CHUNK + 10) as u64);
        assert_eq!(target, data);
        assert_eq!(seen.last().copied(), Some(total));
    }
}
