//! Instalar una clave pública en `~/.ssh/authorized_keys` de un host, como `ssh-copy-id`.
//!
//! El script va por la entrada de `sh`, no en la línea de comandos: así no importa el shell
//! de la cuenta (fish, csh…) ni hay que entrecomillarlo dos veces.

use crate::client::{SshConnection, SshError};
use russh::keys::ssh_key::PublicKey;

const ADDED: &str = "tunel:instalada";
const ALREADY_THERE: &str = "tunel:ya-estaba";
/// Lo que devuelve el shell cuando no encuentra el comando.
const COMMAND_NOT_FOUND: u32 = 127;
/// Líneas de la salida que se enseñan si algo falla.
const ERROR_LINES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installed {
    Added,
    /// Ya estaba en `authorized_keys`: no se duplica.
    AlreadyThere,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("La clave pública no es válida")]
    InvalidKey,
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error("El host no tiene sh; en servidores Windows hay que añadir la clave a mano")]
    NoShell,
    #[error("No se pudo instalar la clave: {0}")]
    Failed(String),
}

/// `text` entre comillas simples para `sh`.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// La clave en una línea limpia: tipo, clave y comentario sin caracteres de control, que
/// podrían partirla en varias líneas de `authorized_keys`.
fn clean_line(public_key: &str) -> Result<(String, String), InstallError> {
    let mut key =
        PublicKey::from_openssh(public_key.trim()).map_err(|_| InstallError::InvalidKey)?;
    let comment: String = key
        .comment()
        .to_string()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    key.set_comment(comment.trim());
    let line = key.to_openssh().map_err(|_| InstallError::InvalidKey)?;
    let blob = line
        .split_whitespace()
        .nth(1)
        .ok_or(InstallError::InvalidKey)?
        .to_string();
    Ok((line, blob))
}

/// El script que añade `public_key` a `~/.ssh/authorized_keys` si no está. Crea `~/.ssh`
/// (700) y el archivo (600) si faltan, y añade el salto de línea final si no lo tenía.
pub fn script(public_key: &str) -> Result<String, InstallError> {
    let (line, blob) = clean_line(public_key)?;
    Ok(format!(
        r#"umask 077
cd || exit 3
[ -d .ssh ] || mkdir .ssh || exit 3
f=.ssh/authorized_keys
if [ -f "$f" ] && grep -qF -- {blob} "$f"; then echo {ALREADY_THERE}; exit 0; fi
if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then printf '\n' >> "$f" || exit 4; fi
printf '%s\n' {line} >> "$f" || exit 4
if command -v restorecon >/dev/null 2>&1; then restorecon -F .ssh "$f" >/dev/null 2>&1; fi
echo {ADDED}
"#,
        blob = quote(&blob),
        line = quote(&line),
    ))
}

/// Lo que pasó, según la salida del script y su código de salida.
pub fn outcome(output: &[u8], status: Option<u32>) -> Result<Installed, InstallError> {
    let text = String::from_utf8_lossy(output);
    if text.lines().any(|l| l.trim() == ADDED) {
        return Ok(Installed::Added);
    }
    if text.lines().any(|l| l.trim() == ALREADY_THERE) {
        return Ok(Installed::AlreadyThere);
    }
    if status == Some(COMMAND_NOT_FOUND) {
        return Err(InstallError::NoShell);
    }
    let tail: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let detail = tail[tail.len().saturating_sub(ERROR_LINES)..].join(" · ");
    Err(InstallError::Failed(match (detail.is_empty(), status) {
        (false, _) => detail,
        (true, Some(code)) => format!("el script terminó con el código {code}"),
        (true, None) => "el host cerró la conexión".into(),
    }))
}

/// Instala `public_key` en la cuenta con la que está abierta `conn`.
pub async fn install(conn: &SshConnection, public_key: &str) -> Result<Installed, InstallError> {
    let script = script(public_key)?;
    let (output, status) = conn
        .exec_with_input("sh 2>&1", Some(script.as_bytes()))
        .await?;
    outcome(&output, status)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnWh4ZKKnR4mH5tN2k1v3VJm5Hk3Vb1+ZbB3Xc5Yw9P";

    /// Ejecuta el script como lo haría el host, con `home` como carpeta personal.
    fn run(home: &Path, public_key: &str) -> Result<Installed, InstallError> {
        let script = script(public_key)?;
        let mut child = Command::new("sh")
            .env("HOME", home)
            .current_dir(home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        outcome(&out.stdout, out.status.code().map(|c| c as u32))
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_key_is_added_once_with_private_permissions() {
        let home = tempfile::tempdir().unwrap();
        let line = format!("{KEY} ana@portatil");
        assert_eq!(run(home.path(), &line).unwrap(), Installed::Added);
        assert_eq!(run(home.path(), &line).unwrap(), Installed::AlreadyThere);
        // Con otro comentario sigue siendo la misma clave.
        assert_eq!(run(home.path(), KEY).unwrap(), Installed::AlreadyThere);
        let ssh = home.path().join(".ssh");
        let file = ssh.join("authorized_keys");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{line}\n"));
        assert_eq!(mode(&ssh), 0o700);
        assert_eq!(mode(&file), 0o600);
    }

    #[test]
    fn keys_already_there_are_kept_and_the_last_line_is_ended() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let file = home.path().join(".ssh/authorized_keys");
        std::fs::write(&file, "ssh-rsa AAAAotra bob").unwrap();
        assert_eq!(run(home.path(), KEY).unwrap(), Installed::Added);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("ssh-rsa AAAAotra bob\n{KEY}\n")
        );
    }

    #[test]
    fn the_comment_cannot_run_commands_or_split_the_line() {
        let home = tempfile::tempdir().unwrap();
        let hostile = format!("{KEY} x'; touch pwned; echo '\n$(touch pwned2)");
        assert_eq!(run(home.path(), &hostile).unwrap(), Installed::Added);
        assert!(!home.path().join("pwned").exists());
        assert!(!home.path().join("pwned2").exists());
        let text = std::fs::read_to_string(home.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.starts_with(KEY));
    }

    #[test]
    fn invalid_keys_are_refused_before_connecting() {
        assert!(matches!(script("hola"), Err(InstallError::InvalidKey)));
        assert!(matches!(script(""), Err(InstallError::InvalidKey)));
    }

    #[test]
    fn failures_explain_what_the_host_said() {
        assert!(matches!(
            outcome(b"", Some(COMMAND_NOT_FOUND)),
            Err(InstallError::NoShell)
        ));
        let failed = outcome(b"mkdir: .ssh: Permission denied\n", Some(3)).unwrap_err();
        assert!(failed.to_string().contains("Permission denied"));
        let silent = outcome(b"", Some(4)).unwrap_err();
        assert!(silent.to_string().contains("código 4"));
    }
}
