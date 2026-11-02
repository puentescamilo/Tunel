//! Herramientas de línea de órdenes del sistema (`aws`, `docker`, `kubectl`…): dónde
//! buscarlas, aunque la app no tenga el `PATH` de la terminal, y cómo ejecutarlas.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Lo que tarda como mucho una consulta; listar muchas regiones puede llevar un rato.
const TIMEOUT: Duration = Duration::from_secs(90);
/// Del error de la herramienta solo se muestra el principio.
const MAX_ERROR_CHARS: usize = 400;

/// Carpetas donde buscar programas: las del `PATH` y las habituales de los gestores de
/// paquetes, que una app abierta desde el Finder o el menú de inicio no siempre tiene.
pub fn search_path() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
    let extra: &[&str] = if cfg!(target_os = "macos") {
        &["/opt/homebrew/bin", "/usr/local/bin"]
    } else if cfg!(windows) {
        &[
            r"C:\Program Files\Amazon\AWSCLIV2",
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin",
            r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin",
        ]
    } else {
        &["/usr/local/bin", "/snap/bin"]
    };
    dirs.extend(extra.iter().map(PathBuf::from));
    if let Some(home) = home {
        dirs.push(home.join(".local/bin"));
    }
    dirs
}

/// El programa `name`, buscado en `dirs`. En Windows prueba también `.exe` y `.cmd`.
fn find_in(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    let names: Vec<String> = if cfg!(windows) {
        ["exe", "cmd", "bat"]
            .iter()
            .map(|ext| format!("{name}.{ext}"))
            .collect()
    } else {
        vec![name.to_string()]
    };
    dirs.iter()
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|path| path.is_file())
}

fn command(path: &Path) -> tokio::process::Command {
    let script = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"));
    let mut command = if script {
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").arg(path);
        c
    } else {
        tokio::process::Command::new(path)
    };
    // La herramienta puede necesitar las demás del mismo sitio (az usa python, por ejemplo).
    if let Ok(path) = std::env::join_paths(search_path()) {
        command.env("PATH", path);
    }
    command
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null());
    command
}

/// El programa `name`, en las carpetas de [`search_path`].
pub fn find(name: &str) -> Option<PathBuf> {
    find_in(name, &search_path())
}

/// Ejecuta `path` con `args` y devuelve lo que escribe; `name` es para los mensajes.
pub async fn run_at(name: &str, path: &Path, args: &[&str]) -> Result<String, String> {
    let output = tokio::time::timeout(TIMEOUT, command(path).args(args).output())
        .await
        .map_err(|_| format!("«{name}» tardó demasiado"))?
        .map_err(|e| format!("no se pudo ejecutar «{}»: {e}", path.display()))?;
    if output.status.success() {
        return String::from_utf8(output.stdout)
            .map_err(|_| format!("«{name}» respondió algo que no es texto"));
    }
    let error = String::from_utf8_lossy(&output.stderr);
    let error: String = error.trim().chars().take(MAX_ERROR_CHARS).collect();
    Err(format!("«{name}» falló: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn a_tools_output_and_errors_reach_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("aws");
        std::fs::write(
            &script,
            "#!/bin/sh\nif [ \"$1\" = ec2 ]; then echo '{\"Reservations\": []}'; \
             else echo 'Unable to locate credentials' >&2; exit 255; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let json = run_at("aws", &script, &["ec2", "describe-instances"])
            .await
            .unwrap();
        assert_eq!(tunel_core::cloud::parse_aws(&json, "x").unwrap(), vec![]);
        let error = run_at("aws", &script, &["configure"]).await.unwrap_err();
        assert_eq!(error, "«aws» falló: Unable to locate credentials");
    }

    /// En Windows, `az` es un `.cmd` y se lanza con `cmd /C`.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_cmd_script_runs_through_cmd() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("az.cmd");
        std::fs::write(&script, "@echo off\r\necho [] \r\n").unwrap();
        let json = run_at("az", &script, &["vm", "list"]).await.unwrap();
        assert_eq!(tunel_core::cloud::parse_azure(&json).unwrap(), vec![]);
    }

    #[test]
    fn programs_are_found_in_the_extra_folders() {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) { "fake.exe" } else { "fake" };
        std::fs::write(dir.path().join(name), "").unwrap();
        let dirs = vec![PathBuf::from("/no/existe"), dir.path().to_path_buf()];
        assert_eq!(find_in("fake", &dirs), Some(dir.path().join(name)));
        assert_eq!(find_in("otro", &dirs), None);
    }
}
