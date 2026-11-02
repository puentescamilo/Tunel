//! Ejecuta las herramientas de la nube (`aws`, `az`, `doctl`) para importar máquinas como
//! hosts (ver `tunel_core::cloud`). Usan la sesión que ya tenga iniciada el usuario.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tunel_core::cloud::{self, CloudHost, Provider};

/// Lo que tarda como mucho una consulta; listar muchas regiones puede llevar un rato.
const TIMEOUT: Duration = Duration::from_secs(90);
/// Del error de la herramienta solo se muestra el principio.
const MAX_ERROR_CHARS: usize = 400;

pub fn program(provider: Provider) -> &'static str {
    match provider {
        Provider::Aws => "aws",
        Provider::Azure => "az",
        Provider::DigitalOcean => "doctl",
    }
}

/// Cómo instalar y preparar la herramienta, para cuando no está.
pub fn setup_hint(provider: Provider) -> &'static str {
    match provider {
        Provider::Aws => "Instala AWS CLI y entra con «aws configure» o «aws sso login».",
        Provider::Azure => "Instala Azure CLI y entra con «az login».",
        Provider::DigitalOcean => "Instala doctl y entra con «doctl auth init».",
    }
}

/// Carpetas donde buscar programas: las del `PATH` y las habituales de los gestores de
/// paquetes, que una app abierta desde el Finder o el menú de inicio no siempre tiene.
fn search_path() -> Vec<PathBuf> {
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

pub fn find(provider: Provider) -> Option<PathBuf> {
    find_in(program(provider), &search_path())
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

/// Ejecuta la herramienta de `provider` con `args` y devuelve lo que escribe.
async fn run(provider: Provider, args: &[&str]) -> Result<String, String> {
    let path = find(provider).ok_or_else(|| {
        format!(
            "no se encontró «{}». {}",
            program(provider),
            setup_hint(provider)
        )
    })?;
    run_at(program(provider), &path, args).await
}

async fn run_at(name: &str, path: &Path, args: &[&str]) -> Result<String, String> {
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

/// Una cuenta con la que consultar: perfil de AWS, suscripción de Azure o contexto de
/// doctl. `value` es lo que se pasa a la herramienta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub label: String,
    pub value: String,
}

fn aws_profiles(text: &str) -> Vec<Account> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| Account {
            label: l.to_string(),
            value: l.to_string(),
        })
        .collect()
}

#[derive(serde::Deserialize)]
struct AzureSubscription {
    id: String,
    name: String,
    #[serde(default, rename = "isDefault")]
    is_default: bool,
}

/// Las suscripciones de Azure, la predeterminada primero.
fn azure_subscriptions(json: &str) -> Result<Vec<Account>, String> {
    let mut subscriptions: Vec<AzureSubscription> =
        serde_json::from_str(json).map_err(|e| format!("respuesta de az no válida: {e}"))?;
    subscriptions.sort_by_key(|s| !s.is_default);
    Ok(subscriptions
        .into_iter()
        .map(|s| Account {
            label: format!("{} ({})", s.name, s.id),
            value: s.id,
        })
        .collect())
}

/// Los contextos de `doctl auth list`, el actual primero.
fn doctl_contexts(text: &str) -> Vec<Account> {
    let mut contexts: Vec<(bool, String)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| match l.strip_suffix("(current)") {
            Some(name) => (true, name.trim().to_string()),
            None => (false, l.to_string()),
        })
        .collect();
    contexts.sort_by_key(|(current, _)| !current);
    contexts
        .into_iter()
        .map(|(_, name)| Account {
            label: name.clone(),
            value: name,
        })
        .collect()
}

/// Las cuentas configuradas en la herramienta de `provider`.
pub async fn accounts(provider: Provider) -> Result<Vec<Account>, String> {
    match provider {
        Provider::Aws => Ok(aws_profiles(
            &run(provider, &["configure", "list-profiles"]).await?,
        )),
        Provider::Azure => {
            azure_subscriptions(&run(provider, &["account", "list", "--output", "json"]).await?)
        }
        Provider::DigitalOcean => Ok(doctl_contexts(&run(provider, &["auth", "list"]).await?)),
    }
}

/// La región configurada en un perfil de AWS, si tiene.
pub async fn aws_region(profile: &str) -> Option<String> {
    let args = ["configure", "get", "region", "--profile", profile];
    run(Provider::Aws, &args)
        .await
        .ok()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
}

/// Las máquinas de `account` (y `region`, en AWS).
pub async fn machines(
    provider: Provider,
    account: &str,
    region: &str,
) -> Result<Vec<CloudHost>, String> {
    let parsed = match provider {
        Provider::Aws => {
            let args = [
                "ec2",
                "describe-instances",
                "--output",
                "json",
                "--profile",
                account,
                "--region",
                region,
            ];
            cloud::parse_aws(&run(provider, &args).await?, region)
        }
        Provider::Azure => {
            let args = [
                "vm",
                "list",
                "--show-details",
                "--output",
                "json",
                "--subscription",
                account,
            ];
            cloud::parse_azure(&run(provider, &args).await?)
        }
        Provider::DigitalOcean => {
            let args = [
                "compute",
                "droplet",
                "list",
                "--output",
                "json",
                "--context",
                account,
            ];
            cloud::parse_digitalocean(&run(provider, &args).await?)
        }
    };
    parsed.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_read_from_each_tool() {
        let profiles = aws_profiles("default\nprod\n\n");
        assert_eq!(
            profiles
                .iter()
                .map(|a| a.value.as_str())
                .collect::<Vec<_>>(),
            ["default", "prod"]
        );
        let subscriptions = azure_subscriptions(
            r#"[{"id": "a", "name": "Pruebas", "isDefault": false},
                {"id": "b", "name": "Producción", "isDefault": true}]"#,
        )
        .unwrap();
        assert_eq!(subscriptions[0].value, "b", "la predeterminada primero");
        assert_eq!(subscriptions[0].label, "Producción (b)");
        let contexts = doctl_contexts("default\ntrabajo (current)\n");
        assert_eq!(contexts[0].value, "trabajo");
        assert_eq!(contexts[1].value, "default");
    }

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
