//! Ejecuta las herramientas de la nube (`aws`, `az`, `doctl`) para importar máquinas como
//! hosts (ver `tunel_core::cloud`). Usan la sesión que ya tenga iniciada el usuario.

use crate::tools;
use std::path::PathBuf;
use tunel_core::cloud::{self, CloudHost, Provider};

pub fn find(provider: Provider) -> Option<PathBuf> {
    tools::find(program(provider))
}

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

/// Ejecuta la herramienta de `provider` con `args` y devuelve lo que escribe.
async fn run(provider: Provider, args: &[&str]) -> Result<String, String> {
    let path = find(provider).ok_or_else(|| {
        format!(
            "no se encontró «{}». {}",
            program(provider),
            setup_hint(provider)
        )
    })?;
    tools::run_at(program(provider), &path, args).await
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
}
