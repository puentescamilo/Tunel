//! Importar máquinas de la nube como hosts: AWS EC2, máquinas virtuales de Azure y droplets
//! de DigitalOcean. Se leen las salidas JSON de sus herramientas oficiales (`aws`, `az`,
//! `doctl`), con la sesión que ya tenga iniciada el usuario: Túnel no guarda credenciales
//! de la nube.

use crate::model::{Group, Host};
use crate::vault::VaultData;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    Aws,
    Azure,
    DigitalOcean,
}

impl Provider {
    pub const ALL: [Provider; 3] = [Self::Aws, Self::Azure, Self::DigitalOcean];

    pub fn label(self) -> &'static str {
        match self {
            Self::Aws => "AWS",
            Self::Azure => "Azure",
            Self::DigitalOcean => "DigitalOcean",
        }
    }

    /// Prefijo de [`Host::cloud_id`] y etiqueta de los hosts importados.
    fn key(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::DigitalOcean => "digitalocean",
        }
    }
}

/// Una máquina tal como la describe su proveedor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudHost {
    pub provider: Provider,
    /// Identificador estable en el proveedor.
    pub id: String,
    pub name: String,
    pub region: String,
    /// Estado según el proveedor, como `running` o `stopped`.
    pub state: String,
    pub running: bool,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub dns: Option<String>,
}

impl CloudHost {
    /// Dirección con la que conectar: la pública o, con `private`, la privada, y si no hay,
    /// la otra o el nombre DNS.
    pub fn address(&self, private: bool) -> Option<&str> {
        let (first, second) = if private {
            (&self.private_ip, &self.public_ip)
        } else {
            (&self.public_ip, &self.private_ip)
        };
        first
            .as_deref()
            .or(second.as_deref())
            .or(self.dns.as_deref())
    }

    pub fn cloud_id(&self) -> String {
        format!("{}:{}", self.provider.key(), self.id)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("la respuesta de {provider} no es la esperada: {source}")]
pub struct CloudError {
    provider: &'static str,
    source: serde_json::Error,
}

fn non_empty(text: Option<String>) -> Option<String> {
    text.map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

// --- AWS: `aws ec2 describe-instances --output json` ---

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsResponse {
    #[serde(default)]
    reservations: Vec<AwsReservation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsReservation {
    #[serde(default)]
    instances: Vec<AwsInstance>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsInstance {
    instance_id: String,
    state: Option<AwsState>,
    public_ip_address: Option<String>,
    private_ip_address: Option<String>,
    public_dns_name: Option<String>,
    placement: Option<AwsPlacement>,
    #[serde(default)]
    tags: Vec<AwsTag>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsState {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsPlacement {
    availability_zone: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsTag {
    key: String,
    value: String,
}

/// Instancias EC2 de `aws ec2 describe-instances`; `region` es la consultada.
pub fn parse_aws(json: &str, region: &str) -> Result<Vec<CloudHost>, CloudError> {
    let response: AwsResponse = serde_json::from_str(json).map_err(|source| CloudError {
        provider: "AWS",
        source,
    })?;
    Ok(response
        .reservations
        .into_iter()
        .flat_map(|r| r.instances)
        .filter(|i| i.state.as_ref().is_none_or(|s| s.name != "terminated"))
        .map(|i| {
            let name = i
                .tags
                .iter()
                .find(|t| t.key == "Name")
                .map(|t| t.value.clone())
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| i.instance_id.clone());
            let state = i.state.map(|s| s.name).unwrap_or_default();
            let zone = i.placement.and_then(|p| p.availability_zone);
            CloudHost {
                provider: Provider::Aws,
                running: state == "running",
                region: zone
                    .map(|z| z.trim_end_matches(char::is_alphabetic).to_string())
                    .filter(|r| !r.is_empty())
                    .unwrap_or_else(|| region.to_string()),
                id: i.instance_id,
                name,
                state,
                public_ip: non_empty(i.public_ip_address),
                private_ip: non_empty(i.private_ip_address),
                dns: non_empty(i.public_dns_name),
            }
        })
        .collect())
}

// --- Azure: `az vm list --show-details --output json` ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureVm {
    id: String,
    name: String,
    #[serde(default)]
    location: String,
    power_state: Option<String>,
    public_ips: Option<String>,
    private_ips: Option<String>,
    fqdns: Option<String>,
}

/// El primero de una lista separada por comas, como la que da `az` con varias IP.
fn first_of(list: Option<String>) -> Option<String> {
    non_empty(list.and_then(|l| l.split(',').next().map(str::to_string)))
}

pub fn parse_azure(json: &str) -> Result<Vec<CloudHost>, CloudError> {
    let vms: Vec<AzureVm> = serde_json::from_str(json).map_err(|source| CloudError {
        provider: "Azure",
        source,
    })?;
    Ok(vms
        .into_iter()
        .map(|vm| {
            let state = vm
                .power_state
                .unwrap_or_default()
                .trim_start_matches("VM ")
                .to_string();
            CloudHost {
                provider: Provider::Azure,
                // El id de Azure es la ruta del recurso; en minúsculas no cambia de forma.
                id: vm.id.to_lowercase(),
                name: vm.name,
                region: vm.location,
                running: state == "running",
                state,
                public_ip: first_of(vm.public_ips),
                private_ip: first_of(vm.private_ips),
                dns: first_of(vm.fqdns),
            }
        })
        .collect())
}

// --- DigitalOcean: `doctl compute droplet list --output json` ---

#[derive(Deserialize)]
struct Droplet {
    id: u64,
    name: String,
    #[serde(default)]
    status: String,
    region: Option<DropletRegion>,
    networks: Option<DropletNetworks>,
}

#[derive(Deserialize)]
struct DropletRegion {
    slug: String,
}

#[derive(Deserialize)]
struct DropletNetworks {
    #[serde(default)]
    v4: Vec<DropletAddress>,
}

#[derive(Deserialize)]
struct DropletAddress {
    ip_address: String,
    #[serde(rename = "type")]
    kind: String,
}

pub fn parse_digitalocean(json: &str) -> Result<Vec<CloudHost>, CloudError> {
    // `doctl` devuelve `null` si no hay ningún droplet.
    let droplets: Option<Vec<Droplet>> =
        serde_json::from_str(json).map_err(|source| CloudError {
            provider: "DigitalOcean",
            source,
        })?;
    Ok(droplets
        .unwrap_or_default()
        .into_iter()
        .map(|d| {
            let v4 = d.networks.map(|n| n.v4).unwrap_or_default();
            let ip = |kind: &str| {
                non_empty(
                    v4.iter()
                        .find(|a| a.kind == kind)
                        .map(|a| a.ip_address.clone()),
                )
            };
            CloudHost {
                provider: Provider::DigitalOcean,
                id: d.id.to_string(),
                running: d.status == "active",
                state: d.status,
                region: d.region.map(|r| r.slug).unwrap_or_default(),
                public_ip: ip("public"),
                private_ip: ip("private"),
                dns: None,
                name: d.name,
            }
        })
        .collect())
}

/// Lo que hizo una importación.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub added: usize,
    /// Ya estaban: se actualizó su dirección.
    pub updated: usize,
    /// Sin ninguna dirección con la que conectar.
    pub skipped: usize,
}

/// Añade `hosts` a la bóveda, en el grupo `group` (que se crea si no hay uno con ese
/// nombre en la raíz de la bóveda personal). Los que ya se importaron antes, estén donde
/// estén, solo cambian de dirección: el resto de su configuración es del usuario.
pub fn import_into(
    data: &VaultData,
    hosts: &[CloudHost],
    group: &str,
    private: bool,
) -> (VaultData, ImportSummary) {
    let mut summary = ImportSummary::default();
    let mut data = data.clone();
    let existing: HashMap<String, Host> = data
        .hosts
        .iter()
        .filter_map(|h| Some((h.cloud_id.clone()?, h.clone())))
        .collect();
    let mut group_id = data
        .groups
        .iter()
        .find(|g| g.name == group && g.parent.is_none() && g.team.is_none())
        .map(|g| g.id);
    for cloud in hosts {
        let Some(address) = cloud.address(private) else {
            summary.skipped += 1;
            continue;
        };
        if let Some(host) = existing.get(&cloud.cloud_id()) {
            if host.address != address {
                data = data.with_host(Host {
                    address: address.to_string(),
                    ..host.clone()
                });
            }
            summary.updated += 1;
            continue;
        }
        let group = *group_id.get_or_insert_with(|| {
            let new = Group::new(group);
            let id = new.id;
            data = data.with_group(new);
            id
        });
        let mut tags = vec![cloud.provider.key().to_string()];
        if !cloud.region.is_empty() {
            tags.push(cloud.region.clone());
        }
        data = data.with_host(Host {
            group: Some(group),
            tags,
            cloud_id: Some(cloud.cloud_id()),
            ..Host::new(cloud.name.clone(), address)
        });
        summary.added += 1;
    }
    (data, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWS: &str = r#"{"Reservations": [{"Instances": [
        {"InstanceId": "i-0abc", "State": {"Name": "running"},
         "PublicIpAddress": "3.250.1.2", "PrivateIpAddress": "10.0.1.5",
         "PublicDnsName": "ec2-3-250-1-2.eu-west-1.compute.amazonaws.com",
         "Placement": {"AvailabilityZone": "eu-west-1b"},
         "Tags": [{"Key": "Name", "Value": "web-1"}, {"Key": "env", "Value": "prod"}]},
        {"InstanceId": "i-0def", "State": {"Name": "stopped"},
         "PrivateIpAddress": "10.0.1.6", "PublicDnsName": ""},
        {"InstanceId": "i-0dead", "State": {"Name": "terminated"}}
    ]}]}"#;

    const AZURE: &str = r#"[{"id": "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/db",
        "name": "db", "location": "westeurope", "powerState": "VM running",
        "publicIps": "20.1.2.3,20.1.2.4", "privateIps": "10.1.0.4", "fqdns": ""}]"#;

    const DROPLETS: &str = r#"[{"id": 1234, "name": "app", "status": "active",
        "region": {"slug": "fra1"},
        "networks": {"v4": [{"ip_address": "10.114.0.2", "type": "private"},
                            {"ip_address": "164.90.1.2", "type": "public"}]}}]"#;

    #[test]
    fn aws_instances_are_read_without_terminated_ones() {
        let hosts = parse_aws(AWS, "eu-west-1").unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].name, "web-1");
        assert_eq!(hosts[0].region, "eu-west-1");
        assert!(hosts[0].running);
        assert_eq!(hosts[0].address(false), Some("3.250.1.2"));
        assert_eq!(hosts[0].address(true), Some("10.0.1.5"));
        assert_eq!(hosts[1].name, "i-0def", "sin etiqueta Name, su id");
        assert_eq!(hosts[1].dns, None, "un nombre vacío no cuenta");
        assert_eq!(hosts[1].address(false), Some("10.0.1.6"));
        assert_eq!(parse_aws(r#"{"Reservations": []}"#, "x").unwrap(), vec![]);
        assert!(parse_aws("no es json", "x").is_err());
    }

    #[test]
    fn azure_vms_take_their_first_ip() {
        let hosts = parse_azure(AZURE).unwrap();
        assert_eq!(hosts[0].public_ip.as_deref(), Some("20.1.2.3"));
        assert_eq!(hosts[0].state, "running");
        assert!(hosts[0].running);
        assert_eq!(hosts[0].dns, None);
        assert!(hosts[0].cloud_id().starts_with("azure:/subscriptions/s/"));
    }

    #[test]
    fn droplets_split_public_and_private_addresses() {
        let hosts = parse_digitalocean(DROPLETS).unwrap();
        assert_eq!(hosts[0].public_ip.as_deref(), Some("164.90.1.2"));
        assert_eq!(hosts[0].private_ip.as_deref(), Some("10.114.0.2"));
        assert_eq!(hosts[0].cloud_id(), "digitalocean:1234");
        assert_eq!(parse_digitalocean("null").unwrap(), vec![]);
    }

    #[test]
    fn importing_again_updates_the_address_and_keeps_the_rest() {
        let hosts = parse_aws(AWS, "eu-west-1").unwrap();
        let (data, summary) = import_into(&VaultData::default(), &hosts, "AWS eu-west-1", false);
        assert_eq!(
            summary,
            ImportSummary {
                added: 2,
                updated: 0,
                skipped: 0
            }
        );
        assert_eq!(data.groups.len(), 1);
        let web = data
            .hosts
            .iter()
            .find(|h| h.label == "web-1")
            .unwrap()
            .clone();
        assert_eq!(web.tags, ["aws", "eu-west-1"]);
        assert_eq!(web.group, Some(data.groups[0].id));

        // El usuario la renombra y la mueve; la instancia cambia de IP.
        let edited = data.with_host(Host {
            label: "Web de producción".into(),
            group: None,
            ..web.clone()
        });
        let mut moved = hosts.clone();
        moved[0].public_ip = Some("3.250.9.9".into());
        let (again, summary) = import_into(&edited, &moved, "AWS eu-west-1", false);
        assert_eq!(
            summary,
            ImportSummary {
                added: 0,
                updated: 2,
                skipped: 0
            }
        );
        let web = again.host(web.id).unwrap();
        assert_eq!(web.address, "3.250.9.9");
        assert_eq!(web.label, "Web de producción");
        assert_eq!(web.group, None);
        assert_eq!(again.groups.len(), 1, "no se duplica el grupo");
    }

    #[test]
    fn machines_without_an_address_are_skipped() {
        let mut hosts = parse_digitalocean(DROPLETS).unwrap();
        hosts[0].public_ip = None;
        hosts[0].private_ip = None;
        let (data, summary) = import_into(&VaultData::default(), &hosts, "DO", false);
        assert_eq!(summary.skipped, 1);
        assert!(data.hosts.is_empty() && data.groups.is_empty());
    }
}
