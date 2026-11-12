//! La bóveda vista desde las apps: abrirla o crearla y leer hosts y grupos.

use crate::TunelError;
use std::sync::{Arc, Mutex, MutexGuard};
use tunel_core::crypto::KdfParams;
use tunel_core::{Group, Host, Protocol, UnlockedVault};

/// Un host tal como lo muestra la lista. Sin secretos: esos se quedan en el núcleo.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostSummary {
    pub id: String,
    /// El nombre del host, o su dirección si no tiene nombre.
    pub label: String,
    pub address: String,
    /// El puerto del host, o el de su grupo, o el habitual del protocolo.
    pub port: u16,
    /// «SSH», «Mosh», «Telnet» o «Serial».
    pub protocol: String,
    pub group_id: Option<String>,
    /// Team al que pertenece; `None` si es de la bóveda personal.
    pub team: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub team: Option<String>,
    /// Icono de Phosphor por su nombre; `None` es la carpeta.
    pub icon: Option<String>,
}

/// Si ya hay una bóveda en `path`, para decidir entre crearla o desbloquearla.
#[uniffi::export]
pub fn vault_exists(path: String) -> bool {
    UnlockedVault::exists(std::path::Path::new(&path))
}

/// Bóveda abierta. Mientras exista, nadie más puede abrir el mismo archivo.
#[derive(uniffi::Object)]
pub struct Vault {
    inner: Mutex<UnlockedVault>,
}

#[uniffi::export]
impl Vault {
    /// Crea una bóveda vacía cifrada con la contraseña maestra.
    #[uniffi::constructor]
    pub fn create(path: String, password: String) -> Result<Arc<Self>, TunelError> {
        let vault = UnlockedVault::create(path, &password, KdfParams::RECOMMENDED)?;
        Ok(Self::wrap(vault))
    }

    /// Abre la bóveda con la contraseña maestra. Deriva la clave con Argon2id: tarda, así que
    /// la app la llama fuera del hilo principal.
    #[uniffi::constructor]
    pub fn unlock(path: String, password: String) -> Result<Arc<Self>, TunelError> {
        let vault = UnlockedVault::unlock(path, &password)?;
        Ok(Self::wrap(vault))
    }

    /// Hosts ordenados por nombre, sin distinguir mayúsculas.
    pub fn hosts(&self) -> Vec<HostSummary> {
        let vault = self.lock();
        let mut hosts: Vec<_> = vault
            .data
            .hosts
            .iter()
            .map(|h| summarize_host(h, &vault.data.groups))
            .collect();
        hosts.sort_by_key(|h| h.label.to_lowercase());
        hosts
    }

    /// Grupos ordenados por nombre, sin distinguir mayúsculas.
    pub fn groups(&self) -> Vec<GroupSummary> {
        let vault = self.lock();
        let mut groups: Vec<_> = vault.data.groups.iter().map(summarize_group).collect();
        groups.sort_by_key(|g| g.name.to_lowercase());
        groups
    }

    /// Hosts que coinciden con `query` (nombre, dirección o etiquetas), con la misma búsqueda
    /// que el escritorio.
    pub fn search_hosts(&self, query: String) -> Vec<HostSummary> {
        let vault = self.lock();
        vault
            .data
            .search_hosts(&query)
            .into_iter()
            .map(|h| summarize_host(h, &vault.data.groups))
            .collect()
    }
}

impl Vault {
    fn wrap(vault: UnlockedVault) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(vault),
        })
    }

    /// Un pánico con el cerrojo tomado no deja la bóveda a medias (solo se lee), así que se
    /// sigue usando.
    pub(crate) fn lock(&self) -> MutexGuard<'_, UnlockedVault> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn default_port(protocol: Option<&Protocol>) -> u16 {
    match protocol {
        Some(Protocol::Telnet) => 23,
        Some(Protocol::Serial { .. }) => 0,
        Some(Protocol::Ssh | Protocol::Mosh { .. }) | None => 22,
    }
}

fn summarize_host(host: &Host, groups: &[Group]) -> HostSummary {
    let group_port = host
        .group
        .and_then(|id| groups.iter().find(|g| g.id == id))
        .and_then(|g| g.port);
    HostSummary {
        id: host.id.0.to_string(),
        label: host.display_name().to_string(),
        address: host.address.clone(),
        port: host
            .port
            .or(group_port)
            .unwrap_or_else(|| default_port(host.protocol.as_ref())),
        protocol: host
            .protocol
            .as_ref()
            .map_or(Protocol::Ssh.label(), Protocol::label)
            .to_string(),
        group_id: host.group.map(|g| g.0.to_string()),
        team: host.team.clone(),
        tags: host.tags.clone(),
    }
}

fn summarize_group(group: &Group) -> GroupSummary {
    GroupSummary {
        id: group.id.0.to_string(),
        name: group.name.clone(),
        parent_id: group.parent.map(|p| p.0.to_string()),
        team: group.team.clone(),
        icon: group.icon.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::VaultData;

    const PASSWORD: &str = "correcta-caballo";

    fn vault_with(data: VaultData) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut vault = UnlockedVault::create(&path, PASSWORD, KdfParams::FAST_FOR_TESTS).unwrap();
        vault.commit(data).unwrap();
        (dir, path.to_string_lossy().into_owned())
    }

    fn host(label: &str) -> Host {
        Host {
            label: label.into(),
            address: format!("{label}.example.com"),
            ..Host::default()
        }
    }

    #[test]
    fn unlocks_a_desktop_vault_and_lists_its_hosts_by_name() {
        let data = VaultData {
            hosts: vec![host("web"), host("Base de datos")],
            ..VaultData::default()
        };
        let (_dir, path) = vault_with(data);

        let vault = Vault::unlock(path, PASSWORD.into()).unwrap();

        let labels: Vec<_> = vault.hosts().into_iter().map(|h| h.label).collect();
        assert_eq!(labels, ["Base de datos", "web"]);
    }

    #[test]
    fn a_host_without_a_name_is_shown_by_its_address() {
        let unnamed = Host {
            label: String::new(),
            ..host("srv")
        };

        assert_eq!(summarize_host(&unnamed, &[]).label, "srv.example.com");
    }

    #[test]
    fn a_wrong_password_is_reported_as_such() {
        let (_dir, path) = vault_with(VaultData::default());

        let error = Vault::unlock(path, "otra-contraseña".into()).err().unwrap();

        assert!(matches!(error, TunelError::WrongPassword));
    }

    #[test]
    fn a_short_password_is_rejected_when_creating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json").to_string_lossy().into_owned();

        let error = Vault::create(path.clone(), "corta".into()).err().unwrap();

        assert!(matches!(error, TunelError::WeakPassword { min: 8 }));
        assert!(!vault_exists(path));
    }

    #[test]
    fn the_same_vault_cannot_be_opened_twice() {
        let (_dir, path) = vault_with(VaultData::default());
        let _open = Vault::unlock(path.clone(), PASSWORD.into()).unwrap();

        let error = Vault::unlock(path, PASSWORD.into()).err().unwrap();

        assert!(matches!(error, TunelError::Locked));
    }

    #[test]
    fn the_port_comes_from_the_host_then_the_group_then_the_protocol() {
        let group = Group {
            port: Some(2222),
            ..Group::new("Producción")
        };
        let in_group = Host {
            group: Some(group.id),
            ..host("a")
        };
        let own_port = Host {
            port: Some(2200),
            group: Some(group.id),
            ..host("b")
        };
        let telnet = Host {
            protocol: Some(Protocol::Telnet),
            ..host("c")
        };
        let groups = [group];

        assert_eq!(summarize_host(&in_group, &groups).port, 2222);
        assert_eq!(summarize_host(&own_port, &groups).port, 2200);
        assert_eq!(summarize_host(&telnet, &groups).port, 23);
        assert_eq!(summarize_host(&telnet, &groups).protocol, "Telnet");
    }

    #[test]
    fn groups_keep_their_parent_and_team() {
        let parent = Group::new("Clientes");
        let child = Group {
            parent: Some(parent.id),
            team: Some("team-1".into()),
            ..Group::new("ACME")
        };
        let data = VaultData {
            groups: vec![parent.clone(), child],
            ..VaultData::default()
        };
        let (_dir, path) = vault_with(data);

        let groups = Vault::unlock(path, PASSWORD.into()).unwrap().groups();

        let acme = groups.iter().find(|g| g.name == "ACME").unwrap();
        assert_eq!(acme.parent_id, Some(parent.id.0.to_string()));
        assert_eq!(acme.team.as_deref(), Some("team-1"));
    }

    #[test]
    fn searching_matches_the_address() {
        let data = VaultData {
            hosts: vec![host("web"), host("correo")],
            ..VaultData::default()
        };
        let (_dir, path) = vault_with(data);

        let found = Vault::unlock(path, PASSWORD.into())
            .unwrap()
            .search_hosts("correo.example".into());

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label, "correo");
    }
}
