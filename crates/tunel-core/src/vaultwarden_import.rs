//! Hosts desde los elementos de Vaultwarden (8d): cada URI `ssh://`, `telnet://` o `mosh://` de
//! un elemento es un host, en un grupo por colección, con una identidad vinculada al elemento.
//!
//! Volver a importar no duplica: cada host recuerda de qué elemento y URI salió (`cloud_id`).
//! Lo que el usuario cambió después en Túnel (nombre, grupo, tema…) se respeta.

use crate::cloud::ImportSummary;
use crate::model::{Group, GroupId, Host, Identity, Protocol, VaultwardenLink};
use crate::vault::VaultData;

/// Un elemento de Vaultwarden ya descifrado, solo con lo que hace falta para importar.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceItem {
    pub item_id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    /// Nombre de su colección, con `/` para anidar (`Clientes/ACME/Switches`); `None` si es
    /// personal.
    pub collection: Option<String>,
}

/// Una URI que se puede usar para conectar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub protocol: Protocol,
    pub address: String,
    pub port: Option<u16>,
    pub user: Option<String>,
}

impl Target {
    fn scheme(&self) -> &'static str {
        match self.protocol {
            Protocol::Telnet => "telnet",
            Protocol::Mosh { .. } => "mosh",
            Protocol::Ssh | Protocol::Serial { .. } => "ssh",
        }
    }
}

/// Lee `ssh://usuario@host:puerto`, `telnet://host` o `mosh://host`. Las direcciones IPv6 van
/// entre corchetes. Lo demás (https, sin esquema…) no es un host.
pub fn parse_uri(uri: &str) -> Option<Target> {
    let (scheme, rest) = uri.trim().split_once("://")?;
    let protocol = match scheme.to_ascii_lowercase().as_str() {
        "ssh" => Protocol::Ssh,
        "telnet" => Protocol::Telnet,
        "mosh" => Protocol::Mosh {
            server_command: None,
        },
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let (user, host_port) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()).filter(|u| !u.is_empty()), host),
        None => (None, authority),
    };
    let (address, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (address, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':').map(str::parse).transpose().ok()?;
        (address.to_string(), port)
    } else {
        match host_port.rsplit_once(':') {
            Some((address, port)) => (address.to_string(), Some(port.parse().ok()?)),
            None => (host_port.to_string(), None),
        }
    };
    if address.is_empty() || address.contains(char::is_whitespace) {
        return None;
    }
    Some(Target {
        protocol,
        address,
        port,
        user,
    })
}

/// Las URIs de `item` que se pueden importar.
pub fn targets(item: &SourceItem) -> Vec<Target> {
    item.uris.iter().filter_map(|u| parse_uri(u)).collect()
}

fn source_id(item: &SourceItem, target: &Target) -> String {
    let port = target.port.map(|p| p.to_string()).unwrap_or_default();
    format!(
        "vaultwarden:{}:{}:{}:{port}",
        item.item_id,
        target.scheme(),
        target.address.to_lowercase()
    )
}

/// El grupo de la ruta `path` dentro de `parent`, creándolo si no existe (en la bóveda
/// personal).
fn group_path(data: &mut VaultData, parent: Option<GroupId>, path: &[&str]) -> Option<GroupId> {
    let mut current = parent;
    for name in path.iter().map(|n| n.trim()).filter(|n| !n.is_empty()) {
        let found = data
            .groups
            .iter()
            .find(|g| g.name == name && g.parent == current && g.team.is_none())
            .map(|g| g.id);
        current = Some(found.unwrap_or_else(|| {
            let new = Group {
                parent: current,
                ..Group::new(name)
            };
            let id = new.id;
            *data = data.with_group(new);
            id
        }));
    }
    current
}

/// La identidad personal vinculada a `item`: la que ya hay o una nueva.
fn identity_for(data: &mut VaultData, item: &SourceItem, user: Option<&str>) -> Identity {
    let existing = data.identities.iter().find(|i| {
        i.team.is_none()
            && i.vaultwarden
                .as_ref()
                .is_some_and(|l| l.item_id == item.item_id)
    });
    if let Some(identity) = existing {
        return identity.clone();
    }
    // Sin usuario propio se usa el del elemento al conectar, aunque cambie en Vaultwarden.
    let username = match &item.username {
        Some(_) => String::new(),
        None => user.unwrap_or_default().to_string(),
    };
    let mut identity = Identity::new(item.name.clone(), username);
    identity.vaultwarden = Some(VaultwardenLink {
        item_id: item.item_id.clone(),
        organization_id: item.organization_id.clone(),
    });
    *data = data.with_identity(identity.clone());
    identity
}

/// Añade a la bóveda personal un host por cada URI de `items`, dentro del grupo `root`.
pub fn import_items(
    data: &VaultData,
    items: &[SourceItem],
    root: &str,
) -> (VaultData, ImportSummary) {
    let mut summary = ImportSummary::default();
    let mut data = data.clone();
    for item in items {
        let found = targets(item);
        if found.is_empty() {
            summary.skipped += 1;
            continue;
        }
        let several = found.len() > 1;
        for target in found {
            let id = source_id(item, &target);
            if data
                .hosts
                .iter()
                .any(|h| h.cloud_id.as_deref() == Some(id.as_str()))
            {
                summary.updated += 1;
                continue;
            }
            let mut path = vec![root];
            if let Some(collection) = &item.collection {
                path.extend(collection.split('/'));
            }
            let group = group_path(&mut data, None, &path);
            let identity = identity_for(&mut data, item, target.user.as_deref());
            let label = if several {
                format!("{} ({})", item.name, target.address)
            } else {
                item.name.clone()
            };
            data = data.with_host(Host {
                group,
                identity: Some(identity.id),
                port: target.port,
                protocol: (target.protocol != Protocol::Ssh).then(|| target.protocol.clone()),
                tags: vec!["vaultwarden".into()],
                notes: item.notes.clone().unwrap_or_default(),
                cloud_id: Some(id),
                ..Host::new(label, target.address.clone())
            });
            summary.added += 1;
        }
    }
    (data, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn switch() -> SourceItem {
        SourceItem {
            item_id: "sw-1".into(),
            organization_id: Some("org".into()),
            name: "SW-Core".into(),
            username: Some("admin".into()),
            uris: vec!["ssh://10.0.0.1:2222".into(), "https://10.0.0.1".into()],
            notes: Some("rack 3".into()),
            collection: Some("Clientes/ACME/Switches".into()),
        }
    }

    #[test]
    fn uris_with_a_connection_scheme_become_targets() {
        let ssh = parse_uri("ssh://admin@10.0.0.1:2222").unwrap();
        assert_eq!(ssh.protocol, Protocol::Ssh);
        assert_eq!((ssh.address.as_str(), ssh.port), ("10.0.0.1", Some(2222)));
        assert_eq!(ssh.user.as_deref(), Some("admin"));
        let telnet = parse_uri(" TELNET://ap-piso2.local/ ").unwrap();
        assert_eq!(telnet.protocol, Protocol::Telnet);
        assert_eq!(
            (telnet.address.as_str(), telnet.port),
            ("ap-piso2.local", None)
        );
        let v6 = parse_uri("mosh://[fe80::1]:60001").unwrap();
        assert_eq!((v6.address.as_str(), v6.port), ("fe80::1", Some(60001)));
        assert!(matches!(v6.protocol, Protocol::Mosh { .. }));
        for bad in [
            "https://10.0.0.1",
            "10.0.0.1:22",
            "ssh://",
            "ssh://host:puerto",
            "ssh://a b",
        ] {
            assert!(parse_uri(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn each_uri_is_a_host_in_its_collection_group_with_a_linked_identity() {
        let (data, summary) = import_items(&VaultData::default(), &[switch()], "Vaultwarden");
        assert_eq!(
            summary,
            ImportSummary {
                added: 1,
                updated: 0,
                skipped: 0
            }
        );
        let host = &data.hosts[0];
        assert_eq!(
            (host.label.as_str(), host.address.as_str()),
            ("SW-Core", "10.0.0.1")
        );
        assert_eq!((host.port, host.protocol.clone()), (Some(2222), None));
        assert_eq!(host.notes, "rack 3");

        let names: Vec<&str> = std::iter::successors(host.group.and_then(|g| data.group(g)), |g| {
            g.parent.and_then(|p| data.group(p))
        })
        .map(|g| g.name.as_str())
        .collect();
        assert_eq!(names, ["Switches", "ACME", "Clientes", "Vaultwarden"]);

        let identity = data.identity(host.identity.unwrap()).unwrap();
        let link = identity.vaultwarden.as_ref().unwrap();
        assert_eq!(
            (link.item_id.as_str(), link.organization_id.as_deref()),
            ("sw-1", Some("org"))
        );
        assert_eq!(
            identity.username, "",
            "se usa el usuario del elemento al conectar"
        );
        assert!(identity.password.is_none());
    }

    #[test]
    fn importing_again_does_not_duplicate_and_keeps_user_changes() {
        let (first, _) = import_items(&VaultData::default(), &[switch()], "Vaultwarden");
        let renamed = Host {
            label: "core renombrado".into(),
            ..first.hosts[0].clone()
        };
        let edited = first.with_host(renamed);
        let mut more = switch();
        more.uris.push("telnet://10.0.0.2".into());
        let (second, summary) = import_items(&edited, &[more], "Vaultwarden");
        assert_eq!(
            summary,
            ImportSummary {
                added: 1,
                updated: 1,
                skipped: 0
            }
        );
        assert_eq!(second.hosts.len(), 2);
        assert!(second.hosts.iter().any(|h| h.label == "core renombrado"));
        assert_eq!(second.identities.len(), 1, "una identidad por elemento");
        assert_eq!(second.groups.len(), 4, "los grupos no se repiten");
        let telnet = second
            .hosts
            .iter()
            .find(|h| h.address == "10.0.0.2")
            .unwrap();
        assert_eq!(telnet.label, "SW-Core (10.0.0.2)");
        assert_eq!(telnet.protocol, Some(Protocol::Telnet));
    }

    #[test]
    fn personal_items_go_to_the_root_group_and_items_without_hosts_are_skipped() {
        let personal = SourceItem {
            item_id: "mio".into(),
            name: "Mi VPS".into(),
            username: None,
            uris: vec!["ssh://root@vps.ejemplo.com".into()],
            ..SourceItem::default()
        };
        let web = SourceItem {
            item_id: "web".into(),
            name: "Correo".into(),
            uris: vec!["https://mail.ejemplo.com".into()],
            ..SourceItem::default()
        };
        let (data, summary) = import_items(&VaultData::default(), &[personal, web], "Vaultwarden");
        assert_eq!(
            summary,
            ImportSummary {
                added: 1,
                updated: 0,
                skipped: 1
            }
        );
        let host = &data.hosts[0];
        assert_eq!(data.group(host.group.unwrap()).unwrap().name, "Vaultwarden");
        let identity = data.identity(host.identity.unwrap()).unwrap();
        assert_eq!(
            identity.username, "root",
            "sin usuario en el elemento, el de la URI"
        );
    }
}
