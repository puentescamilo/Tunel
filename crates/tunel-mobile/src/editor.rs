//! Crear, editar y borrar hosts desde el móvil. Solo los de la bóveda personal: los de un
//! Team se editan desde el escritorio, donde están los permisos y el registro de auditoría.
//!
//! Los cambios se guardan en la bóveda y suben a la cuenta en la siguiente sincronización,
//! como en el escritorio.

use crate::vault::{commit_local, summarize_host};
use crate::{HostSummary, TunelError, Vault};
use std::str::FromStr;
use tunel_core::{GroupId, Host, HostId, Identity, IdentityId, Protocol, ResolveError, VaultData};
use uuid::Uuid;

/// Un host tal como lo edita el formulario. Sin secretos: la contraseña de una identidad
/// nueva solo se escribe, no se lee.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostDraft {
    /// `None` para un host nuevo.
    pub id: Option<String>,
    pub label: String,
    pub address: String,
    /// `None` es el del grupo o el habitual del protocolo.
    pub port: Option<u16>,
    /// «SSH», «Mosh» o «Telnet».
    pub protocol: String,
    pub group_id: Option<String>,
    pub identity_id: Option<String>,
    /// Si no está vacío, se crea una identidad nueva con este usuario y se usa en lugar de
    /// `identity_id`.
    pub new_username: String,
    pub new_password: String,
    pub tags: Vec<String>,
    /// En orden de salto.
    pub jump_host_ids: Vec<String>,
    pub notes: String,
}

/// Una identidad para elegirla en el formulario: nombre y usuario, sin la credencial.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentitySummary {
    pub id: String,
    pub label: String,
    pub username: String,
    pub team: Option<String>,
}

/// Los protocolos que se pueden elegir en el móvil. El puerto serie no tiene sentido aquí.
const PROTOCOLS: [&str; 3] = ["SSH", "Mosh", "Telnet"];

#[uniffi::export]
impl Vault {
    /// Un formulario vacío para un host nuevo, en el grupo `group_id` si se da.
    pub fn new_host_draft(&self, group_id: Option<String>) -> HostDraft {
        HostDraft {
            id: None,
            label: String::new(),
            address: String::new(),
            port: None,
            protocol: "SSH".into(),
            group_id,
            identity_id: None,
            new_username: String::new(),
            new_password: String::new(),
            tags: Vec::new(),
            jump_host_ids: Vec::new(),
            notes: String::new(),
        }
    }

    /// El formulario de un host que ya existe.
    pub fn host_draft(&self, host_id: String) -> Result<HostDraft, TunelError> {
        let vault = self.lock();
        let host = editable(&vault.data, &host_id)?;
        Ok(HostDraft {
            id: Some(host_id),
            label: host.label.clone(),
            address: host.address.clone(),
            port: host.port,
            protocol: host.protocol().label().to_string(),
            group_id: host.group.map(|g| g.0.to_string()),
            identity_id: host.identity.map(|i| i.0.to_string()),
            new_username: String::new(),
            new_password: String::new(),
            tags: host.tags.clone(),
            jump_host_ids: host.jump_hosts.iter().map(|j| j.0.to_string()).collect(),
            notes: host.notes.clone(),
        })
    }

    /// Si el host se puede editar aquí: existe y es de la bóveda personal.
    pub fn can_edit_host(&self, host_id: String) -> bool {
        editable(&self.lock().data, &host_id).is_ok()
    }

    /// Identidades para elegir, ordenadas por nombre.
    pub fn identities(&self) -> Vec<IdentitySummary> {
        let vault = self.lock();
        let mut identities: Vec<_> = vault
            .data
            .identities
            .iter()
            .map(|i| IdentitySummary {
                id: i.id.0.to_string(),
                label: i.label.clone(),
                username: i.username.clone(),
                team: i.team.clone(),
            })
            .collect();
        identities.sort_by_key(|i| i.label.to_lowercase());
        identities
    }

    /// Guarda el host del formulario y devuelve cómo queda en la lista.
    pub fn save_host(&self, draft: HostDraft) -> Result<HostSummary, TunelError> {
        let mut vault = self.lock();
        let (data, id) = apply(&vault.data, &draft)?;
        commit_local(&mut vault, data)?;
        let host = vault.data.host(id).ok_or(TunelError::HostNotFound)?;
        Ok(summarize_host(host, &vault.data.groups))
    }

    /// Borra el host. Los que saltaban por él dejan de hacerlo.
    pub fn delete_host(&self, host_id: String) -> Result<(), TunelError> {
        let mut vault = self.lock();
        let id = editable(&vault.data, &host_id)?.id;
        let data = vault.data.without_host(id);
        commit_local(&mut vault, data)
    }
}

fn parse_id(id: &str) -> Option<Uuid> {
    Uuid::from_str(id).ok()
}

/// El host `id`, si existe y es personal.
fn editable<'a>(data: &'a VaultData, id: &str) -> Result<&'a Host, TunelError> {
    let host = parse_id(id)
        .and_then(|uuid| data.host(HostId(uuid)))
        .ok_or(TunelError::HostNotFound)?;
    if host.team.is_some() {
        return Err(TunelError::TeamHostReadOnly);
    }
    Ok(host)
}

fn invalid(message: &str) -> TunelError {
    TunelError::InvalidHost {
        message: message.into(),
    }
}

/// La bóveda con el host del formulario guardado, y su id.
pub(crate) fn apply(
    data: &VaultData,
    draft: &HostDraft,
) -> Result<(VaultData, HostId), TunelError> {
    let address = draft.address.trim();
    if address.is_empty() {
        return Err(invalid("La dirección es obligatoria"));
    }
    if address.chars().any(char::is_whitespace) {
        return Err(invalid("La dirección no puede tener espacios"));
    }
    if draft.port == Some(0) {
        return Err(invalid("El puerto tiene que estar entre 1 y 65535"));
    }
    let existing = draft
        .id
        .as_deref()
        .map(|id| editable(data, id))
        .transpose()?;
    let protocol = protocol(&draft.protocol, existing)?;
    let group = optional_id(&draft.group_id, "Ese grupo ya no existe", |id| {
        data.group(GroupId(id)).map(|g| g.id)
    })?;
    let mut result = data.clone();
    let identity = match draft.new_username.trim() {
        "" => optional_id(&draft.identity_id, "Esa identidad ya no existe", |id| {
            data.identity(IdentityId(id)).map(|i| i.id)
        })?,
        username => {
            let label = if draft.label.trim().is_empty() {
                address
            } else {
                draft.label.trim()
            };
            // Identity borra sus secretos al soltarse: no admite `..Identity::new(..)`.
            let mut identity = Identity::new(format!("{username}@{label}"), username);
            identity.password = Some(draft.new_password.clone()).filter(|p| !p.is_empty());
            let id = identity.id;
            result = result.with_identity(identity);
            Some(id)
        }
    };
    let jump_hosts = draft
        .jump_host_ids
        .iter()
        .map(|id| {
            parse_id(id)
                .and_then(|uuid| data.host(HostId(uuid)))
                .map(|h| h.id)
                .ok_or_else(|| invalid("Uno de los jump hosts ya no existe"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let host = Host {
        label: draft.label.trim().to_string(),
        address: address.to_string(),
        port: draft.port,
        protocol: Some(protocol),
        group,
        identity,
        tags: tags(&draft.tags),
        jump_hosts,
        notes: draft.notes.clone(),
        ..existing.cloned().unwrap_or_default()
    };
    let id = host.id;
    if host.jump_hosts.contains(&id) {
        return Err(invalid("Un host no puede saltar a través de sí mismo"));
    }
    let result = result.with_host(host);
    match result.resolve_jump_chain(id) {
        Err(ResolveError::JumpCycle) => Err(invalid(
            "Los jump hosts forman un ciclo: uno de ellos ya salta a través de este host",
        )),
        _ => Ok((result, id)),
    }
}

/// El protocolo elegido. Si no cambia, se conserva lo que el móvil no edita (el comando de
/// Mosh).
fn protocol(name: &str, existing: Option<&Host>) -> Result<Protocol, TunelError> {
    if !PROTOCOLS.contains(&name) {
        return Err(invalid(
            "Ese protocolo no se puede elegir en este dispositivo",
        ));
    }
    let current = existing.map(Host::protocol);
    Ok(match (name, current) {
        (_, Some(current)) if current.label() == name => current,
        ("Mosh", _) => Protocol::Mosh {
            server_command: None,
        },
        ("Telnet", _) => Protocol::Telnet,
        _ => Protocol::Ssh,
    })
}

fn optional_id<T>(
    id: &Option<String>,
    missing: &str,
    find: impl FnOnce(Uuid) -> Option<T>,
) -> Result<Option<T>, TunelError> {
    match id.as_deref().filter(|id| !id.is_empty()) {
        None => Ok(None),
        Some(id) => parse_id(id)
            .and_then(find)
            .map(Some)
            .ok_or_else(|| invalid(missing)),
    }
}

/// Sin espacios alrededor, sin vacías y sin repetir.
fn tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        if !out.iter().any(|t| t == tag) {
            out.push(tag.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::Group;

    fn draft(address: &str) -> HostDraft {
        HostDraft {
            id: None,
            label: String::new(),
            address: address.into(),
            port: None,
            protocol: "SSH".into(),
            group_id: None,
            identity_id: None,
            new_username: String::new(),
            new_password: String::new(),
            tags: Vec::new(),
            jump_host_ids: Vec::new(),
            notes: String::new(),
        }
    }

    fn message(error: TunelError) -> String {
        error.to_string()
    }

    #[test]
    fn a_new_host_is_added_with_its_fields() {
        let group = Group::new("Web");
        let data = VaultData::default().with_group(group.clone());
        let new = HostDraft {
            label: " web-1 ".into(),
            port: Some(2222),
            group_id: Some(group.id.0.to_string()),
            tags: vec!["prod".into(), " prod ".into(), "".into(), "eu".into()],
            ..draft(" web1.example.com ")
        };

        let (data, id) = apply(&data, &new).unwrap();

        let host = data.host(id).unwrap();
        assert_eq!(host.label, "web-1");
        assert_eq!(host.address, "web1.example.com");
        assert_eq!(host.port, Some(2222));
        assert_eq!(host.group, Some(group.id));
        assert_eq!(host.tags, ["prod", "eu"]);
        assert_eq!(host.protocol, Some(Protocol::Ssh));
    }

    #[test]
    fn editing_keeps_what_the_phone_does_not_show() {
        let original = Host {
            protocol: Some(Protocol::Mosh {
                server_command: Some("mosh-server new -l LANG=es".into()),
            }),
            agent_forwarding: true,
            env: [("TERM".to_string(), "xterm".to_string())].into(),
            ..Host::new("db", "db.example.com")
        };
        let data = VaultData::default().with_host(original.clone());
        let edit = HostDraft {
            id: Some(original.id.0.to_string()),
            label: "base de datos".into(),
            protocol: "Mosh".into(),
            ..draft("db.example.com")
        };

        let (data, _) = apply(&data, &edit).unwrap();

        let host = data.host(original.id).unwrap();
        assert_eq!(host.label, "base de datos");
        assert_eq!(host.protocol, original.protocol);
        assert!(host.agent_forwarding);
        assert_eq!(host.env, original.env);
        assert_eq!(data.hosts.len(), 1);
    }

    #[test]
    fn a_new_username_creates_an_identity_with_its_password() {
        let new = HostDraft {
            label: "web".into(),
            new_username: "deploy".into(),
            new_password: "s3creta".into(),
            ..draft("web.example.com")
        };

        let (data, id) = apply(&VaultData::default(), &new).unwrap();

        let identity = data
            .identity(data.host(id).unwrap().identity.unwrap())
            .unwrap();
        assert_eq!(identity.label, "deploy@web");
        assert_eq!(identity.username, "deploy");
        assert_eq!(identity.password.as_deref(), Some("s3creta"));
        assert_eq!(identity.team, None);
    }

    #[test]
    fn jump_hosts_are_kept_in_order() {
        let (a, b) = (Host::new("a", "a.example"), Host::new("b", "b.example"));
        let data = VaultData::default()
            .with_host(a.clone())
            .with_host(b.clone());
        let new = HostDraft {
            jump_host_ids: vec![b.id.0.to_string(), a.id.0.to_string()],
            ..draft("target.example")
        };

        let (data, id) = apply(&data, &new).unwrap();

        assert_eq!(data.host(id).unwrap().jump_hosts, [b.id, a.id]);
    }

    #[test]
    fn a_jump_cycle_is_rejected() {
        let target = Host::new("target", "target.example");
        let jump = Host {
            jump_hosts: vec![target.id],
            ..Host::new("jump", "jump.example")
        };
        let data = VaultData::default()
            .with_host(target.clone())
            .with_host(jump.clone());
        let edit = HostDraft {
            id: Some(target.id.0.to_string()),
            jump_host_ids: vec![jump.id.0.to_string()],
            ..draft("target.example")
        };

        let error = apply(&data, &edit).err().unwrap();

        assert!(message(error).contains("ciclo"));
    }

    #[test]
    fn invalid_fields_are_explained() {
        let data = VaultData::default();
        let cases = [
            (draft("  "), "La dirección es obligatoria"),
            (draft("web 1"), "La dirección no puede tener espacios"),
            (
                HostDraft {
                    port: Some(0),
                    ..draft("web")
                },
                "El puerto",
            ),
            (
                HostDraft {
                    protocol: "Serial".into(),
                    ..draft("web")
                },
                "protocolo",
            ),
            (
                HostDraft {
                    group_id: Some(Uuid::new_v4().to_string()),
                    ..draft("web")
                },
                "grupo",
            ),
            (
                HostDraft {
                    jump_host_ids: vec!["no-es-un-id".into()],
                    ..draft("web")
                },
                "jump hosts",
            ),
        ];

        for (draft, expected) in cases {
            let error = message(apply(&data, &draft).err().unwrap());
            assert!(
                error.contains(expected),
                "{error:?} no contiene {expected:?}"
            );
        }
    }

    #[test]
    fn team_hosts_cannot_be_edited_here() {
        let team_host = Host {
            team: Some("team-1".into()),
            ..Host::new("t", "t.example")
        };
        let data = VaultData::default().with_host(team_host.clone());
        let edit = HostDraft {
            id: Some(team_host.id.0.to_string()),
            ..draft("otro.example")
        };

        let error = apply(&data, &edit).err().unwrap();

        assert!(matches!(error, TunelError::TeamHostReadOnly));
    }
}
