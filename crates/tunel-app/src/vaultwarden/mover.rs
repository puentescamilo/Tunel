//! «Mover a Vaultwarden» (8c): la contraseña de una identidad pasa a un elemento nuevo de
//! Vaultwarden, en la bóveda personal o en una colección, y la identidad queda vinculada.
//!
//! La identidad solo cambia cuando el servidor confirmó el elemento y la sincronización lo
//! trae: si algo falla, la contraseña sigue en Túnel como estaba.

use super::{AppEvent, VwEvent, VwStatus, synced};
use crate::app::TunelApp;
use tunel_core::model::{Identity, IdentityId, Protocol, VaultwardenLink};
use tunel_core::vault::VaultData;
use tunel_vaultwarden::{Collection, NewLogin, Place, Session, Vault, VwError};
use zeroize::Zeroize;

/// Adónde se puede mover una credencial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Personal,
    Collection {
        organization_id: String,
        collection_id: String,
        name: String,
    },
}

impl Destination {
    pub fn label(&self) -> &str {
        match self {
            Destination::Personal => "Mi bóveda personal",
            Destination::Collection { name, .. } => name,
        }
    }

    fn place(&self) -> Place {
        match self {
            Destination::Personal => Place::Personal,
            Destination::Collection {
                organization_id,
                collection_id,
                ..
            } => Place::Organization {
                organization_id: organization_id.clone(),
                collection_ids: vec![collection_id.clone()],
            },
        }
    }

    fn organization_id(&self) -> Option<String> {
        match self {
            Destination::Personal => None,
            Destination::Collection {
                organization_id, ..
            } => Some(organization_id.clone()),
        }
    }
}

/// Los destinos posibles para una identidad: la bóveda personal si la organización no la
/// quitó y la identidad no es de un Team (nadie más del Team podría descifrarla), y las
/// colecciones en las que se puede escribir.
pub fn destinations(
    collections: &[Collection],
    personal_vault_disabled: bool,
    team: Option<&str>,
) -> Vec<Destination> {
    let personal = (team.is_none() && !personal_vault_disabled).then_some(Destination::Personal);
    let mut collections: Vec<Destination> = collections
        .iter()
        .filter(|c| !c.read_only)
        .map(|c| Destination::Collection {
            organization_id: c.organization_id.clone(),
            collection_id: c.id.clone(),
            name: c.name.clone(),
        })
        .collect();
    collections.sort_by_key(|d| d.label().to_lowercase());
    personal.into_iter().chain(collections).collect()
}

fn scheme(protocol: &Protocol) -> Option<&'static str> {
    match protocol {
        Protocol::Ssh => Some("ssh"),
        Protocol::Mosh { .. } => Some("mosh"),
        Protocol::Telnet => Some("telnet"),
        Protocol::Serial { .. } => None,
    }
}

/// El elemento que se crea para `identity`: su usuario y contraseña, y como URI los hosts que
/// la usan (directamente o heredada de su grupo), para que se vea bien también en la web.
/// `None` si no tiene contraseña que mover.
pub fn new_login(data: &VaultData, identity: &Identity) -> Option<NewLogin> {
    let password = identity.password.clone().filter(|p| !p.is_empty())?;
    let mut uris: Vec<String> = data
        .hosts
        .iter()
        .filter_map(|host| {
            let resolved = data.resolve(host.id).ok()?;
            if resolved.identity.as_ref().map(|i| i.id) != Some(identity.id) {
                return None;
            }
            let scheme = scheme(&host.protocol())?;
            Some(format!("{scheme}://{}:{}", host.address, resolved.port))
        })
        .collect();
    uris.sort();
    uris.dedup();
    let name = if identity.label.trim().is_empty() {
        identity.username.clone()
    } else {
        identity.label.clone()
    };
    Some(NewLogin {
        name,
        username: Some(identity.username.clone()).filter(|u| !u.is_empty()),
        password: Some(password),
        uris,
        notes: Some("Movido desde Túnel".into()),
        fields: Vec::new(),
    })
}

pub struct Moved {
    round: u64,
    identity: IdentityId,
    session: Session,
    /// La sincronización de antes, por si falla; con éxito llega la nueva.
    previous: Vault,
    result: Result<(VaultwardenLink, Vault), VwError>,
}

/// Mueve la contraseña guardada de `identity` a `destination`.
pub fn start(app: &mut TunelApp, identity: IdentityId, destination: &Destination) {
    let controller = &mut app.vaultwarden;
    if controller.busy() {
        return;
    }
    let Some(saved) = app
        .vault
        .as_ref()
        .and_then(|v| v.data.identity(identity))
        .cloned()
    else {
        return;
    };
    let Some(data) = app.data() else { return };
    let Some(login) = new_login(data, &saved) else {
        return app.notify("Esta identidad no tiene una contraseña guardada que mover");
    };
    let controller = &mut app.vaultwarden;
    let (Some(mut session), Some(vault)) = (controller.session.take(), controller.vault.take())
    else {
        return app.notify("Conecta Vaultwarden y espera a que sincronice");
    };
    let round = controller.begin();
    controller.status = VwStatus::Syncing;
    let place = destination.place();
    let organization_id = destination.organization_id();
    app.engine.background(async move {
        let result = async {
            let item_id = session.create_login(&vault, &login, &place).await?;
            let fresh = session.sync().await?;
            if fresh.item(&item_id).is_none() {
                return Err(VwError::Unexpected);
            }
            let link = VaultwardenLink {
                item_id,
                organization_id,
            };
            Ok((link, fresh))
        }
        .await;
        AppEvent::Vaultwarden(Box::new(VwEvent::Moved(Moved {
            round,
            identity,
            session,
            previous: vault,
            result,
        })))
    });
}

/// Vincula la identidad y borra su contraseña local; también en el editor si está abierto,
/// para que «Guardar» no la devuelva.
fn link(identity: &Identity, link: &VaultwardenLink) -> Identity {
    let mut linked = identity.clone();
    linked.password.zeroize();
    linked.password = None;
    linked.vaultwarden = Some(link.clone());
    linked
}

pub fn on_moved(app: &mut TunelApp, moved: Moved) {
    if !app.vaultwarden.finish(moved.round) {
        return;
    }
    let (new_link, fresh) = match moved.result {
        Ok(ok) => ok,
        Err(e) => {
            app.vaultwarden.session = Some(moved.session);
            app.vaultwarden.vault = Some(moved.previous);
            // La sincronización que sigue valiendo es la de antes.
            let last = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_millis(app.vaultwarden.synced_at_ms);
            app.vaultwarden.status = VwStatus::Ready { last };
            return app.notify(format!(
                "No se pudo mover a Vaultwarden; la contraseña sigue en Túnel: {e}"
            ));
        }
    };
    drop(moved.previous);
    synced(app, moved.session, fresh);
    let Some(current) = app.data().and_then(|d| d.identity(moved.identity)).cloned() else {
        return;
    };
    let label = current.label.clone();
    if let Some(crate::editor::Editor::Identity(draft)) = app.editor.as_mut()
        && draft.id == moved.identity
    {
        *draft = link(draft, &new_link);
    }
    let Some(data) = app.data().cloned() else {
        return;
    };
    app.commit(data.with_identity(link(&current, &new_link)));
    app.notify(format!(
        "«{label}» ahora usa la credencial de Vaultwarden; la contraseña ya no está en Túnel"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::model::{Group, Host};

    #[test]
    fn the_new_item_carries_the_credential_and_the_hosts_that_use_it() {
        let identity = Identity::new("Switches", "admin").with_password("cisco");
        let group = Group {
            identity: Some(identity.id),
            port: Some(2222),
            ..Group::new("core")
        };
        let direct = Host {
            identity: Some(identity.id),
            ..Host::new("sw-1", "10.0.0.1")
        };
        let inherited = Host {
            group: Some(group.id),
            ..Host::new("sw-2", "10.0.0.2")
        };
        let telnet = Host {
            identity: Some(identity.id),
            protocol: Some(Protocol::Telnet),
            ..Host::new("ap", "10.0.0.3")
        };
        let other = Host::new("otro", "10.0.0.9");
        let data = VaultData::default()
            .with_identity(identity.clone())
            .with_group(group)
            .with_host(direct)
            .with_host(inherited)
            .with_host(telnet)
            .with_host(other);

        let login = new_login(&data, &identity).unwrap();
        assert_eq!(login.name, "Switches");
        assert_eq!(login.username.as_deref(), Some("admin"));
        assert_eq!(login.password.as_deref(), Some("cisco"));
        assert_eq!(
            login.uris,
            [
                "ssh://10.0.0.1:22",
                "ssh://10.0.0.2:2222",
                "telnet://10.0.0.3:23"
            ]
        );
    }

    fn collection(name: &str, read_only: bool) -> Collection {
        Collection {
            id: format!("id-{name}"),
            organization_id: "org".into(),
            name: name.into(),
            hide_passwords: false,
            read_only,
        }
    }

    #[test]
    fn destinations_respect_the_policy_teams_and_read_only_collections() {
        let collections = [
            collection("Switches", false),
            collection("auditoría", true),
            collection("APs", false),
        ];
        let labels = |personal_disabled, team| -> Vec<String> {
            destinations(&collections, personal_disabled, team)
                .iter()
                .map(|d| d.label().to_string())
                .collect()
        };
        assert_eq!(
            labels(false, None),
            ["Mi bóveda personal", "APs", "Switches"]
        );
        assert_eq!(
            labels(true, None),
            ["APs", "Switches"],
            "política de la organización"
        );
        assert_eq!(
            labels(false, Some("acme")),
            ["APs", "Switches"],
            "en un Team"
        );
        assert!(destinations(&[], true, None).is_empty());
    }

    #[test]
    fn without_a_password_there_is_nothing_to_move() {
        let identity = Identity::new("solo clave", "deploy");
        assert!(new_login(&VaultData::default(), &identity).is_none());
        let empty = Identity::new("vacía", "x").with_password("");
        assert!(new_login(&VaultData::default(), &empty).is_none());
    }

    #[test]
    fn linking_clears_the_local_password() {
        let identity = Identity::new("sw", "admin").with_password("cisco");
        let linked = link(
            &identity,
            &VaultwardenLink {
                item_id: "i".into(),
                organization_id: Some("o".into()),
            },
        );
        assert!(linked.password.is_none());
        assert_eq!(linked.vaultwarden.as_ref().unwrap().item_id, "i");
        assert_eq!((linked.id, linked.label.as_str()), (identity.id, "sw"));
    }
}
