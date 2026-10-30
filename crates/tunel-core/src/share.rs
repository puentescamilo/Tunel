//! Mover hosts y grupos entre la bóveda personal y los Teams.
//!
//! Un host que pasa a un Team se sincroniza con sus miembros, pero la identidad y la
//! clave a las que apunta pueden seguir en otro espacio: los demás no las tendrían, y
//! sacarlas de ese espacio dejaría sin credenciales a otros hosts que las usan. Por eso
//! se elige qué hacer con ellas: copiarlas al espacio de destino (la copia es nueva y lo
//! original no cambia) o quitárselas al host para que cada cual ponga las suyas.

use crate::model::{GroupId, HostId, Identity, IdentityId, KeyId, SshKey};
use crate::vault::VaultData;
use std::collections::HashMap;

/// Qué hacer con la identidad de un host o grupo que cambia de espacio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credentials {
    /// Copiar la identidad (y su clave) al espacio de destino.
    Copy,
    /// Dejar el host o grupo sin identidad.
    Drop,
}

/// Copias hechas en una misma operación, para no duplicar dos veces la misma identidad.
#[derive(Default)]
struct Copies {
    identities: HashMap<IdentityId, IdentityId>,
    keys: HashMap<KeyId, KeyId>,
}

impl Copies {
    /// Identidad a usar en `team`: la misma si ya está allí, o una copia.
    fn identity(
        &mut self,
        data: VaultData,
        id: IdentityId,
        team: Option<&str>,
    ) -> (VaultData, Option<IdentityId>) {
        let Some(identity) = data.identity(id).cloned() else {
            return (data, None);
        };
        if identity.team.as_deref() == team {
            return (data, Some(id));
        }
        if let Some(copy) = self.identities.get(&id) {
            return (data, Some(*copy));
        }
        let (data, key) = match identity.key {
            Some(key) => self.key(data, key, team),
            None => (data, None),
        };
        let copy = Identity {
            id: IdentityId::new(),
            team: team.map(str::to_string),
            key,
            ..identity
        };
        self.identities.insert(id, copy.id);
        (data.with_identity(copy.clone()), Some(copy.id))
    }

    fn key(
        &mut self,
        data: VaultData,
        id: KeyId,
        team: Option<&str>,
    ) -> (VaultData, Option<KeyId>) {
        let Some(key) = data.key(id).cloned() else {
            return (data, None);
        };
        if key.team.as_deref() == team {
            return (data, Some(id));
        }
        if let Some(copy) = self.keys.get(&id) {
            return (data, Some(*copy));
        }
        let copy = SshKey {
            id: KeyId::new(),
            team: team.map(str::to_string),
            ..key
        };
        self.keys.insert(id, copy.id);
        (data.with_key(copy.clone()), Some(copy.id))
    }

    fn credentials(
        &mut self,
        data: VaultData,
        identity: Option<IdentityId>,
        team: Option<&str>,
        credentials: Credentials,
    ) -> (VaultData, Option<IdentityId>) {
        match (identity, credentials) {
            (Some(id), Credentials::Copy) => self.identity(data, id, team),
            (Some(id), Credentials::Drop) => {
                // Una identidad que ya está en el destino se conserva.
                let same = data.identity(id).is_some_and(|i| i.team.as_deref() == team);
                (data, same.then_some(id))
            }
            (None, _) => (data, None),
        }
    }
}

/// Pasa el host al espacio `team` (`None` es la bóveda personal).
pub fn move_host(
    data: &VaultData,
    host: HostId,
    team: Option<&str>,
    credentials: Credentials,
) -> VaultData {
    move_hosts(
        data.clone(),
        &[host],
        team,
        credentials,
        &mut Copies::default(),
    )
}

fn move_hosts(
    mut data: VaultData,
    hosts: &[HostId],
    team: Option<&str>,
    credentials: Credentials,
    copies: &mut Copies,
) -> VaultData {
    for id in hosts {
        let Some(host) = data.host(*id).cloned() else {
            continue;
        };
        let (next, identity) = copies.credentials(data, host.identity, team, credentials);
        // Un grupo que se queda en otro espacio no existiría para los demás.
        let group = host
            .group
            .filter(|g| next.group(*g).is_some_and(|g| g.team.as_deref() == team));
        data = next.with_host(crate::model::Host {
            team: team.map(str::to_string),
            identity,
            group,
            ..host
        });
    }
    data
}

/// El grupo y todo lo que cuelga de él: subgrupos y sus hosts.
fn subtree(data: &VaultData, root: GroupId) -> Vec<GroupId> {
    let mut found = vec![root];
    let mut i = 0;
    while i < found.len() {
        let parent = found[i];
        let children: Vec<GroupId> = data
            .groups
            .iter()
            .filter(|g| g.parent == Some(parent) && !found.contains(&g.id))
            .map(|g| g.id)
            .collect();
        found.extend(children);
        i += 1;
    }
    found
}

/// Pasa el grupo, sus subgrupos y todos sus hosts al espacio `team`. Si el grupo padre
/// queda en otro espacio, el grupo pasa a la raíz.
pub fn move_group(
    data: &VaultData,
    group: GroupId,
    team: Option<&str>,
    credentials: Credentials,
) -> VaultData {
    let groups = subtree(data, group);
    let mut copies = Copies::default();
    let mut data = data.clone();
    for id in &groups {
        let Some(g) = data.group(*id).cloned() else {
            continue;
        };
        let (next, identity) = copies.credentials(data, g.identity, team, credentials);
        let parent = g.parent.filter(|p| groups.contains(p));
        data = next.with_group(crate::model::Group {
            team: team.map(str::to_string),
            identity,
            parent,
            ..g
        });
    }
    let hosts: Vec<HostId> = data
        .hosts
        .iter()
        .filter(|h| h.group.is_some_and(|g| groups.contains(&g)))
        .map(|h| h.id)
        .collect();
    move_hosts(data, &hosts, team, credentials, &mut copies)
}

/// La identidad del host (propia o heredada del grupo) está en otro espacio que el host:
/// los demás miembros del Team no la tendrán.
pub fn credentials_elsewhere(data: &VaultData, host: HostId) -> bool {
    let Some(host) = data.host(host) else {
        return false;
    };
    let identity = host.identity.or_else(|| {
        host.group
            .and_then(|g| data.group(g))
            .and_then(|g| g.identity)
    });
    identity
        .and_then(|i| data.identity(i))
        .is_some_and(|i| i.team != host.team)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, Host};

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn vault() -> (VaultData, HostId, IdentityId, KeyId) {
        let key = SshKey::new("clave", "-----BEGIN OPENSSH PRIVATE KEY-----");
        let identity = Identity {
            key: Some(key.id),
            ..Identity::new("deploy", "deploy")
        };
        let host = Host {
            identity: Some(identity.id),
            ..Host::new("web", "10.0.0.1")
        };
        let other = Host {
            identity: Some(identity.id),
            ..Host::new("otro", "10.0.0.2")
        };
        let ids = (host.id, identity.id, key.id);
        let data = VaultData::default()
            .with_key(key)
            .with_identity(identity)
            .with_host(host)
            .with_host(other);
        (data, ids.0, ids.1, ids.2)
    }

    #[test]
    fn copying_credentials_leaves_the_personal_ones_untouched() {
        let (data, host, identity, key) = vault();
        let moved = move_host(&data, host, Some(TEAM), Credentials::Copy);
        let shared = moved.host(host).unwrap();
        assert_eq!(shared.team.as_deref(), Some(TEAM));
        let copy = moved.identity(shared.identity.unwrap()).unwrap();
        assert_ne!(copy.id, identity);
        assert_eq!(copy.team.as_deref(), Some(TEAM));
        let key_copy = moved.key(copy.key.unwrap()).unwrap();
        assert_ne!(key_copy.id, key);
        assert_eq!(key_copy.team.as_deref(), Some(TEAM));
        // Lo personal sigue igual y el otro host conserva su identidad.
        assert_eq!(moved.identity(identity).unwrap().team, None);
        assert_eq!(moved.key(key).unwrap().team, None);
        assert!(
            moved
                .hosts
                .iter()
                .any(|h| h.label == "otro" && h.identity == Some(identity))
        );
        assert!(!credentials_elsewhere(&moved, host));
    }

    #[test]
    fn a_host_leaves_a_group_that_stays_behind() {
        let (data, host, _, _) = vault();
        let group = Group::new("personal");
        let data = data.with_group(group.clone()).with_host(Host {
            group: Some(group.id),
            ..data.host(host).unwrap().clone()
        });
        let moved = move_host(&data, host, Some(TEAM), Credentials::Copy);
        assert_eq!(moved.host(host).unwrap().group, None);
        assert_eq!(moved.group(group.id).unwrap().team, None);
    }

    #[test]
    fn dropping_credentials_leaves_the_host_without_identity() {
        let (data, host, _, _) = vault();
        let moved = move_host(&data, host, Some(TEAM), Credentials::Drop);
        assert_eq!(moved.host(host).unwrap().identity, None);
        assert_eq!(moved.identities.len(), 1);
        assert_eq!(moved.keys.len(), 1);
    }

    #[test]
    fn a_group_moves_with_its_subgroups_and_hosts_sharing_one_copy() {
        let (data, host, identity, _) = vault();
        let root = Group {
            identity: Some(identity),
            ..Group::new("producción")
        };
        let child = Group {
            parent: Some(root.id),
            ..Group::new("web")
        };
        let outside = Group::new("otro");
        let data = data
            .with_group(root.clone())
            .with_group(child.clone())
            .with_group(outside.clone())
            .with_host(Host {
                group: Some(child.id),
                ..data.host(host).unwrap().clone()
            });
        let moved = move_group(&data, root.id, Some(TEAM), Credentials::Copy);
        for id in [root.id, child.id] {
            assert_eq!(moved.group(id).unwrap().team.as_deref(), Some(TEAM));
        }
        assert_eq!(moved.group(outside.id).unwrap().team, None);
        assert_eq!(moved.group(child.id).unwrap().parent, Some(root.id));
        let shared = moved.host(host).unwrap();
        assert_eq!(shared.team.as_deref(), Some(TEAM));
        // El grupo y el host comparten la misma copia de la identidad.
        assert_eq!(shared.identity, moved.group(root.id).unwrap().identity);
        assert_eq!(moved.identities.len(), 2);
    }

    #[test]
    fn a_group_moved_alone_leaves_its_parent_behind() {
        let parent = Group::new("padre");
        let child = Group {
            parent: Some(parent.id),
            ..Group::new("hijo")
        };
        let data = VaultData::default()
            .with_group(parent.clone())
            .with_group(child.clone());
        let moved = move_group(&data, child.id, Some(TEAM), Credentials::Copy);
        assert_eq!(moved.group(child.id).unwrap().parent, None);
        assert_eq!(moved.group(parent.id).unwrap().team, None);
    }

    #[test]
    fn moving_back_to_personal_copies_the_team_credentials() {
        let (data, host, _, _) = vault();
        let shared = move_host(&data, host, Some(TEAM), Credentials::Copy);
        let back = move_host(&shared, host, None, Credentials::Copy);
        let identity = back
            .identity(back.host(host).unwrap().identity.unwrap())
            .unwrap();
        assert_eq!(identity.team, None);
        assert!(!credentials_elsewhere(&back, host));
    }

    #[test]
    fn credentials_in_another_space_are_detected() {
        let (data, host, _, _) = vault();
        let mut shared = data.host(host).unwrap().clone();
        shared.team = Some(TEAM.into());
        let data = data.with_host(shared);
        assert!(credentials_elsewhere(&data, host));
    }
}
