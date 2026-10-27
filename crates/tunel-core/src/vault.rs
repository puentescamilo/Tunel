//! Contenido de la bóveda y operaciones puras sobre él.
//!
//! Todas las modificaciones devuelven una bóveda nueva en lugar de cambiar la original.

use crate::model::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub hosts: Vec<Host>,
    pub groups: Vec<Group>,
    pub identities: Vec<Identity>,
    pub keys: Vec<SshKey>,
    pub snippets: Vec<Snippet>,
    pub forwards: Vec<PortForward>,
    pub known_hosts: Vec<KnownHost>,
    pub settings: Settings,
}

/// Resultado de comparar la clave que presenta un servidor con las conocidas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    Trusted,
    /// Primera conexión: pedir confirmación al usuario.
    Unknown,
    /// La clave cambió: posible ataque de intermediario.
    Mismatch {
        expected: String,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("host no encontrado")]
    HostNotFound,
    #[error("la cadena de jump hosts contiene un ciclo")]
    JumpCycle,
}

/// Valores de conexión ya resueltos con herencia de grupos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub host: Host,
    pub port: u16,
    pub identity: Option<Identity>,
    pub key: Option<SshKey>,
}

macro_rules! upsert_and_remove {
    ($upsert:ident, $remove:ident, $field:ident, $ty:ty, $id:ty) => {
        pub fn $upsert(&self, item: $ty) -> Self {
            let mut items: Vec<$ty> = self
                .$field
                .iter()
                .filter(|x| x.id != item.id)
                .cloned()
                .collect();
            items.push(item);
            Self {
                $field: items,
                ..self.clone()
            }
        }

        pub fn $remove(&self, id: $id) -> Self {
            Self {
                $field: self.$field.iter().filter(|x| x.id != id).cloned().collect(),
                ..self.clone()
            }
        }
    };
}

impl VaultData {
    upsert_and_remove!(with_host, without_host_only, hosts, Host, HostId);
    upsert_and_remove!(with_group, without_group_only, groups, Group, GroupId);
    upsert_and_remove!(
        with_identity,
        without_identity_only,
        identities,
        Identity,
        IdentityId
    );
    upsert_and_remove!(with_key, without_key_only, keys, SshKey, KeyId);
    upsert_and_remove!(with_snippet, without_snippet, snippets, Snippet, SnippetId);
    upsert_and_remove!(
        with_forward,
        without_forward,
        forwards,
        PortForward,
        ForwardId
    );

    pub fn host(&self, id: HostId) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }

    pub fn group(&self, id: GroupId) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn identity(&self, id: IdentityId) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == id)
    }

    pub fn key(&self, id: KeyId) -> Option<&SshKey> {
        self.keys.iter().find(|k| k.id == id)
    }

    pub fn snippet(&self, id: SnippetId) -> Option<&Snippet> {
        self.snippets.iter().find(|s| s.id == id)
    }

    /// Elimina el host y las reglas de túnel que dependen de él.
    pub fn without_host(&self, id: HostId) -> Self {
        let base = self.without_host_only(id);
        Self {
            forwards: base
                .forwards
                .iter()
                .filter(|f| f.host != id)
                .cloned()
                .collect(),
            hosts: base
                .hosts
                .iter()
                .map(|h| Host {
                    jump_hosts: h.jump_hosts.iter().copied().filter(|j| *j != id).collect(),
                    ..h.clone()
                })
                .collect(),
            ..base
        }
    }

    /// Elimina el grupo; sus hosts y subgrupos pasan al grupo padre.
    pub fn without_group(&self, id: GroupId) -> Self {
        let parent = self.group(id).and_then(|g| g.parent);
        let base = self.without_group_only(id);
        Self {
            hosts: base
                .hosts
                .iter()
                .map(|h| {
                    if h.group == Some(id) {
                        Host {
                            group: parent,
                            ..h.clone()
                        }
                    } else {
                        h.clone()
                    }
                })
                .collect(),
            groups: base
                .groups
                .iter()
                .map(|g| {
                    if g.parent == Some(id) {
                        Group {
                            parent,
                            ..g.clone()
                        }
                    } else {
                        g.clone()
                    }
                })
                .collect(),
            ..base
        }
    }

    /// Elimina la identidad y la desvincula de hosts y grupos.
    pub fn without_identity(&self, id: IdentityId) -> Self {
        let base = self.without_identity_only(id);
        Self {
            hosts: base
                .hosts
                .iter()
                .map(|h| {
                    if h.identity == Some(id) {
                        Host {
                            identity: None,
                            ..h.clone()
                        }
                    } else {
                        h.clone()
                    }
                })
                .collect(),
            groups: base
                .groups
                .iter()
                .map(|g| {
                    if g.identity == Some(id) {
                        Group {
                            identity: None,
                            ..g.clone()
                        }
                    } else {
                        g.clone()
                    }
                })
                .collect(),
            ..base
        }
    }

    /// Elimina la clave y la desvincula de las identidades.
    pub fn without_key(&self, id: KeyId) -> Self {
        let base = self.without_key_only(id);
        Self {
            identities: base
                .identities
                .iter()
                .map(|i| {
                    if i.key == Some(id) {
                        Identity {
                            key: None,
                            ..i.clone()
                        }
                    } else {
                        i.clone()
                    }
                })
                .collect(),
            ..base
        }
    }

    /// Sobrescribe en memoria contraseñas y claves antes de soltarlas (al bloquear la bóveda).
    ///
    /// Solo alcanza a esta copia: las que la interfaz haya clonado se liberan sin borrar.
    pub fn wipe_secrets(&mut self) {
        use zeroize::Zeroize;
        for identity in &mut self.identities {
            identity.password.zeroize();
        }
        for key in &mut self.keys {
            key.private_key.zeroize();
            key.passphrase.zeroize();
        }
        for host in &mut self.hosts {
            if let Some(ProxyConfig::Socks5 { password, .. } | ProxyConfig::Http { password, .. }) =
                host.proxy.as_mut()
            {
                password.zeroize();
            }
        }
        self.identities.clear();
        self.keys.clear();
        self.hosts.clear();
    }

    pub fn with_settings(&self, settings: Settings) -> Self {
        Self {
            settings,
            ..self.clone()
        }
    }

    /// Cadena de grupos desde el del host hasta la raíz (protegida contra ciclos).
    fn group_chain(&self, start: Option<GroupId>) -> Vec<&Group> {
        let mut seen = HashSet::new();
        std::iter::successors(start.and_then(|id| self.group(id)), |g| {
            g.parent.and_then(|p| self.group(p))
        })
        .take_while(|g| seen.insert(g.id))
        .collect()
    }

    pub fn resolve(&self, id: HostId) -> Result<ResolvedHost, ResolveError> {
        let host = self.host(id).ok_or(ResolveError::HostNotFound)?;
        let chain = self.group_chain(host.group);
        let identity_id = host
            .identity
            .or_else(|| chain.iter().find_map(|g| g.identity));
        let identity = identity_id.and_then(|i| self.identity(i)).cloned();
        let key = identity
            .as_ref()
            .and_then(|i| i.key)
            .and_then(|k| self.key(k))
            .cloned();
        let port = host
            .port
            .or_else(|| chain.iter().find_map(|g| g.port))
            .unwrap_or_else(|| host.effective_port());
        Ok(ResolvedHost {
            host: host.clone(),
            port,
            identity,
            key,
        })
    }

    /// Resuelve los jump hosts en orden de salto, detectando ciclos.
    pub fn resolve_jump_chain(&self, id: HostId) -> Result<Vec<ResolvedHost>, ResolveError> {
        fn walk(
            vault: &VaultData,
            id: HostId,
            path: &mut Vec<HostId>,
            out: &mut Vec<ResolvedHost>,
        ) -> Result<(), ResolveError> {
            if path.contains(&id) {
                return Err(ResolveError::JumpCycle);
            }
            path.push(id);
            let host = vault.host(id).ok_or(ResolveError::HostNotFound)?;
            for jump in &host.jump_hosts {
                walk(vault, *jump, path, out)?;
                out.push(vault.resolve(*jump)?);
            }
            path.pop();
            Ok(())
        }
        let mut out = Vec::new();
        walk(self, id, &mut Vec::new(), &mut out)?;
        Ok(out)
    }

    pub fn check_host_key(
        &self,
        host: &str,
        port: u16,
        algorithm: &str,
        fingerprint: &str,
    ) -> HostKeyStatus {
        let for_host: Vec<&KnownHost> = self
            .known_hosts
            .iter()
            .filter(|k| k.host.eq_ignore_ascii_case(host) && k.port == port)
            .collect();
        if for_host
            .iter()
            .any(|k| k.algorithm == algorithm && k.fingerprint == fingerprint)
        {
            return HostKeyStatus::Trusted;
        }
        // Cualquier otra clave ya registrada para este host:puerto, aunque sea de otro
        // algoritmo, es un cambio: un atacante podría ofrecer un tipo de clave distinto.
        match for_host.first() {
            None => HostKeyStatus::Unknown,
            Some(k) => HostKeyStatus::Mismatch {
                expected: format!("{} {}", k.algorithm, k.fingerprint),
            },
        }
    }

    /// Confía en una clave, sustituyendo cualquier entrada previa del mismo host:puerto.
    pub fn trust_host_key(&self, entry: KnownHost) -> Self {
        let same = |k: &KnownHost| k.host.eq_ignore_ascii_case(&entry.host) && k.port == entry.port;
        let mut known_hosts: Vec<KnownHost> = self
            .known_hosts
            .iter()
            .filter(|k| !same(k))
            .cloned()
            .collect();
        known_hosts.push(entry);
        Self {
            known_hosts,
            ..self.clone()
        }
    }

    pub fn forget_host_key(&self, host: &str, port: u16) -> Self {
        Self {
            known_hosts: self
                .known_hosts
                .iter()
                .filter(|k| !(k.host == host && k.port == port))
                .cloned()
                .collect(),
            ..self.clone()
        }
    }

    /// Hosts que coinciden con la búsqueda, ordenados por nombre visible.
    pub fn search_hosts(&self, query: &str) -> Vec<&Host> {
        let mut hosts: Vec<&Host> = self.hosts.iter().filter(|h| h.matches(query)).collect();
        hosts.sort_by_key(|h| h.display_name().to_lowercase());
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (VaultData, HostId, GroupId, IdentityId) {
        let identity = Identity::new("deploy", "deploy");
        let group = Group {
            identity: Some(identity.id),
            port: Some(2200),
            ..Group::new("Producción")
        };
        let host = Host {
            group: Some(group.id),
            ..Host::new("web", "web.example.com")
        };
        let ids = (host.id, group.id, identity.id);
        let vault = VaultData::default()
            .with_identity(identity)
            .with_group(group)
            .with_host(host);
        (vault, ids.0, ids.1, ids.2)
    }

    #[test]
    fn with_host_does_not_modify_original() {
        let original = VaultData::default();
        let updated = original.with_host(Host::new("a", "b"));
        assert!(original.hosts.is_empty());
        assert_eq!(updated.hosts.len(), 1);
    }

    #[test]
    fn with_host_replaces_existing_by_id() {
        let host = Host::new("a", "1.1.1.1");
        let vault = VaultData::default().with_host(host.clone());
        let renamed = vault.with_host(Host {
            label: "b".into(),
            ..host
        });
        assert_eq!(renamed.hosts.len(), 1);
        assert_eq!(renamed.hosts[0].label, "b");
    }

    #[test]
    fn resolve_inherits_identity_and_port_from_group() {
        let (vault, host, _, identity) = sample();
        let resolved = vault.resolve(host).unwrap();
        assert_eq!(resolved.port, 2200);
        assert_eq!(resolved.identity.unwrap().id, identity);
    }

    #[test]
    fn resolve_inherits_from_grandparent_group() {
        let (vault, host, group, identity) = sample();
        let child = Group {
            parent: Some(group),
            ..Group::new("Web")
        };
        let moved = Host {
            group: Some(child.id),
            ..vault.host(host).unwrap().clone()
        };
        let vault = vault.with_group(child).with_host(moved);
        assert_eq!(vault.resolve(host).unwrap().identity.unwrap().id, identity);
    }

    #[test]
    fn resolve_survives_group_cycles() {
        let a = Group::new("a");
        let b = Group {
            parent: Some(a.id),
            ..Group::new("b")
        };
        let a = Group {
            parent: Some(b.id),
            ..a
        };
        let host = Host {
            group: Some(a.id),
            ..Host::new("h", "h")
        };
        let id = host.id;
        let vault = VaultData::default()
            .with_group(a)
            .with_group(b)
            .with_host(host);
        assert_eq!(vault.resolve(id).unwrap().port, 22);
    }

    #[test]
    fn host_identity_overrides_group_identity() {
        let (vault, host, _, _) = sample();
        let own = Identity::new("root", "root");
        let own_id = own.id;
        let updated = Host {
            identity: Some(own_id),
            ..vault.host(host).unwrap().clone()
        };
        let vault = vault.with_identity(own).with_host(updated);
        assert_eq!(vault.resolve(host).unwrap().identity.unwrap().id, own_id);
    }

    #[test]
    fn resolve_unknown_host_errors() {
        assert_eq!(
            VaultData::default().resolve(HostId::new()).unwrap_err(),
            ResolveError::HostNotFound
        );
    }

    #[test]
    fn removing_group_moves_hosts_to_parent() {
        let (vault, host, group, _) = sample();
        let vault = vault.without_group(group);
        assert_eq!(vault.host(host).unwrap().group, None);
    }

    #[test]
    fn removing_identity_unlinks_it() {
        let (vault, _, group, identity) = sample();
        let vault = vault.without_identity(identity);
        assert_eq!(vault.group(group).unwrap().identity, None);
    }

    #[test]
    fn removing_host_drops_its_forwards_and_jump_references() {
        let (vault, host, _, _) = sample();
        let other = Host {
            jump_hosts: vec![host],
            ..Host::new("interno", "10.0.0.5")
        };
        let other_id = other.id;
        let vault =
            vault
                .with_host(other)
                .with_forward(PortForward::local(host, 8080, "localhost", 80));
        let vault = vault.without_host(host);
        assert!(vault.forwards.is_empty());
        assert!(vault.host(other_id).unwrap().jump_hosts.is_empty());
    }

    #[test]
    fn jump_chain_is_resolved_in_hop_order() {
        let bastion = Host::new("bastion", "bastion.example.com");
        let middle = Host {
            jump_hosts: vec![bastion.id],
            ..Host::new("middle", "10.0.0.1")
        };
        let target = Host {
            jump_hosts: vec![middle.id],
            ..Host::new("target", "10.0.1.1")
        };
        let target_id = target.id;
        let vault = VaultData::default()
            .with_host(bastion)
            .with_host(middle)
            .with_host(target);
        let chain: Vec<String> = vault
            .resolve_jump_chain(target_id)
            .unwrap()
            .into_iter()
            .map(|r| r.host.label)
            .collect();
        assert_eq!(chain, vec!["bastion", "middle"]);
    }

    #[test]
    fn jump_chain_detects_cycles() {
        let a = Host::new("a", "a");
        let b = Host {
            jump_hosts: vec![a.id],
            ..Host::new("b", "b")
        };
        let a = Host {
            jump_hosts: vec![b.id],
            ..a
        };
        let id = a.id;
        let vault = VaultData::default().with_host(a).with_host(b);
        assert_eq!(
            vault.resolve_jump_chain(id).unwrap_err(),
            ResolveError::JumpCycle
        );
    }

    #[test]
    fn host_key_check_reports_unknown_trusted_and_mismatch() {
        let vault = VaultData::default();
        assert_eq!(
            vault.check_host_key("srv", 22, "ssh-ed25519", "SHA256:a"),
            HostKeyStatus::Unknown
        );
        let vault = vault.trust_host_key(KnownHost {
            host: "srv".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:a".into(),
        });
        assert_eq!(
            vault.check_host_key("SRV", 22, "ssh-ed25519", "SHA256:a"),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            vault.check_host_key("srv", 22, "ssh-ed25519", "SHA256:b"),
            HostKeyStatus::Mismatch {
                expected: "ssh-ed25519 SHA256:a".into()
            }
        );
        assert_eq!(
            vault.check_host_key("srv", 2222, "ssh-ed25519", "SHA256:a"),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn trusting_again_replaces_previous_fingerprint() {
        let entry = |fp: &str| KnownHost {
            host: "srv".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: fp.into(),
        };
        let vault = VaultData::default()
            .trust_host_key(entry("SHA256:a"))
            .trust_host_key(entry("SHA256:b"));
        assert_eq!(vault.known_hosts.len(), 1);
        assert_eq!(
            vault.check_host_key("srv", 22, "ssh-ed25519", "SHA256:b"),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn search_filters_and_sorts_by_name() {
        let vault = VaultData::default()
            .with_host(Host::new("zeta", "z"))
            .with_host(Host::new("Alfa", "a"))
            .with_host(Host::new("db", "db.local"));
        let names: Vec<&str> = vault
            .search_hosts("")
            .iter()
            .map(|h| h.display_name())
            .collect();
        assert_eq!(names, vec!["Alfa", "db", "zeta"]);
        assert_eq!(vault.search_hosts("db").len(), 1);
    }

    #[test]
    fn different_key_algorithm_for_known_host_is_a_mismatch() {
        let vault = VaultData::default().trust_host_key(KnownHost {
            host: "srv".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:a".into(),
        });
        assert_eq!(
            vault.check_host_key("srv", 22, "ssh-rsa", "SHA256:z"),
            HostKeyStatus::Mismatch {
                expected: "ssh-ed25519 SHA256:a".into()
            }
        );
    }

    #[test]
    fn wipe_secrets_clears_passwords_and_keys() {
        let identity = Identity {
            password: Some("pw".into()),
            ..Identity::new("a", "ana")
        };
        let key = SshKey {
            passphrase: Some("frase".into()),
            ..SshKey::new("k", "PRIVADA")
        };
        let mut vault = VaultData::default().with_identity(identity).with_key(key);
        vault.wipe_secrets();
        assert!(vault.identities.is_empty() && vault.keys.is_empty());
    }
}
