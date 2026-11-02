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
    #[error(
        "«{0}» es de un Team y usa un host que no es de ese Team; elige uno del Team en su \
         configuración"
    )]
    OtherSpace(String),
}

/// Un elemento del espacio `from` puede usar uno del espacio `to`. Lo personal puede usar
/// lo de cualquier espacio: lo eligió la propia persona. Lo de un Team solo usa lo de ese
/// mismo Team: cualquier miembro puede escribirlo, y si pudiera apuntar a la identidad, el
/// grupo, el jump host o el snippet personal de otro, le haría mandar sus credenciales o
/// su script al servidor que eligiera.
pub fn can_use(from: &Option<String>, to: &Option<String>) -> bool {
    from.is_none() || from == to
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

    /// Snippet que se ejecuta al conectar a `host`, si es de un espacio que puede usar.
    pub fn startup_snippet(&self, host: &Host) -> Option<&Snippet> {
        host.startup_snippet
            .and_then(|s| self.snippet(s))
            .filter(|s| can_use(&host.team, &s.team))
    }

    /// Host por el que va el túnel `rule`. Una regla de un Team solo usa un host de ese
    /// Team: si no, iría con las credenciales personales de quien la abre.
    pub fn forward_host(&self, rule: &PortForward) -> Result<&Host, ResolveError> {
        let host = self.host(rule.host).ok_or(ResolveError::HostNotFound)?;
        if can_use(&rule.team, &host.team) {
            Ok(host)
        } else {
            Err(ResolveError::OtherSpace(rule.label.clone()))
        }
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
                        let mut unlinked = i.clone();
                        unlinked.key = None;
                        unlinked
                    } else {
                        i.clone()
                    }
                })
                .collect(),
            ..base
        }
    }

    /// Suelta contraseñas y claves al bloquear la bóveda. Cada una se borra de la memoria al
    /// soltarse, también las copias que haya hecho la interfaz.
    pub fn wipe_secrets(&mut self) {
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

    /// Primer tema definido subiendo desde `group`, con el grupo que lo define.
    pub fn inherited_terminal_theme(&self, group: Option<GroupId>) -> Option<(&Group, &str)> {
        self.group_chain(group)
            .into_iter()
            .find_map(|g| g.terminal_theme.as_deref().map(|theme| (g, theme)))
    }

    /// Id del tema de la terminal de un host: el suyo, el heredado de su grupo o el general.
    pub fn terminal_theme_id(&self, id: HostId) -> &str {
        let host = self.host(id);
        host.and_then(|h| h.terminal_theme.as_deref())
            .or_else(|| {
                let group = host.and_then(|h| h.group);
                self.inherited_terminal_theme(group).map(|(_, theme)| theme)
            })
            .unwrap_or(&self.settings.theme)
    }

    /// Valores con los que conectar al host `id`. Lo que un host de un Team hereda o usa de
    /// otro espacio no cuenta (ver [`can_use`]).
    pub fn resolve(&self, id: HostId) -> Result<ResolvedHost, ResolveError> {
        let host = self.host(id).ok_or(ResolveError::HostNotFound)?;
        let chain: Vec<&Group> = self
            .group_chain(host.group)
            .into_iter()
            .take_while(|g| can_use(&host.team, &g.team))
            .collect();
        let identity_id = host
            .identity
            .or_else(|| chain.iter().find_map(|g| g.identity));
        let identity = identity_id
            .and_then(|i| self.identity(i))
            .filter(|i| can_use(&host.team, &i.team))
            .cloned();
        let key = identity
            .as_ref()
            .and_then(|i| {
                i.key
                    .and_then(|k| self.key(k))
                    .filter(|k| can_use(&i.team, &k.team))
            })
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
                // Saltarse el jump host conectaría por otro camino sin avisar.
                let usable = vault
                    .host(*jump)
                    .is_none_or(|j| can_use(&host.team, &j.team));
                if !usable {
                    return Err(ResolveError::OtherSpace(host.display_name().to_string()));
                }
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

    fn with_group_theme(vault: VaultData, group: GroupId, theme: Option<&str>) -> VaultData {
        let updated = Group {
            terminal_theme: theme.map(String::from),
            ..vault.group(group).unwrap().clone()
        };
        vault.with_group(updated)
    }

    fn with_host_theme(vault: VaultData, host: HostId, theme: Option<&str>) -> VaultData {
        let updated = Host {
            terminal_theme: theme.map(String::from),
            ..vault.host(host).unwrap().clone()
        };
        vault.with_host(updated)
    }

    #[test]
    fn terminal_theme_defaults_to_general_setting() {
        let (vault, host, _, _) = sample();
        assert_eq!(vault.terminal_theme_id(host), vault.settings.theme);
        assert_eq!(
            vault.inherited_terminal_theme(vault.host(host).unwrap().group),
            None
        );
    }

    #[test]
    fn terminal_theme_is_inherited_from_group_chain() {
        let (vault, host, group, _) = sample();
        let child = Group {
            parent: Some(group),
            ..Group::new("Web")
        };
        let moved = Host {
            group: Some(child.id),
            ..vault.host(host).unwrap().clone()
        };
        let child_id = child.id;
        let vault = with_group_theme(
            vault.with_group(child).with_host(moved),
            group,
            Some("nord"),
        );
        assert_eq!(vault.terminal_theme_id(host), "nord");
        let (source, theme) = vault.inherited_terminal_theme(Some(child_id)).unwrap();
        assert_eq!((source.name.as_str(), theme), ("Producción", "nord"));
    }

    #[test]
    fn host_theme_overrides_group_theme() {
        let (vault, host, group, _) = sample();
        let vault = with_group_theme(vault, group, Some("nord"));
        let vault = with_host_theme(vault, host, Some("dracula"));
        assert_eq!(vault.terminal_theme_id(host), "dracula");
    }

    #[test]
    fn terminal_theme_of_unknown_host_is_general_setting() {
        let vault = VaultData::default();
        assert_eq!(vault.terminal_theme_id(HostId::new()), vault.settings.theme);
    }

    #[test]
    fn group_without_theme_field_still_deserializes() {
        let json = r#"{"id":"00000000-0000-0000-0000-000000000001","name":"G","parent":null,"identity":null,"port":null}"#;
        let group: Group = serde_json::from_str(json).unwrap();
        assert_eq!(group.terminal_theme, None);
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

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    /// La bóveda de quien recibe un host de un Team que apunta a sus cosas personales.
    fn team_host_pointing_at_personal_items() -> (VaultData, HostId, ForwardId) {
        let identity = Identity::new("mía", "ana").with_password("personal");
        let group = Group {
            identity: Some(identity.id),
            ..Group::new("personal")
        };
        let snippet = Snippet::new("mío", "cat ~/.secreto");
        let bastion = Host::new("bastión", "10.0.0.1");
        let host = Host {
            team: Some(TEAM.into()),
            group: Some(group.id),
            startup_snippet: Some(snippet.id),
            ..Host::new("trampa", "atacante.invalid")
        };
        let rule = PortForward {
            team: Some(TEAM.into()),
            ..PortForward::local(bastion.id, 1080, "localhost", 80)
        };
        let (host_id, rule_id) = (host.id, rule.id);
        let data = VaultData::default()
            .with_identity(identity)
            .with_group(group)
            .with_snippet(snippet)
            .with_host(bastion)
            .with_host(host)
            .with_forward(rule);
        (data, host_id, rule_id)
    }

    #[test]
    fn a_team_host_does_not_use_personal_credentials_groups_or_snippets() {
        let (data, id, _) = team_host_pointing_at_personal_items();
        let resolved = data.resolve(id).unwrap();
        assert_eq!(resolved.identity, None, "ni heredada del grupo personal");
        let personal_identity = data.identities[0].id;
        let direct = data.with_host(Host {
            identity: Some(personal_identity),
            ..data.host(id).unwrap().clone()
        });
        assert_eq!(direct.resolve(id).unwrap().identity, None, "ni directa");
        assert!(data.startup_snippet(data.host(id).unwrap()).is_none());

        // En el mismo Team sí.
        let shared = data
            .with_identity(data.identities[0].with_team(TEAM))
            .with_snippet(Snippet {
                team: Some(TEAM.into()),
                ..data.snippets[0].clone()
            })
            .with_group(Group {
                team: Some(TEAM.into()),
                ..data.groups[0].clone()
            });
        assert!(shared.resolve(id).unwrap().identity.is_some());
        assert!(shared.startup_snippet(shared.host(id).unwrap()).is_some());
    }

    #[test]
    fn a_team_host_cannot_jump_through_a_personal_host() {
        let (data, id, _) = team_host_pointing_at_personal_items();
        let bastion = data.hosts[0].id;
        let data = data.with_host(Host {
            jump_hosts: vec![bastion],
            ..data.host(id).unwrap().clone()
        });
        assert!(matches!(
            data.resolve_jump_chain(id),
            Err(ResolveError::OtherSpace(_))
        ));
        // Un host personal sí puede saltar por uno de un Team.
        let personal = Host {
            jump_hosts: vec![id],
            ..Host::new("mío", "10.0.0.9")
        };
        let personal_id = personal.id;
        let data = data.with_host(Host {
            jump_hosts: Vec::new(),
            ..data.host(id).unwrap().clone()
        });
        let data = data.with_host(personal);
        assert_eq!(data.resolve_jump_chain(personal_id).unwrap().len(), 1);
    }

    #[test]
    fn a_team_forward_cannot_run_through_a_personal_host() {
        let (data, _, rule) = team_host_pointing_at_personal_items();
        let rule = data.forwards.iter().find(|f| f.id == rule).unwrap();
        assert!(matches!(
            data.forward_host(rule),
            Err(ResolveError::OtherSpace(_))
        ));
        let personal = PortForward {
            team: None,
            ..rule.clone()
        };
        assert!(data.forward_host(&personal).is_ok());
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
        let identity = Identity::new("a", "ana").with_password("pw");
        let key = SshKey::new("k", "PRIVADA").with_passphrase("frase");
        let mut vault = VaultData::default().with_identity(identity).with_key(key);
        vault.wipe_secrets();
        assert!(vault.identities.is_empty() && vault.keys.is_empty());
    }
}
