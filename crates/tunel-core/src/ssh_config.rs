//! Importación de hosts desde un archivo `~/.ssh/config` de OpenSSH.

/// Entrada `Host` con los campos que Túnel sabe aprovechar.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshConfigHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<String>,
    pub proxy_jump: Vec<String>,
    pub forward_agent: bool,
}

impl SshConfigHost {
    pub fn address(&self) -> &str {
        self.hostname.as_deref().unwrap_or(&self.alias)
    }
}

fn is_pattern(alias: &str) -> bool {
    alias.contains(['*', '?', '!'])
}

fn split_directive(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, value) = match line.find(|c: char| c == '=' || c.is_whitespace()) {
        Some(i) => (
            &line[..i],
            line[i + 1..].trim_start_matches(|c: char| c == '=' || c.is_whitespace()),
        ),
        None => (line, ""),
    };
    let value = value.trim().trim_matches('"').to_string();
    Some((key.to_ascii_lowercase(), value))
}

/// Analiza el archivo. Omite patrones con comodines (`Host *`) porque no son hosts concretos.
pub fn parse(text: &str) -> Vec<SshConfigHost> {
    let mut hosts: Vec<SshConfigHost> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for (key, value) in text.lines().filter_map(split_directive) {
        if key == "host" {
            current = value
                .split_whitespace()
                .filter(|alias| !is_pattern(alias))
                .map(|alias| {
                    hosts.push(SshConfigHost {
                        alias: alias.to_string(),
                        ..SshConfigHost::default()
                    });
                    hosts.len() - 1
                })
                .collect();
            continue;
        }
        if key == "match" {
            current.clear();
            continue;
        }
        for &i in &current {
            let host = &mut hosts[i];
            // Como OpenSSH, el primer valor encontrado gana (salvo IdentityFile, que se acumula).
            match key.as_str() {
                "hostname" if host.hostname.is_none() => host.hostname = Some(value.clone()),
                "user" if host.user.is_none() => host.user = Some(value.clone()),
                "port" if host.port.is_none() => host.port = value.parse().ok(),
                "identityfile" => host.identity_files.push(value.clone()),
                "proxyjump"
                    if host.proxy_jump.is_empty() && !value.eq_ignore_ascii_case("none") =>
                {
                    host.proxy_jump = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "forwardagent" => host.forward_agent = value.eq_ignore_ascii_case("yes"),
                _ => {}
            }
        }
    }
    hosts
}

/// Resumen de una importación.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportReport {
    pub hosts: usize,
    pub keys: usize,
    pub skipped_existing: usize,
    pub unreadable_keys: Vec<String>,
}

/// Añade los hosts a la bóveda. `read_key` devuelve el contenido de un archivo de clave.
/// Los hosts cuyo alias ya existe como etiqueta se omiten.
pub fn import_into(
    vault: &crate::vault::VaultData,
    entries: &[SshConfigHost],
    read_key: impl Fn(&str) -> Option<String>,
) -> (crate::vault::VaultData, ImportReport) {
    use crate::model::{Host, HostId, Identity, SshKey};
    use std::collections::HashMap;

    let mut report = ImportReport::default();
    let mut data = vault.clone();
    let mut by_alias: HashMap<String, HostId> =
        data.hosts.iter().map(|h| (h.label.clone(), h.id)).collect();
    let mut key_cache: HashMap<String, Option<crate::model::KeyId>> = HashMap::new();
    let mut created: Vec<(HostId, &SshConfigHost)> = Vec::new();

    for entry in entries {
        if by_alias.contains_key(&entry.alias) {
            report.skipped_existing += 1;
            continue;
        }
        let key_id = entry.identity_files.iter().find_map(|path| {
            *key_cache
                .entry(path.clone())
                .or_insert_with(|| match read_key(path) {
                    Some(contents) => {
                        let key = SshKey::new(path.rsplit('/').next().unwrap_or(path), contents);
                        let id = key.id;
                        data = data.with_key(key);
                        report.keys += 1;
                        Some(id)
                    }
                    None => {
                        report.unreadable_keys.push(path.clone());
                        None
                    }
                })
        });
        let identity = entry.user.as_ref().map(|user| Identity {
            key: key_id,
            use_agent: key_id.is_none(),
            ..Identity::new(format!("{user}@{}", entry.alias), user.clone())
        });
        let host = Host {
            port: entry.port,
            identity: identity.as_ref().map(|i| i.id),
            agent_forwarding: entry.forward_agent,
            tags: vec!["ssh-config".into()],
            ..Host::new(entry.alias.clone(), entry.address())
        };
        if let Some(identity) = identity {
            data = data.with_identity(identity);
        }
        by_alias.insert(entry.alias.clone(), host.id);
        created.push((host.id, entry));
        data = data.with_host(host);
        report.hosts += 1;
    }

    // Segunda pasada: los ProxyJump pueden apuntar a hosts definidos más abajo.
    for (id, entry) in created {
        let jumps: Vec<HostId> = entry
            .proxy_jump
            .iter()
            .filter_map(|alias| by_alias.get(alias).copied())
            .collect();
        if let (false, Some(host)) = (jumps.is_empty(), data.host(id).cloned()) {
            data = data.with_host(crate::model::Host {
                jump_hosts: jumps,
                ..host
            });
        }
    }
    (data, report)
}

/// Expande `~/` usando el directorio personal indicado.
pub fn expand_home(path: &str, home: &std::path::Path) -> std::path::PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => std::path::PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# Comentario
Host bastion
    HostName bastion.example.com
    User ops
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host web-1 web-2
    HostName=10.0.0.10
    User deploy
    ProxyJump bastion
    ForwardAgent yes
    IdentityFile ~/.ssh/a
    IdentityFile ~/.ssh/b

Host *
    User nadie
    ServerAliveInterval 30

Match host x
    User ignorado
"#;

    #[test]
    fn parses_concrete_hosts_and_skips_wildcards() {
        let hosts = parse(SAMPLE);
        let aliases: Vec<&str> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, vec!["bastion", "web-1", "web-2"]);
    }

    #[test]
    fn reads_connection_fields() {
        let hosts = parse(SAMPLE);
        let bastion = &hosts[0];
        assert_eq!(bastion.address(), "bastion.example.com");
        assert_eq!(bastion.user.as_deref(), Some("ops"));
        assert_eq!(bastion.port, Some(2222));
        assert_eq!(bastion.identity_files, vec!["~/.ssh/id_ed25519"]);
    }

    #[test]
    fn multi_alias_block_applies_to_each_alias() {
        let hosts = parse(SAMPLE);
        for web in &hosts[1..] {
            assert_eq!(web.hostname.as_deref(), Some("10.0.0.10"));
            assert_eq!(web.proxy_jump, vec!["bastion"]);
            assert!(web.forward_agent);
            assert_eq!(web.identity_files.len(), 2);
        }
    }

    #[test]
    fn wildcard_and_match_blocks_do_not_leak_into_hosts() {
        let hosts = parse(SAMPLE);
        assert!(
            hosts.iter().all(
                |h| h.user.as_deref() != Some("nadie") && h.user.as_deref() != Some("ignorado")
            )
        );
    }

    #[test]
    fn first_value_wins_like_openssh() {
        let hosts = parse("Host a\n User uno\n User dos\n");
        assert_eq!(hosts[0].user.as_deref(), Some("uno"));
    }

    #[test]
    fn address_falls_back_to_alias() {
        assert_eq!(parse("Host solo-alias\n")[0].address(), "solo-alias");
    }

    #[test]
    fn import_creates_hosts_identities_keys_and_jumps() {
        let entries = parse(SAMPLE);
        let read = |path: &str| (path == "~/.ssh/id_ed25519").then(|| "CLAVE".to_string());
        let (vault, report) = import_into(&crate::vault::VaultData::default(), &entries, read);
        assert_eq!(report.hosts, 3);
        assert_eq!(report.keys, 1);
        assert_eq!(report.unreadable_keys, vec!["~/.ssh/a", "~/.ssh/b"]);

        let bastion = vault.hosts.iter().find(|h| h.label == "bastion").unwrap();
        let resolved = vault.resolve(bastion.id).unwrap();
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.identity.as_ref().unwrap().username, "ops");
        assert_eq!(resolved.key.unwrap().private_key, "CLAVE");

        let web = vault.hosts.iter().find(|h| h.label == "web-1").unwrap();
        assert_eq!(web.jump_hosts, vec![bastion.id]);
        assert!(web.agent_forwarding);
        assert!(vault.resolve(web.id).unwrap().identity.unwrap().use_agent);
    }

    #[test]
    fn import_skips_existing_labels_and_does_not_modify_input() {
        let original =
            crate::vault::VaultData::default().with_host(crate::model::Host::new("bastion", "x"));
        let (vault, report) = import_into(&original, &parse(SAMPLE), |_| None);
        assert_eq!(report.skipped_existing, 1);
        assert_eq!(original.hosts.len(), 1);
        assert_eq!(vault.hosts.len(), 3);
    }

    #[test]
    fn expand_home_only_touches_tilde_prefix() {
        let home = std::path::Path::new("/home/ana");
        assert_eq!(
            expand_home("~/.ssh/id", home),
            std::path::PathBuf::from("/home/ana/.ssh/id")
        );
        assert_eq!(
            expand_home("/etc/key", home),
            std::path::PathBuf::from("/etc/key")
        );
    }
}
