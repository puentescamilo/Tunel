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
    pub forward_x11: bool,
}

impl SshConfigHost {
    pub fn address(&self) -> &str {
        self.hostname.as_deref().unwrap_or(&self.alias)
    }
}

fn is_pattern(alias: &str) -> bool {
    alias.contains(['*', '?', '!'])
}

/// Comodín de OpenSSH (`*` y `?`), sin distinguir mayúsculas.
///
/// Vuelve atrás solo hasta el último `*`, así que el coste es lineal en la práctica
/// aunque el patrón tenga muchos comodines.
fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c.eq_ignore_ascii_case(&text[t]) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Lista de patrones de una línea `Host`: basta un positivo y ningún `!negado`.
fn host_matches(patterns: &[String], alias: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        match pattern.strip_prefix('!') {
            Some(negated) if glob_matches(negated.as_bytes(), alias.as_bytes()) => return false,
            Some(_) => {}
            None => matched |= glob_matches(pattern.as_bytes(), alias.as_bytes()),
        }
    }
    matched
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

/// Bloque `Host` (o `Match`, sin patrones porque no se evalúa) con sus directivas.
struct Block {
    patterns: Option<Vec<String>>,
    directives: Vec<(String, String)>,
}

fn blocks(text: &str) -> Vec<Block> {
    // Lo que va antes del primer `Host` se aplica a todos, como un `Host *`.
    let mut blocks = vec![Block {
        patterns: Some(vec!["*".into()]),
        directives: Vec::new(),
    }];
    for (key, value) in text.lines().filter_map(split_directive) {
        match key.as_str() {
            "host" => blocks.push(Block {
                patterns: Some(value.split_whitespace().map(str::to_string).collect()),
                directives: Vec::new(),
            }),
            "match" => blocks.push(Block {
                patterns: None,
                directives: Vec::new(),
            }),
            _ => blocks
                .last_mut()
                .into_iter()
                .for_each(|b| b.directives.push((key.clone(), value.clone()))),
        }
    }
    blocks
}

fn yes(value: &str) -> bool {
    value.eq_ignore_ascii_case("yes")
}

/// Valores de un host mientras se recorren sus bloques; los opcionales guardan el primero.
#[derive(Default)]
struct Collected {
    host: SshConfigHost,
    forward_agent: Option<bool>,
    forward_x11: Option<bool>,
    forward_x11_trusted: Option<bool>,
}

impl Collected {
    // Como OpenSSH, el primer valor encontrado gana (salvo IdentityFile, que se acumula).
    fn apply(&mut self, key: &str, value: &str) {
        let host = &mut self.host;
        match key {
            "hostname" if host.hostname.is_none() => host.hostname = Some(value.to_string()),
            "user" if host.user.is_none() => host.user = Some(value.to_string()),
            "port" if host.port.is_none() => host.port = value.parse().ok(),
            "identityfile" => host.identity_files.push(value.to_string()),
            "proxyjump" if host.proxy_jump.is_empty() && !value.eq_ignore_ascii_case("none") => {
                host.proxy_jump = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "forwardagent" => {
                self.forward_agent.get_or_insert(yes(value));
            }
            "forwardx11" => {
                self.forward_x11.get_or_insert(yes(value));
            }
            "forwardx11trusted" => {
                self.forward_x11_trusted.get_or_insert(yes(value));
            }
            _ => {}
        }
    }

    fn finish(self) -> SshConfigHost {
        SshConfigHost {
            forward_agent: self.forward_agent.unwrap_or(false),
            // Túnel solo hace X11 de confianza (con la cookie real), así que solo se activa
            // si OpenSSH también lo haría de confianza; su valor por omisión es `no`.
            forward_x11: self.forward_x11.unwrap_or(false)
                && self.forward_x11_trusted.unwrap_or(false),
            ..self.host
        }
    }
}

/// Analiza el archivo y devuelve los hosts concretos (los alias sin comodines).
///
/// A cada alias se le aplican, en orden, todos los bloques `Host` que coinciden con él,
/// incluidos los de comodines como `Host *`. Los bloques `Match` no se evalúan.
pub fn parse(text: &str) -> Vec<SshConfigHost> {
    let blocks = blocks(text);
    let mut aliases: Vec<&str> = Vec::new();
    for alias in blocks
        .iter()
        .filter_map(|b| b.patterns.as_ref())
        .flatten()
        .filter(|alias| !is_pattern(alias))
    {
        if !aliases.contains(&alias.as_str()) {
            aliases.push(alias);
        }
    }
    aliases
        .into_iter()
        .map(|alias| {
            let mut collected = Collected {
                host: SshConfigHost {
                    alias: alias.to_string(),
                    ..SshConfigHost::default()
                },
                ..Collected::default()
            };
            blocks
                .iter()
                .filter(|b| b.patterns.as_ref().is_some_and(|p| host_matches(p, alias)))
                .flat_map(|b| &b.directives)
                .for_each(|(key, value)| collected.apply(key, value));
            collected.finish()
        })
        .collect()
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
            x11_forwarding: entry.forward_x11,
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
    fn forward_x11_is_parsed_and_imported() {
        let entries = parse(
            "Host grafico\n    ForwardX11 yes\n    ForwardX11Trusted yes\n\nHost texto\n    ForwardX11 no\n",
        );
        assert!(entries[0].forward_x11);
        assert!(!entries[1].forward_x11);
        let (vault, _) = import_into(&crate::vault::VaultData::default(), &entries, |_| None);
        let host = |label: &str| vault.hosts.iter().find(|h| h.label == label).unwrap();
        assert!(host("grafico").x11_forwarding);
        assert!(!host("texto").x11_forwarding);
    }

    #[test]
    fn wildcard_block_before_host_wins_like_openssh() {
        let config = "Host *\n ForwardX11 no\n ForwardAgent no\n User todos\n\n\
                      Host a\n ForwardX11 yes\n ForwardX11Trusted yes\n ForwardAgent yes\n User propio\n";
        let a = &parse(config)[0];
        assert!(!a.forward_x11);
        assert!(!a.forward_agent);
        assert_eq!(a.user.as_deref(), Some("todos"));
    }

    #[test]
    fn wildcard_block_after_host_fills_missing_values() {
        let a = &parse("Host a\n Port 2200\n\nHost *\n User todos\n Port 22\n")[0];
        assert_eq!(a.user.as_deref(), Some("todos"));
        assert_eq!(a.port, Some(2200));
    }

    #[test]
    fn directives_before_first_host_apply_to_all() {
        let a = &parse("ForwardAgent no\nHost a\n ForwardAgent yes\n")[0];
        assert!(!a.forward_agent);
    }

    #[test]
    fn patterns_with_negation_and_question_mark() {
        let config = "Host web? !web9\n User web\n\nHost web1 web9 db\n";
        let hosts = parse(config);
        let user = |alias: &str| {
            hosts
                .iter()
                .find(|h| h.alias == alias)
                .and_then(|h| h.user.clone())
        };
        assert_eq!(user("web1").as_deref(), Some("web"));
        assert_eq!(user("web9"), None);
        assert_eq!(user("db"), None);
    }

    #[test]
    fn glob_handles_stars_and_many_wildcards() {
        assert!(glob_matches(b"*.Example.com", b"web.example.COM"));
        assert!(glob_matches(b"a*b*c", b"axxbyyc"));
        assert!(!glob_matches(b"a*b*c", b"axxbyy"));
        assert!(glob_matches(b"*", b""));
        let many = "*a".repeat(30);
        assert!(!glob_matches(many.as_bytes(), "a".repeat(29).as_bytes()));
    }

    #[test]
    fn untrusted_x11_is_not_imported_as_trusted() {
        let hosts = parse(
            "Host por-omision\n ForwardX11 yes\n\nHost no-confiable\n ForwardX11 yes\n ForwardX11Trusted no\n",
        );
        assert!(hosts.iter().all(|h| !h.forward_x11));
    }

    #[test]
    fn alias_in_several_blocks_is_imported_once() {
        let hosts = parse("Host a\n User uno\n\nHost a b\n Port 2222\n");
        let aliases: Vec<&str> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, vec!["a", "b"]);
        assert_eq!(hosts[0].port, Some(2222));
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
