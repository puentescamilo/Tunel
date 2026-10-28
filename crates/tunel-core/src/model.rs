//! Modelos de dominio guardados en la bóveda.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

id_type!(HostId);
id_type!(GroupId);
id_type!(IdentityId);
id_type!(KeyId);
id_type!(SnippetId);
id_type!(ForwardId);

pub const DEFAULT_SSH_PORT: u16 = 22;
pub const DEFAULT_TELNET_PORT: u16 = 23;
pub const DEFAULT_MOSH_PORTS: &str = "60000:61000";

/// Protocolo de conexión de un host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Protocol {
    Ssh,
    Mosh { server_command: Option<String> },
    Telnet,
    Serial { device: String, baud_rate: u32 },
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Mosh { .. } => "Mosh",
            Protocol::Telnet => "Telnet",
            Protocol::Serial { .. } => "Serial",
        }
    }
}

/// Proxy de red para la conexión TCP inicial.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProxyConfig {
    Socks5 {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Host {
    pub id: HostId,
    pub label: String,
    pub address: String,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub group: Option<GroupId>,
    pub identity: Option<IdentityId>,
    pub tags: Vec<String>,
    /// Hosts intermedios en orden (ProxyJump).
    pub jump_hosts: Vec<HostId>,
    pub proxy: Option<ProxyConfig>,
    pub agent_forwarding: bool,
    pub startup_snippet: Option<SnippetId>,
    pub env: BTreeMap<String, String>,
    pub notes: String,
    /// Tema de terminal propio de este host (p. ej. rojo para producción).
    pub terminal_theme: Option<String>,
}

impl Host {
    pub fn new(label: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            id: HostId::new(),
            label: label.into(),
            address: address.into(),
            ..Self::default()
        }
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol.clone().unwrap_or(Protocol::Ssh)
    }

    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.protocol() {
            Protocol::Telnet => DEFAULT_TELNET_PORT,
            Protocol::Ssh | Protocol::Mosh { .. } | Protocol::Serial { .. } => DEFAULT_SSH_PORT,
        })
    }

    pub fn display_name(&self) -> &str {
        if self.label.trim().is_empty() {
            &self.address
        } else {
            &self.label
        }
    }

    /// Coincidencia sin distinguir mayúsculas en etiqueta, dirección y tags.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        q.is_empty()
            || self.label.to_lowercase().contains(&q)
            || self.address.to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
    }
}

/// Grupo de hosts; los valores de conexión se heredan hacia los hosts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    pub parent: Option<GroupId>,
    pub identity: Option<IdentityId>,
    pub port: Option<u16>,
    /// Tema de la terminal para los hosts del grupo que no tengan uno propio.
    #[serde(default)]
    pub terminal_theme: Option<String>,
}

impl Group {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: GroupId::new(),
            name: name.into(),
            ..Self::default()
        }
    }
}

/// Usuario + credencial reutilizable.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identity {
    pub id: IdentityId,
    pub label: String,
    pub username: String,
    pub password: Option<String>,
    pub key: Option<KeyId>,
    /// Usar el agente SSH del sistema (SSH_AUTH_SOCK / Pageant).
    pub use_agent: bool,
}

impl Identity {
    pub fn new(label: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id: IdentityId::new(),
            label: label.into(),
            username: username.into(),
            ..Self::default()
        }
    }
}

/// Clave privada en formato OpenSSH/PEM, guardada dentro de la bóveda.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SshKey {
    pub id: KeyId,
    pub label: String,
    pub private_key: String,
    pub public_key: Option<String>,
    pub passphrase: Option<String>,
    /// Certificado OpenSSH opcional (`*-cert.pub`).
    pub certificate: Option<String>,
}

impl SshKey {
    pub fn new(label: impl Into<String>, private_key: impl Into<String>) -> Self {
        Self {
            id: KeyId::new(),
            label: label.into(),
            private_key: private_key.into(),
            ..Self::default()
        }
    }
}

const REDACTED: &str = "«oculto»";

fn redact<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, host, port, username, password) = match self {
            ProxyConfig::Socks5 {
                host,
                port,
                username,
                password,
            } => ("Socks5", host, port, username, password),
            ProxyConfig::Http {
                host,
                port,
                username,
                password,
            } => ("Http", host, port, username, password),
        };
        f.debug_struct(kind)
            .field("host", host)
            .field("port", port)
            .field("username", username)
            .field("password", &redact(password))
            .finish()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("username", &self.username)
            .field("password", &redact(&self.password))
            .field("key", &self.key)
            .field("use_agent", &self.use_agent)
            .finish()
    }
}

impl std::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKey")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("private_key", &REDACTED)
            .field("public_key", &self.public_key)
            .field("passphrase", &redact(&self.passphrase))
            .field(
                "certificate",
                &self.certificate.as_ref().map(|_| "presente"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Snippet {
    pub id: SnippetId,
    pub label: String,
    pub script: String,
    pub tags: Vec<String>,
}

impl Snippet {
    pub fn new(label: impl Into<String>, script: impl Into<String>) -> Self {
        Self {
            id: SnippetId::new(),
            label: label.into(),
            script: script.into(),
            tags: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardKind {
    /// `-L`: puerto local → destino visto desde el servidor.
    Local,
    /// `-R`: puerto del servidor → destino visto desde aquí.
    Remote,
    /// `-D`: proxy SOCKS5 local.
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub id: ForwardId,
    pub label: String,
    pub host: HostId,
    pub kind: ForwardKind,
    pub bind_address: String,
    pub bind_port: u16,
    /// Ignorados en reenvío dinámico.
    pub destination_host: String,
    pub destination_port: u16,
}

impl PortForward {
    pub fn local(
        host: HostId,
        bind_port: u16,
        destination_host: impl Into<String>,
        destination_port: u16,
    ) -> Self {
        Self {
            id: ForwardId::new(),
            label: String::new(),
            host,
            kind: ForwardKind::Local,
            bind_address: "127.0.0.1".into(),
            bind_port,
            destination_host: destination_host.into(),
            destination_port,
        }
    }

    pub fn describe(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!(
                "L {}:{} → {}:{}",
                self.bind_address, self.bind_port, self.destination_host, self.destination_port
            ),
            ForwardKind::Remote => format!(
                "R {}:{} → {}:{}",
                self.bind_address, self.bind_port, self.destination_host, self.destination_port
            ),
            ForwardKind::Dynamic => format!("D SOCKS5 {}:{}", self.bind_address, self.bind_port),
        }
    }
}

/// Clave de host confiada (equivalente a una línea de known_hosts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHost {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// Huella SHA-256 en formato OpenSSH (`SHA256:...`).
    pub fingerprint: String,
}

/// `serde(default)`: los campos añadidos en versiones nuevas toman su valor por defecto
/// al abrir bóvedas antiguas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub font_size: f32,
    /// Id del tema de la terminal (incluido o importado).
    pub theme: String,
    pub scrollback_lines: usize,
    pub copy_on_select: bool,
    pub keepalive_seconds: u32,
    pub ui_theme: crate::theme::UiThemeMode,
    pub cursor_style: crate::theme::CursorStyle,
    /// Temas importados por el usuario.
    pub custom_themes: Vec<crate::theme::TerminalTheme>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            font_size: 14.0,
            theme: "tunel-oscuro".into(),
            scrollback_lines: 10_000,
            copy_on_select: false,
            keepalive_seconds: 30,
            ui_theme: crate::theme::UiThemeMode::Auto,
            cursor_style: crate::theme::CursorStyle::Block,
            custom_themes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_from_older_vaults_get_new_defaults() {
        let old = r#"{"font_size":16.0,"theme":"tunel-claro","scrollback_lines":500,"copy_on_select":true,"keepalive_seconds":10}"#;
        let settings: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(settings.theme, "tunel-claro");
        assert_eq!(settings.ui_theme, crate::theme::UiThemeMode::Auto);
        assert!(settings.custom_themes.is_empty());
    }

    #[test]
    fn hosts_from_older_vaults_have_no_theme_override() {
        let host = Host::new("a", "b");
        let mut json: serde_json::Value = serde_json::to_value(&host).unwrap();
        json.as_object_mut().unwrap().remove("terminal_theme");
        let parsed: Host = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.terminal_theme, None);
    }

    #[test]
    fn host_defaults_to_ssh_on_port_22() {
        let host = Host::new("web", "10.0.0.1");
        assert_eq!(host.protocol(), Protocol::Ssh);
        assert_eq!(host.effective_port(), 22);
    }

    #[test]
    fn telnet_host_defaults_to_port_23() {
        let host = Host {
            protocol: Some(Protocol::Telnet),
            ..Host::new("sw", "10.0.0.2")
        };
        assert_eq!(host.effective_port(), 23);
    }

    #[test]
    fn explicit_port_overrides_default() {
        let host = Host {
            port: Some(2222),
            ..Host::new("a", "b")
        };
        assert_eq!(host.effective_port(), 2222);
    }

    #[test]
    fn display_name_falls_back_to_address_when_label_blank() {
        assert_eq!(Host::new("  ", "db.local").display_name(), "db.local");
    }

    #[test]
    fn host_matches_label_address_and_tags_case_insensitively() {
        let host = Host {
            tags: vec!["Producción".into()],
            ..Host::new("Web-01", "web.example.com")
        };
        assert!(host.matches("web-01"));
        assert!(host.matches("EXAMPLE"));
        assert!(host.matches("producción"));
        assert!(host.matches(""));
        assert!(!host.matches("staging"));
    }

    #[test]
    fn forward_descriptions_are_readable() {
        let host = HostId::new();
        let fwd = PortForward::local(host, 8080, "localhost", 80);
        assert_eq!(fwd.describe(), "L 127.0.0.1:8080 → localhost:80");
        let dynamic = PortForward {
            kind: ForwardKind::Dynamic,
            bind_port: 1080,
            ..fwd
        };
        assert_eq!(dynamic.describe(), "D SOCKS5 127.0.0.1:1080");
    }

    #[test]
    fn protocol_round_trips_through_json() {
        let p = Protocol::Serial {
            device: "/dev/ttyUSB0".into(),
            baud_rate: 115_200,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Protocol>(&json).unwrap(), p);
    }

    #[test]
    fn debug_output_hides_secrets() {
        let identity = Identity {
            password: Some("pw-secreta".into()),
            ..Identity::new("a", "ana")
        };
        let key = SshKey {
            passphrase: Some("frase".into()),
            ..SshKey::new("k", "-----BEGIN CLAVE-----")
        };
        let proxy = ProxyConfig::Socks5 {
            host: "p".into(),
            port: 1,
            username: Some("u".into()),
            password: Some("proxy-pw".into()),
        };
        let text = format!("{identity:?} {key:?} {proxy:?}");
        for secret in ["pw-secreta", "frase", "BEGIN CLAVE", "proxy-pw"] {
            assert!(!text.contains(secret), "se filtró {secret}: {text}");
        }
        assert!(text.contains("ana"));
    }
}
