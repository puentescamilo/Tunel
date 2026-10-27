//! Formulario de host y validación de sus campos.

use super::combo;
use std::collections::BTreeMap;
use tunel_core::*;

/// Parsea un puerto; vacío significa "por defecto".
pub fn parse_port(text: &str) -> Result<Option<u16>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("«{text}» no es un puerto válido (1-65535)")),
        Ok(port) => Ok(Some(port)),
    }
}

pub fn parse_tags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = text
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    tags.dedup();
    tags
}

/// Una variable por línea en formato `NOMBRE=valor`.
pub fn parse_env(text: &str) -> Result<BTreeMap<String, String>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("Falta «=» en «{line}»"))?;
            let name = name.trim();
            let valid = !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit());
            if !valid {
                return Err(format!("«{name}» no es un nombre de variable válido"));
            }
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

pub fn format_env(env: &BTreeMap<String, String>) -> String {
    env.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

const FIELD_WIDTH: f32 = 320.0;

fn default_port_hint(protocol: ProtocolChoice) -> &'static str {
    match protocol {
        ProtocolChoice::Telnet => "23",
        ProtocolChoice::Ssh | ProtocolChoice::Mosh | ProtocolChoice::Serial => "22",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProtocolChoice {
    Ssh,
    Mosh,
    Telnet,
    Serial,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProxyChoice {
    None,
    Socks5,
    Http,
}

pub struct HostForm {
    pub(super) host: Host,
    port: String,
    protocol: ProtocolChoice,
    serial_device: String,
    serial_baud: String,
    mosh_command: String,
    proxy: ProxyChoice,
    proxy_host: String,
    proxy_port: String,
    proxy_user: String,
    proxy_password: String,
    tags: String,
    env: String,
    new_username: String,
    new_password: String,
    pub(super) error: Option<String>,
}

impl HostForm {
    pub fn new(host: Host) -> Self {
        let (protocol, serial_device, serial_baud, mosh_command) = match host.protocol() {
            Protocol::Ssh => (
                ProtocolChoice::Ssh,
                String::new(),
                "115200".into(),
                String::new(),
            ),
            Protocol::Mosh { server_command } => (
                ProtocolChoice::Mosh,
                String::new(),
                "115200".into(),
                server_command.unwrap_or_default(),
            ),
            Protocol::Telnet => (
                ProtocolChoice::Telnet,
                String::new(),
                "115200".into(),
                String::new(),
            ),
            Protocol::Serial { device, baud_rate } => (
                ProtocolChoice::Serial,
                device,
                baud_rate.to_string(),
                String::new(),
            ),
        };
        let proxy = match &host.proxy {
            None => ProxyChoice::None,
            Some(ProxyConfig::Socks5 { .. }) => ProxyChoice::Socks5,
            Some(ProxyConfig::Http { .. }) => ProxyChoice::Http,
        };
        let (proxy_host, proxy_port, proxy_user, proxy_password) = match &host.proxy {
            None => Default::default(),
            Some(
                ProxyConfig::Socks5 {
                    host,
                    port,
                    username,
                    password,
                }
                | ProxyConfig::Http {
                    host,
                    port,
                    username,
                    password,
                },
            ) => (
                host.clone(),
                port.to_string(),
                username.clone().unwrap_or_default(),
                password.clone().unwrap_or_default(),
            ),
        };
        Self {
            port: host.port.map(|p| p.to_string()).unwrap_or_default(),
            tags: host.tags.join(", "),
            env: format_env(&host.env),
            host,
            protocol,
            serial_device,
            serial_baud,
            mosh_command,
            proxy,
            proxy_host,
            proxy_port,
            proxy_user,
            proxy_password,
            new_username: String::new(),
            new_password: String::new(),
            error: None,
        }
    }

    pub(super) fn build(&self, data: &VaultData) -> Result<VaultData, String> {
        let protocol = match self.protocol {
            ProtocolChoice::Ssh => Protocol::Ssh,
            ProtocolChoice::Telnet => Protocol::Telnet,
            ProtocolChoice::Mosh => Protocol::Mosh {
                server_command: Some(self.mosh_command.trim().to_string())
                    .filter(|c| !c.is_empty()),
            },
            ProtocolChoice::Serial => Protocol::Serial {
                device: self.serial_device.trim().to_string(),
                baud_rate: self
                    .serial_baud
                    .trim()
                    .parse()
                    .map_err(|_| "Velocidad (baudios) no válida".to_string())?,
            },
        };
        let is_serial = matches!(protocol, Protocol::Serial { .. });
        if !is_serial && self.host.address.trim().is_empty() {
            return Err("La dirección es obligatoria".into());
        }
        if let Protocol::Serial { device, .. } = &protocol
            && device.is_empty()
        {
            return Err("Elige un puerto serie".into());
        }
        let proxy = match self.proxy {
            ProxyChoice::None => None,
            choice => {
                let port = parse_port(&self.proxy_port)?.ok_or("El proxy necesita un puerto")?;
                let host = self.proxy_host.trim().to_string();
                if host.is_empty() {
                    return Err("El proxy necesita una dirección".into());
                }
                let username = Some(self.proxy_user.trim().to_string()).filter(|u| !u.is_empty());
                let password = Some(self.proxy_password.clone()).filter(|p| !p.is_empty());
                Some(if choice == ProxyChoice::Http {
                    ProxyConfig::Http {
                        host,
                        port,
                        username,
                        password,
                    }
                } else {
                    ProxyConfig::Socks5 {
                        host,
                        port,
                        username,
                        password,
                    }
                })
            }
        };
        let mut result = data.clone();
        let mut identity = self.host.identity;
        if !self.new_username.trim().is_empty() {
            let new_identity = Identity {
                password: Some(self.new_password.clone()).filter(|p| !p.is_empty()),
                ..Identity::new(
                    format!("{}@{}", self.new_username.trim(), self.host.display_name()),
                    self.new_username.trim(),
                )
            };
            identity = Some(new_identity.id);
            result = result.with_identity(new_identity);
        }
        let host = Host {
            label: self.host.label.trim().to_string(),
            address: self.host.address.trim().to_string(),
            port: parse_port(&self.port)?,
            protocol: Some(protocol),
            proxy,
            identity,
            tags: parse_tags(&self.tags),
            env: parse_env(&self.env)?,
            ..self.host.clone()
        };
        Ok(result.with_host(host))
    }
}

const GENERAL_THEME: &str = "Usar el tema general";

/// Tema propio del host; `None` usa el de ajustes.
fn theme_selector(ui: &mut egui::Ui, value: &mut Option<String>, data: &VaultData) {
    let custom = &data.settings.custom_themes;
    let selected = value
        .as_deref()
        .map(|id| tunel_term::palette::find(id, custom).name.clone())
        .unwrap_or_else(|| GENERAL_THEME.into());
    ui.horizontal(|ui| {
        ui.label("Tema de la terminal");
        egui::ComboBox::from_id_salt("tema-host")
            .selected_text(selected)
            .width(220.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(value, None, GENERAL_THEME);
                ui.separator();
                for theme in custom.iter().chain(tunel_term::palette::builtin()) {
                    ui.selectable_value(value, Some(theme.id.clone()), &theme.name);
                }
            });
    });
}

pub(super) fn host_form(ui: &mut egui::Ui, form: &mut HostForm, data: &VaultData) {
    egui::Grid::new("form-host")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            ui.label("Nombre");
            ui.add(
                egui::TextEdit::singleline(&mut form.host.label)
                    .hint_text("web-01")
                    .desired_width(FIELD_WIDTH),
            );
            ui.end_row();
            ui.label("Protocolo");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut form.protocol, ProtocolChoice::Ssh, "SSH");
                ui.selectable_value(&mut form.protocol, ProtocolChoice::Mosh, "Mosh");
                ui.selectable_value(&mut form.protocol, ProtocolChoice::Telnet, "Telnet");
                ui.selectable_value(&mut form.protocol, ProtocolChoice::Serial, "Serie");
            });
            ui.end_row();
            if form.protocol == ProtocolChoice::Serial {
                ui.label("Puerto serie");
                egui::ComboBox::from_id_salt("serie")
                    .selected_text(form.serial_device.clone())
                    .show_ui(ui, |ui| {
                        for port in tunel_term::serial::available_ports() {
                            ui.selectable_value(&mut form.serial_device, port.clone(), port);
                        }
                    });
                ui.end_row();
                ui.label("Baudios");
                ui.text_edit_singleline(&mut form.serial_baud);
                ui.end_row();
            } else {
                ui.label("Dirección");
                ui.add(
                    egui::TextEdit::singleline(&mut form.host.address)
                        .hint_text("servidor.ejemplo.com")
                        .desired_width(FIELD_WIDTH),
                );
                ui.end_row();
                ui.label("Puerto");
                ui.add(
                    egui::TextEdit::singleline(&mut form.port)
                        .hint_text(default_port_hint(form.protocol))
                        .desired_width(80.0),
                );
                ui.end_row();
            }
            if form.protocol == ProtocolChoice::Mosh {
                ui.label("Comando mosh-server");
                ui.add(egui::TextEdit::singleline(&mut form.mosh_command).hint_text("mosh-server"));
                ui.end_row();
            }
            ui.label("Grupo");
            let groups: Vec<(GroupId, String)> =
                data.groups.iter().map(|g| (g.id, g.name.clone())).collect();
            combo(ui, "grupo", &mut form.host.group, &groups, "(sin grupo)");
            ui.end_row();
            ui.label("Identidad");
            let identities: Vec<(IdentityId, String)> = data
                .identities
                .iter()
                .map(|i| (i.id, format!("{} ({})", i.label, i.username)))
                .collect();
            let inherited = form
                .host
                .group
                .and_then(|g| data.group(g))
                .and_then(|g| g.identity)
                .and_then(|i| data.identity(i))
                .map(|i| format!("Heredada del grupo: {}", i.label))
                .unwrap_or_else(|| "(ninguna)".into());
            combo(
                ui,
                "identidad",
                &mut form.host.identity,
                &identities,
                &inherited,
            );
            ui.end_row();
            ui.label("Usuario nuevo");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut form.new_username)
                        .hint_text("usuario")
                        .desired_width(FIELD_WIDTH / 2.0 - 4.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut form.new_password)
                        .password(true)
                        .hint_text("contraseña")
                        .desired_width(FIELD_WIDTH / 2.0 - 4.0),
                );
            });
            ui.end_row();
            ui.label("Etiquetas");
            ui.add(
                egui::TextEdit::singleline(&mut form.tags)
                    .hint_text("producción, web")
                    .desired_width(FIELD_WIDTH),
            );
            ui.end_row();
        });

    ui.collapsing("Avanzado", |ui| {
        ui.horizontal(|ui| {
            crate::ui::toggle(ui, &mut form.host.agent_forwarding);
            ui.label("Reenvío del agente SSH");
        });
        theme_selector(ui, &mut form.host.terminal_theme, data);
        ui.label("Saltar a través de (jump hosts, en orden):");
        for other in data.hosts.iter().filter(|h| h.id != form.host.id) {
            let mut on = form.host.jump_hosts.contains(&other.id);
            if ui.checkbox(&mut on, other.display_name()).changed() {
                form.host.jump_hosts = if on {
                    form.host
                        .jump_hosts
                        .iter()
                        .copied()
                        .chain(std::iter::once(other.id))
                        .collect()
                } else {
                    form.host
                        .jump_hosts
                        .iter()
                        .copied()
                        .filter(|j| *j != other.id)
                        .collect()
                };
            }
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Proxy");
            ui.selectable_value(&mut form.proxy, ProxyChoice::None, "Ninguno");
            ui.selectable_value(&mut form.proxy, ProxyChoice::Socks5, "SOCKS5");
            ui.selectable_value(&mut form.proxy, ProxyChoice::Http, "HTTP");
        });
        if form.proxy != ProxyChoice::None {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut form.proxy_host)
                        .hint_text("proxy")
                        .desired_width(140.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut form.proxy_port)
                        .hint_text("puerto")
                        .desired_width(60.0),
                );
            });
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut form.proxy_user)
                        .hint_text("usuario")
                        .desired_width(100.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut form.proxy_password)
                        .password(true)
                        .hint_text("contraseña")
                        .desired_width(100.0),
                );
            });
        }
        ui.separator();
        ui.label("Snippet de inicio");
        let snippets: Vec<(SnippetId, String)> = data
            .snippets
            .iter()
            .map(|s| (s.id, s.label.clone()))
            .collect();
        combo(
            ui,
            "snippet-inicio",
            &mut form.host.startup_snippet,
            &snippets,
            "(ninguno)",
        );
        ui.label("Variables de entorno (NOMBRE=valor por línea)");
        ui.add(
            egui::TextEdit::multiline(&mut form.env)
                .desired_rows(3)
                .code_editor(),
        );
        ui.label("Notas");
        ui.add(egui::TextEdit::multiline(&mut form.host.notes).desired_rows(2));
    });
    if let Some(error) = &form.error {
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
}

/// Lee el contenido de un archivo elegido por el usuario (clave o certificado).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_accepts_empty_and_valid_ports() {
        assert_eq!(parse_port(""), Ok(None));
        assert_eq!(parse_port(" 2222 "), Ok(Some(2222)));
        assert!(parse_port("0").is_err());
        assert!(parse_port("70000").is_err());
        assert!(parse_port("ssh").is_err());
    }

    #[test]
    fn parse_tags_trims_and_drops_empty() {
        assert_eq!(parse_tags(" web, , prod ,"), vec!["web", "prod"]);
    }

    #[test]
    fn parse_env_reads_pairs_and_rejects_bad_names() {
        let env = parse_env("LANG=es_ES.UTF-8\n# comentario\n\nEDITOR=vim -u NONE").unwrap();
        assert_eq!(env.get("EDITOR").map(String::as_str), Some("vim -u NONE"));
        assert!(parse_env("SIN_IGUAL").is_err());
        assert!(parse_env("1X=a").is_err());
        assert!(parse_env("A-B=c").is_err());
        assert_eq!(format_env(&env), "EDITOR=vim -u NONE\nLANG=es_ES.UTF-8");
    }

    #[test]
    fn host_form_requires_address_for_network_protocols() {
        let form = HostForm::new(Host::new("x", ""));
        assert!(form.build(&VaultData::default()).is_err());
    }

    #[test]
    fn host_form_creates_inline_identity() {
        let host = Host::new("web", "10.0.0.1");
        let id = host.id;
        let mut form = HostForm::new(host);
        form.new_username = "ana".into();
        form.new_password = "secreto".into();
        form.port = "2200".into();
        let data = form.build(&VaultData::default()).unwrap();
        let resolved = data.resolve(id).unwrap();
        assert_eq!(resolved.port, 2200);
        let identity = resolved.identity.unwrap();
        assert_eq!(identity.username, "ana");
        assert_eq!(identity.password.as_deref(), Some("secreto"));
    }

    #[test]
    fn host_form_round_trips_proxy_settings() {
        let host = Host {
            proxy: Some(ProxyConfig::Http {
                host: "p".into(),
                port: 3128,
                username: None,
                password: None,
            }),
            ..Host::new("a", "b")
        };
        let id = host.id;
        let data = HostForm::new(host).build(&VaultData::default()).unwrap();
        assert_eq!(
            data.host(id).unwrap().proxy,
            Some(ProxyConfig::Http {
                host: "p".into(),
                port: 3128,
                username: None,
                password: None
            })
        );
    }
}
