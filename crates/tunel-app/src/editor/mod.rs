//! Ventanas de edición para cada tipo de elemento de la bóveda.

mod host;
mod install_key;
mod keygen;

use crate::app::TunelApp;
use host::{HostForm, effective_identity, host_form, inherited_theme, parse_port, team_picker};
pub use install_key::installed_message;
use install_key::{InstallKeyForm, install_key_form};
use keygen::{KeyGenForm, keygen_form};
use tunel_core::*;

const MODAL_WIDTH: f32 = 520.0;

pub enum Editor {
    Host(Box<HostForm>),
    Group(Group),
    Identity(Identity),
    Key(SshKey),
    GenerateKey(Box<KeyGenForm>),
    InstallKey(Box<InstallKeyForm>),
    Snippet(Snippet),
    Forward {
        rule: PortForward,
        bind_port: String,
        dest_port: String,
        error: Option<String>,
    },
}

impl Editor {
    pub fn host(host: Host) -> Self {
        Editor::Host(Box::new(HostForm::new(host)))
    }

    pub fn generate_key() -> Self {
        Editor::GenerateKey(Box::new(KeyGenForm::new()))
    }

    pub fn install_key(key: SshKey) -> Self {
        Editor::InstallKey(Box::new(InstallKeyForm::new(key)))
    }

    pub fn forward(rule: PortForward) -> Self {
        Editor::Forward {
            bind_port: rule.bind_port.to_string(),
            dest_port: rule.destination_port.to_string(),
            rule,
            error: None,
        }
    }
}

/// Campos de contraseña de los formularios, para olvidar al cerrar cuáles se veían.
const PASSWORD_FIELDS: [&str; 3] = ["host-nueva", "host-identidad", "identidad"];

/// Quién puede ver las contraseñas guardadas: las de la bóveda personal, siempre; las de
/// un Team, solo sus administradores.
pub(super) struct Secrets {
    admin_teams: Vec<String>,
}

impl Secrets {
    fn of(app: &TunelApp) -> Self {
        let admin_teams = app
            .sync
            .local()
            .map(|l| {
                l.teams
                    .iter()
                    .filter(|t| t.role == tunel_core::sync::protocol::TeamRole::Admin)
                    .map(|t| t.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        Self { admin_teams }
    }

    pub(super) fn can_reveal(&self, team: Option<&str>) -> bool {
        team.is_none_or(|team| self.admin_teams.iter().any(|t| t == team))
    }
}

pub(super) fn combo<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut Option<T>,
    options: &[(T, String)],
    none: &str,
) {
    let selected = value
        .and_then(|v| options.iter().find(|(o, _)| *o == v))
        .map(|(_, l)| l.clone())
        .unwrap_or_else(|| none.into());
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, none);
            for (option, label) in options {
                ui.selectable_value(value, Some(*option), label);
            }
        });
}

fn pick_text_file(title: &str) -> Option<Result<String, String>> {
    let path = rfd::FileDialog::new().set_title(title).pick_file()?;
    Some(
        std::fs::read_to_string(&path)
            .map_err(|e| format!("No se pudo leer {}: {e}", path.display())),
    )
}

fn key_form(ui: &mut egui::Ui, key: &mut SshKey) {
    ui.label("Nombre");
    ui.text_edit_singleline(&mut key.label);
    ui.horizontal(|ui| {
        ui.label("Clave privada (OpenSSH/PEM)");
        if ui.button("Importar archivo…").clicked()
            && let Some(Ok(text)) = pick_text_file("Clave privada")
        {
            key.private_key = text;
            key.public_key = None;
        }
    });
    let edited = ui
        .add(
            egui::TextEdit::multiline(&mut key.private_key)
                .desired_rows(6)
                .code_editor()
                .hint_text("-----BEGIN OPENSSH PRIVATE KEY-----"),
        )
        .changed();
    if edited {
        key.public_key = None;
    }
    let mut passphrase = key.passphrase.clone().unwrap_or_default();
    ui.label("Frase de paso (si la clave está cifrada)");
    if ui
        .add(egui::TextEdit::singleline(&mut passphrase).password(true))
        .changed()
    {
        key.passphrase = Some(passphrase).filter(|p| !p.is_empty());
        key.public_key = None;
    }
    ui.horizontal(|ui| {
        ui.label("Certificado OpenSSH (opcional)");
        if ui.button("Importar…").clicked()
            && let Some(Ok(text)) = pick_text_file("Certificado")
        {
            key.certificate = Some(text);
        }
        if key.certificate.is_some() && ui.button("Quitar").clicked() {
            key.certificate = None;
        }
    });
    public_key_field(ui, key);
}

/// La clave pública, para copiarla a `authorized_keys`. Se recalcula si cambia la privada.
fn public_key_field(ui: &mut egui::Ui, key: &mut SshKey) {
    if key.public_key.is_none() {
        key.public_key = tunel_ssh::keygen::public_key(&key.private_key, key.passphrase.as_deref());
    }
    let Some(public) = key.public_key.clone() else {
        return;
    };
    ui.horizontal(|ui| {
        ui.label("Clave pública");
        if ui.button("Copiar").clicked() {
            ui.ctx().copy_text(public.clone());
        }
    });
    ui.add(
        egui::TextEdit::multiline(&mut public.as_str())
            .desired_rows(2)
            .code_editor(),
    );
}

fn identity_form(ui: &mut egui::Ui, identity: &mut Identity, data: &VaultData, secrets: &Secrets) {
    egui::Grid::new("form-identidad")
        .num_columns(2)
        .show(ui, |ui| {
            ui.label("Nombre");
            ui.text_edit_singleline(&mut identity.label);
            ui.end_row();
            ui.label("Usuario");
            ui.text_edit_singleline(&mut identity.username);
            ui.end_row();
            ui.label("Contraseña");
            let mut password = identity.password.clone().unwrap_or_default();
            let can_reveal = secrets.can_reveal(identity.team.as_deref());
            let changed = ui
                .horizontal(|ui| {
                    crate::ui::password_field(ui, "identidad", &mut password, "", 220.0, can_reveal)
                })
                .inner
                .changed();
            if changed {
                identity.password = Some(password).filter(|p| !p.is_empty());
            }
            ui.end_row();
            ui.label("Clave");
            let keys: Vec<(KeyId, String)> =
                data.keys.iter().map(|k| (k.id, k.label.clone())).collect();
            combo(ui, "clave", &mut identity.key, &keys, "(ninguna)");
            ui.end_row();
        });
    ui.checkbox(
        &mut identity.use_agent,
        "Probar también las claves del agente SSH del sistema",
    );
}

/// Muestra el editor abierto, si lo hay, y aplica los cambios al guardar.
pub fn show(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let teams = crate::sync::teams::names(app);
    let secrets = Secrets::of(app);
    if let Some(Editor::GenerateKey(form)) = app.editor.as_mut()
        && let Some(key) = form.poll()
    {
        app.commit(data.with_key(key.clone()));
        app.editor = Some(Editor::Key(key));
        return;
    }
    let Some(editor) = app.editor.as_mut() else {
        return;
    };
    let mut save = false;
    let mut cancel = false;
    use crate::ui::icons;
    let (icon, noun, exists) = match &*editor {
        Editor::Host(f) => (icons::SERVERS, "host", data.host(f.host.id).is_some()),
        Editor::Group(g) => (icons::FOLDER, "grupo", data.group(g.id).is_some()),
        Editor::Identity(i) => (icons::IDENTITY, "identidad", data.identity(i.id).is_some()),
        Editor::Key(k) => (icons::KEY, "clave SSH", data.key(k.id).is_some()),
        Editor::GenerateKey(_) => (icons::KEY, "clave SSH", false),
        Editor::InstallKey(_) => (icons::UPLOAD, "clave SSH", false),
        Editor::Snippet(s) => (icons::CODE, "snippet", data.snippet(s.id).is_some()),
        Editor::Forward { rule, .. } => (
            icons::TUNNEL,
            "regla de túnel",
            data.forwards.iter().any(|f| f.id == rule.id),
        ),
    };
    let generating = matches!(&*editor, Editor::GenerateKey(f) if f.generating());
    let (title, action) = match &*editor {
        Editor::GenerateKey(_) => ("Generar clave SSH".to_string(), "  Generar  "),
        Editor::InstallKey(_) => ("Instalar la clave en un host".to_string(), "  Instalar  "),
        _ if exists => (format!("Editar {noun}"), "  Guardar  "),
        _ => (format!("Nuevo {noun}"), "  Guardar  "),
    };
    let p = crate::ui::theme::palette(ctx);
    let frame = egui::Frame::popup(&ctx.global_style())
        .inner_margin(egui::Margin::same(24))
        .corner_radius(egui::CornerRadius::same(14));
    let modal = egui::Modal::new(egui::Id::unique("editor"))
        .frame(frame)
        .show(ctx, |ui| {
            ui.set_width(MODAL_WIDTH);
            ui.horizontal(|ui| {
                let (rect, _) =
                    ui.allocate_exact_size(egui::Vec2::splat(34.0), egui::Sense::hover());
                crate::ui::avatar(ui, rect, icon, p.accent);
                ui.label(egui::RichText::new(&title).size(18.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    cancel |= crate::ui::icon_button(ui, icons::CLOSE, "Cerrar (Esc)").clicked();
                });
            });
            ui.add_space(12.0);
            egui::ScrollArea::vertical()
                .max_height(ctx.content_rect().height() * 0.7)
                .show(ui, |ui| match editor {
                    Editor::Host(form) => host_form(ui, form, &data, &teams, &secrets),
                    Editor::Group(group) => {
                        ui.label("Nombre");
                        ui.text_edit_singleline(&mut group.name);
                        if !teams.is_empty() || group.team.is_some() {
                            ui.label("Compartir en (con sus subgrupos y hosts)");
                            team_picker(ui, "team-grupo", &mut group.team, &teams);
                        }
                        ui.label("Identidad por defecto para sus hosts");
                        let identities: Vec<(IdentityId, String)> = data
                            .identities
                            .iter()
                            .map(|i| (i.id, i.label.clone()))
                            .collect();
                        combo(
                            ui,
                            "grupo-identidad",
                            &mut group.identity,
                            &identities,
                            "(ninguna)",
                        );
                        ui.label("Grupo padre");
                        let parents: Vec<(GroupId, String)> = data
                            .groups
                            .iter()
                            .filter(|g| g.id != group.id)
                            .map(|g| (g.id, g.name.clone()))
                            .collect();
                        combo(ui, "grupo-padre", &mut group.parent, &parents, "(raíz)");
                        ui.label("Tema de la terminal para sus hosts");
                        let inherited = inherited_theme(&data, group.parent);
                        crate::views::themes::theme_picker(
                            ui,
                            "tema-grupo",
                            &mut group.terminal_theme,
                            &inherited,
                            &data.settings.custom_themes,
                        );
                    }
                    Editor::Identity(identity) => identity_form(ui, identity, &data, &secrets),
                    Editor::Key(key) => key_form(ui, key),
                    Editor::GenerateKey(form) => keygen_form(ui, form),
                    Editor::InstallKey(form) => install_key_form(ui, form, &data),
                    Editor::Snippet(snippet) => {
                        ui.label("Nombre");
                        ui.text_edit_singleline(&mut snippet.label);
                        ui.label("Script");
                        ui.add(
                            egui::TextEdit::multiline(&mut snippet.script)
                                .desired_rows(8)
                                .code_editor(),
                        );
                        ui.label(
                            egui::RichText::new(
                                "Escribe {{nombre}} para que pida un valor al ejecutarlo, por \
                                 ejemplo: systemctl restart {{servicio}}",
                            )
                            .size(12.0)
                            .color(crate::ui::pal(ui).muted),
                        );
                    }
                    Editor::Forward {
                        rule,
                        bind_port,
                        dest_port,
                        error,
                    } => {
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut rule.kind, ForwardKind::Local, "Local (-L)");
                            ui.selectable_value(&mut rule.kind, ForwardKind::Remote, "Remoto (-R)");
                            ui.selectable_value(
                                &mut rule.kind,
                                ForwardKind::Dynamic,
                                "Dinámico (-D)",
                            );
                        });
                        ui.label("Nombre");
                        ui.text_edit_singleline(&mut rule.label);
                        ui.label("Host SSH");
                        // Una regla de un Team solo va por hosts de ese Team.
                        let hosts: Vec<(HostId, String)> = data
                            .hosts
                            .iter()
                            .filter(|h| tunel_core::vault::can_use(&rule.team, &h.team))
                            .map(|h| (h.id, h.display_name().to_string()))
                            .collect();
                        let mut host = Some(rule.host);
                        combo(ui, "regla-host", &mut host, &hosts, "(elige un host)");
                        if let Some(h) = host {
                            rule.host = h;
                        }
                        let bind_label = if rule.kind == ForwardKind::Remote {
                            "Escuchar en el servidor"
                        } else {
                            "Escuchar en este equipo"
                        };
                        ui.label(bind_label);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut rule.bind_address)
                                    .desired_width(140.0),
                            );
                            ui.add(egui::TextEdit::singleline(bind_port).desired_width(70.0));
                        });
                        if rule.kind != ForwardKind::Dynamic {
                            ui.label("Destino");
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut rule.destination_host)
                                        .desired_width(140.0),
                                );
                                ui.add(egui::TextEdit::singleline(dest_port).desired_width(70.0));
                            });
                        }
                        if let Some(error) = error {
                            ui.colored_label(ui.visuals().error_fg_color, error.as_str());
                        }
                    }
                });
            ui.add_space(16.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                save = ui
                    .add_enabled_ui(!generating, |ui| crate::ui::primary_button(ui, action))
                    .inner
                    .clicked();
                cancel |= crate::ui::secondary_button(ui, "Cancelar").clicked();
            });
        });
    cancel |= modal.should_close();
    record_revealed(app, ctx, &data);

    if cancel {
        crate::ui::forget_revealed(ctx, &PASSWORD_FIELDS);
        app.editor = None;
        return;
    }
    if !save {
        return;
    }
    let result: Result<VaultData, String> = match app.editor.as_mut() {
        Some(Editor::Host(form)) => form
            .build(&data)
            .inspect_err(|e| form.error = Some(e.clone())),
        Some(Editor::Group(group)) => {
            let before = data.group(group.id).and_then(|g| g.team.clone());
            let saved = data.with_group(Group {
                team: before.clone(),
                ..group.clone()
            });
            Ok(if group.team == before {
                saved
            } else {
                tunel_core::share::move_group(
                    &saved,
                    group.id,
                    group.team.as_deref(),
                    tunel_core::share::Credentials::Copy,
                )
            })
        }
        Some(Editor::Identity(identity)) => Ok(data.with_identity(identity.clone())),
        Some(Editor::Key(key)) => Ok(data.with_key(key.clone())),
        Some(Editor::GenerateKey(form)) => {
            if let Err(e) = form.start(ctx) {
                form.error = Some(e);
            }
            return;
        }
        Some(Editor::InstallKey(form)) => {
            let started = form.request(&data).and_then(|(host, public)| {
                app.engine
                    .install_key(&data, host, public)
                    .map_err(|e| format!("{e:#}"))
            });
            match started {
                Ok(()) => {
                    app.notify("Instalando la clave…");
                    app.editor = None;
                }
                Err(e) => form.error = Some(e),
            }
            return;
        }
        Some(Editor::Snippet(snippet)) => Ok(data.with_snippet(snippet.clone())),
        Some(Editor::Forward {
            rule,
            bind_port,
            dest_port,
            error,
        }) => {
            let parsed = parse_port(bind_port)
                .and_then(|b| b.ok_or("Falta el puerto de escucha".to_string()))
                .and_then(|b| {
                    let d = if rule.kind == ForwardKind::Dynamic {
                        Some(0)
                    } else {
                        parse_port(dest_port)?
                    };
                    Ok((b, d.ok_or("Falta el puerto de destino")?))
                });
            match parsed {
                Ok((bind, dest)) if data.forward_host(rule).is_ok() => {
                    Ok(data.with_forward(PortForward {
                        bind_port: bind,
                        destination_port: dest,
                        ..rule.clone()
                    }))
                }
                Ok(_) => {
                    *error = Some("Elige el host SSH".into());
                    Err(String::new())
                }
                Err(e) => {
                    *error = Some(e.clone());
                    Err(e)
                }
            }
        }
        None => return,
    };
    if let Ok(updated) = result {
        app.commit(updated);
        crate::ui::forget_revealed(ctx, &PASSWORD_FIELDS);
        app.editor = None;
    }
}

/// Anota en el registro del Team las contraseñas guardadas que se acaban de mostrar.
fn record_revealed(app: &mut TunelApp, ctx: &egui::Context, data: &VaultData) {
    for field in crate::ui::take_revealed(ctx) {
        let identity = match (field.as_str(), app.editor.as_ref()) {
            ("identidad", Some(Editor::Identity(i))) => data.identity(i.id),
            ("host-identidad", Some(Editor::Host(form))) => effective_identity(form, data),
            _ => None,
        };
        if let Some(identity) = identity.filter(|i| i.password.is_some()).cloned() {
            crate::audit::secret_viewed(app, &identity);
        }
    }
}
