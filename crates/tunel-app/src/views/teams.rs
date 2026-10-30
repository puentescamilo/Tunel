//! Tarjeta de Teams en Ajustes: invitaciones, Teams, miembros y huellas.

use crate::app::TunelApp;
use crate::sync::teams::{Confirm, TeamOp, start, trust_key};
use crate::ui::{self, icons};
use egui::{FontId, RichText};
use tunel_core::sync::protocol::TeamRole;
use tunel_core::sync::{PublicKey, SyncLocal, TeamLocal};
use tunel_sync::teams::{KeyStatus, MAX_TEAM_NAME_CHARS, MemberView};

const HELP: &str = "Un Team comparte hosts, grupos y sus credenciales con otras cuentas de este \
servidor, cifrados de extremo a extremo. Para compartir un host o un grupo, elige el Team en su \
ficha.";
const FINGERPRINT_HELP: &str = "Compara la huella con la otra persona por un medio que no pase \
por el servidor (en persona, por teléfono). Si coincide, nadie se está haciendo pasar por ella.";

fn fingerprint(ui: &mut egui::Ui, key: &PublicKey) {
    ui.label(
        RichText::new(key.fingerprint())
            .font(FontId::monospace(12.0))
            .color(ui::pal(ui).text),
    );
}

fn muted(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text).size(12.0).color(ui::pal(ui).muted));
}

pub fn card(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    let p = ui::pal(ui);
    ui.label(RichText::new(HELP).color(p.muted));
    ui.add_space(8.0);
    if local.keypair.is_none() {
        muted(
            ui,
            "Sincroniza una vez para preparar las claves de los Teams (hace falta un servidor \
             actualizado).",
        );
        return;
    }
    let busy = app.sync.busy();
    if let Some(working) = app.sync.teams.working {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new(working).color(p.muted));
        });
        ui.add_space(6.0);
    }
    for problem in app.sync.team_problems().to_vec() {
        let name = local
            .team(&problem.team)
            .map_or("Teams".to_string(), |t| t.name.clone());
        ui.label(
            RichText::new(format!("{name}: {}", problem.message))
                .size(12.0)
                .color(p.warning),
        );
    }
    invitations(app, ui, &local, busy);
    for team in &local.teams {
        team_row(app, ui, team, busy);
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let teams = &mut app.sync.teams;
        ui.add(
            egui::TextEdit::singleline(&mut teams.new_name)
                .hint_text("Nombre del nuevo Team")
                .char_limit(MAX_TEAM_NAME_CHARS)
                .desired_width(260.0),
        );
        let name = teams.new_name.trim().to_string();
        let create = ui
            .add_enabled_ui(!busy && !name.is_empty(), |ui| {
                ui::primary_button(ui, &ui::with_icon(icons::PLUS, "Crear Team"))
            })
            .inner
            .clicked();
        if create {
            start(app, TeamOp::Create { name });
        }
    });
}

fn invitations(app: &mut TunelApp, ui: &mut egui::Ui, local: &SyncLocal, busy: bool) {
    for invitation in &local.invitations {
        ui::card_frame(ui, true)
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!("{} te invita a un Team", invitation.from)).strong(),
                );
                ui.horizontal(|ui| {
                    muted(ui, "Su huella:");
                    fingerprint(ui, &invitation.from_key);
                });
                muted(ui, FINGERPRINT_HELP);
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui::primary_button(ui, "Coincide, aceptar").clicked() {
                            start(
                                app,
                                TeamOp::Accept {
                                    team: invitation.team.clone(),
                                },
                            );
                        }
                        if ui::secondary_button(ui, "Rechazar").clicked() {
                            start(
                                app,
                                TeamOp::Leave {
                                    team: invitation.team.clone(),
                                },
                            );
                        }
                    });
                });
            });
        ui.add_space(8.0);
    }
}

fn role_name(role: TeamRole) -> &'static str {
    match role {
        TeamRole::Admin => "Admin",
        TeamRole::Member => "Miembro",
    }
}

fn team_row(app: &mut TunelApp, ui: &mut egui::Ui, team: &TeamLocal, busy: bool) {
    let p = ui::pal(ui);
    let open = app.sync.teams.open.as_deref() == Some(team.id.as_str());
    ui::card_frame(ui, open)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let header = ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::USERS)
                        .font(ui::icon_font(16.0))
                        .color(p.accent),
                );
                ui.label(RichText::new(&team.name).strong());
                ui::chip(ui, role_name(team.role), p.muted);
                let pending = team.state.pending.len();
                if pending > 0 {
                    muted(ui, format!("{pending} cambios por subir"));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if open { "Cerrar" } else { "Miembros" };
                    ui.add_enabled_ui(!busy || open, |ui| ui::secondary_button(ui, label))
                        .inner
                        .clicked()
                })
                .inner
            });
            if header.inner {
                if open {
                    app.sync.teams.open = None;
                    app.sync.teams.members = None;
                } else {
                    app.sync.teams.open = Some(team.id.clone());
                    app.sync.teams.members = None;
                    app.sync.teams.found = None;
                    app.sync.teams.confirm = None;
                    start(
                        app,
                        TeamOp::Members {
                            team: team.id.clone(),
                        },
                    );
                }
            }
            if open {
                ui.add_space(8.0);
                team_details(app, ui, team, busy);
            }
        });
    ui.add_space(8.0);
}

fn status_text(status: KeyStatus) -> (&'static str, &'static str) {
    match status {
        KeyStatus::Own => ("Tú", "Tu propia clave"),
        KeyStatus::Verified => ("Verificada", "Comparaste su huella en persona"),
        KeyStatus::Pinned => (
            "Conocida",
            "Es la clave que ya conocías, pero no comparaste la huella",
        ),
        KeyStatus::New => (
            "Sin confirmar",
            "Nunca confirmaste esta clave: compara la huella",
        ),
        KeyStatus::Changed => (
            "¡Cambió!",
            "No es la clave que conocías: puede ser una suplantación",
        ),
    }
}

fn team_details(app: &mut TunelApp, ui: &mut egui::Ui, team: &TeamLocal, busy: bool) {
    let p = ui::pal(ui);
    let admin = team.role == TeamRole::Admin;
    let members = app
        .sync
        .teams
        .members
        .as_ref()
        .filter(|(id, _)| *id == team.id)
        .map(|(_, m)| m.clone());
    match &members {
        None => muted(ui, "Cargando miembros…"),
        Some(members) => {
            for member in members {
                member_row(app, ui, team, member, admin, busy);
            }
        }
    }
    ui.add_space(8.0);
    if admin {
        invite_form(app, ui, team, busy);
        ui.add_space(8.0);
    }
    let confirm = app.sync.teams.confirm.clone();
    ui.horizontal(|ui| {
        ui.add_enabled_ui(!busy, |ui| match &confirm {
            Some(Confirm::Leave { team: id }) if *id == team.id => {
                ui.label(
                    RichText::new("¿Salir? Sus hosts desaparecerán de este equipo.")
                        .color(p.warning),
                );
                if ui::danger_button(ui, "Sí, salir").clicked() {
                    app.sync.teams.confirm = None;
                    start(
                        app,
                        TeamOp::Leave {
                            team: team.id.clone(),
                        },
                    );
                }
                if ui::secondary_button(ui, "Cancelar").clicked() {
                    app.sync.teams.confirm = None;
                }
            }
            Some(Confirm::Delete { team: id }) if *id == team.id => {
                ui.label(RichText::new("¿Borrar el Team para todos sus miembros?").color(p.danger));
                if ui::danger_button(ui, "Sí, borrar").clicked() {
                    app.sync.teams.confirm = None;
                    start(
                        app,
                        TeamOp::Delete {
                            team: team.id.clone(),
                        },
                    );
                }
                if ui::secondary_button(ui, "Cancelar").clicked() {
                    app.sync.teams.confirm = None;
                }
            }
            _ => {
                if ui::secondary_button(ui, "Salir del Team").clicked() {
                    app.sync.teams.confirm = Some(Confirm::Leave {
                        team: team.id.clone(),
                    });
                }
                if admin
                    && ui::danger_button(ui, &ui::with_icon(icons::TRASH, "Borrar Team")).clicked()
                {
                    app.sync.teams.confirm = Some(Confirm::Delete {
                        team: team.id.clone(),
                    });
                }
            }
        });
    });
}

fn member_row(
    app: &mut TunelApp,
    ui: &mut egui::Ui,
    team: &TeamLocal,
    member: &MemberView,
    admin: bool,
    busy: bool,
) {
    let p = ui::pal(ui);
    let (status, help) = status_text(member.key);
    let color = match member.key {
        KeyStatus::Own | KeyStatus::Verified => p.success,
        KeyStatus::Pinned => p.muted,
        KeyStatus::New => p.warning,
        KeyStatus::Changed => p.danger,
    };
    let own = member.key == KeyStatus::Own;
    let confirming = app.sync.teams.confirm
        == Some(Confirm::Remove {
            team: team.id.clone(),
            email: member.email.clone(),
        });
    ui.horizontal(|ui| {
        ui.label(&member.email);
        ui::chip(ui, role_name(member.role), p.muted);
        if member.pending {
            ui::chip(ui, "Invitado", p.warning);
        }
        ui::chip(ui, status, color).on_hover_text(help);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                if admin && !own {
                    if confirming {
                        if ui::danger_button(ui, "Sí, expulsar").clicked() {
                            app.sync.teams.confirm = None;
                            start(
                                app,
                                TeamOp::Remove {
                                    team: team.id.clone(),
                                    email: member.email.clone(),
                                },
                            );
                        }
                        if ui::secondary_button(ui, "Cancelar").clicked() {
                            app.sync.teams.confirm = None;
                        }
                    } else {
                        if ui::icon_button(ui, icons::TRASH, "Expulsar y renovar la clave")
                            .clicked()
                        {
                            app.sync.teams.confirm = Some(Confirm::Remove {
                                team: team.id.clone(),
                                email: member.email.clone(),
                            });
                        }
                        let (label, role) = match member.role {
                            TeamRole::Admin => ("Quitar admin", TeamRole::Member),
                            TeamRole::Member => ("Hacer admin", TeamRole::Admin),
                        };
                        if !member.pending && ui::secondary_button(ui, label).clicked() {
                            start(
                                app,
                                TeamOp::SetRole {
                                    team: team.id.clone(),
                                    email: member.email.clone(),
                                    role,
                                },
                            );
                        }
                    }
                }
                match member.key {
                    KeyStatus::New | KeyStatus::Pinned => {
                        if ui::secondary_button(ui, "La huella coincide").clicked() {
                            trust_key(app, &member.email, member.public_key, false);
                        }
                    }
                    KeyStatus::Changed => {
                        if ui::danger_button(ui, "Aceptar la clave nueva").clicked() {
                            trust_key(app, &member.email, member.public_key, true);
                        }
                    }
                    KeyStatus::Own | KeyStatus::Verified => {}
                }
            });
        });
    });
    if !own {
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            muted(ui, "Huella:");
            fingerprint(ui, &member.public_key);
        });
    }
    if confirming {
        muted(
            ui,
            "Dejará de recibir lo que se guarde en el Team; lo que ya tenía, lo conserva.",
        );
    }
    ui.add_space(4.0);
}

fn invite_form(app: &mut TunelApp, ui: &mut egui::Ui, team: &TeamLocal, busy: bool) {
    let found = app.sync.teams.found.clone();
    match found {
        None => {
            ui.horizontal(|ui| {
                let teams = &mut app.sync.teams;
                ui.add(
                    egui::TextEdit::singleline(&mut teams.invite_email)
                        .hint_text("Correo de la cuenta a invitar")
                        .desired_width(240.0),
                );
                ui::toggle(ui, &mut teams.invite_admin);
                ui.label("Admin");
                let email = teams.invite_email.trim().to_string();
                let search = ui
                    .add_enabled_ui(!busy && email.contains('@'), |ui| {
                        ui::secondary_button(ui, &ui::with_icon(icons::SEARCH, "Buscar"))
                    })
                    .inner
                    .clicked();
                if search {
                    start(app, TeamOp::Lookup { email });
                }
            });
        }
        Some((email, key)) => {
            ui::card_frame(ui, true)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("Invitar a {email}")).strong());
                    ui.horizontal(|ui| {
                        muted(ui, "Su huella:");
                        fingerprint(ui, &key);
                    });
                    muted(ui, FINGERPRINT_HELP);
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(!busy, |ui| {
                            if ui::primary_button(ui, "Coincide, invitar").clicked() {
                                let role = if app.sync.teams.invite_admin {
                                    TeamRole::Admin
                                } else {
                                    TeamRole::Member
                                };
                                start(
                                    app,
                                    TeamOp::Invite {
                                        team: team.id.clone(),
                                        email: email.clone(),
                                        role,
                                        key,
                                    },
                                );
                            }
                            if ui::secondary_button(ui, "Cancelar").clicked() {
                                app.sync.teams.found = None;
                            }
                        });
                    });
                });
        }
    }
}
