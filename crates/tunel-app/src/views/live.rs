//! Sesiones compartidas en la interfaz: la franja «En vivo» de la vista de hosts y la
//! barra sobre una terminal que se comparte o se mira.

use crate::app::TunelApp;
use crate::live::{self, Live, Share, Watching};
use crate::session::TerminalSession;
use crate::ui::{self, icons};
use egui::{FontId, RichText};
use tunel_core::sync::protocol::ConnId;
use tunel_sync::live::LiveListing;
use tunel_sync::teams::KeyStatus;

const FINGERPRINT_HELP: &str = "Pídele que lea la huella de su cuenta (Ajustes → Teams) por \
un medio que no pase por el servidor, como una llamada. Si coincide, es esa persona.";

/// Sesiones en vivo de los Teams, encima de la lista de hosts.
pub fn strip(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(local) = app.sync.local() else {
        return;
    };
    if local.teams.is_empty() || local.keypair.is_none() {
        return;
    }
    let own = local.email.clone();
    live::refresh_if_due(app);
    ui.ctx().request_repaint_after(live::REFRESH);
    let listings: Vec<LiveListing> = app
        .live
        .listings()
        .filter(|l| !l.owner.eq_ignore_ascii_case(&own))
        .cloned()
        .collect();
    if listings.is_empty() {
        return;
    }
    let p = ui::pal(ui);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(icons::BROADCAST)
                .font(ui::icon_font(15.0))
                .color(p.danger),
        );
        ui.label(RichText::new("En vivo").strong());
        if ui::icon_button(ui, icons::REFRESH, "Actualizar").clicked() {
            live::refresh(app);
        }
    });
    for listing in listings {
        listing_row(app, ui, listing);
    }
    ui.add_space(10.0);
}

fn listing_row(app: &mut TunelApp, ui: &mut egui::Ui, listing: LiveListing) {
    let p = ui::pal(ui);
    let team = app
        .sync
        .local()
        .and_then(|l| l.team(&listing.team))
        .map_or_else(String::new, |t| t.name.clone());
    let opening = app.live.opening.as_deref() == Some(listing.id.as_str());
    let mut watch = false;
    ui::card_frame(ui, false)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::TERMINAL)
                        .font(ui::icon_font(15.0))
                        .color(p.accent),
                );
                let title = listing.title.as_deref().unwrap_or("Sesión");
                ui.label(RichText::new(title).strong());
                ui.label(
                    RichText::new(format!("de {} · {team}", listing.owner))
                        .size(12.0)
                        .color(p.muted),
                );
                if listing.viewers > 0 {
                    ui::chip(ui, &format!("{} mirando", listing.viewers), p.muted);
                }
                let (warning, can_watch) = match (&listing.title, listing.owner_key) {
                    (None, _) => (Some("Anunciada con otra clave del Team; sincroniza"), false),
                    (_, Some(KeyStatus::Changed)) => (
                        Some("¡La clave de quien comparte cambió! Puede ser una suplantación"),
                        false,
                    ),
                    (_, Some(KeyStatus::New)) => (Some("Huella sin comprobar"), true),
                    _ => (None, true),
                };
                if let Some(warning) = warning {
                    ui.label(RichText::new(warning).size(12.0).color(p.warning));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if opening {
                        ui.spinner();
                    } else {
                        watch = ui
                            .add_enabled_ui(can_watch && app.live.opening.is_none(), |ui| {
                                ui::primary_button(ui, &ui::with_icon(icons::EYE, "Mirar"))
                            })
                            .inner
                            .clicked();
                    }
                });
            });
        });
    ui.add_space(6.0);
    if watch {
        live::start_watching(app, listing);
    }
}

/// Lo que la barra no puede hacer por sí sola: necesita la configuración o el motor.
pub enum BarAction {
    Grant(ConnId),
    Confirm,
    Stop,
}

/// Barra sobre una terminal compartida o que se mira.
pub fn bar(ui: &mut egui::Ui, session: &mut TerminalSession) -> Option<BarAction> {
    let p = ui::pal(ui);
    let mut action = None;
    egui::Frame::new()
        .fill(p.accent.gamma_multiply(0.10))
        .inner_margin(egui::Margin::symmetric(14, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            match session.live.as_mut() {
                Some(Live::Host(share)) => action = host_bar(ui, share),
                Some(Live::Viewer(watching)) => viewer_bar(ui, watching),
                None => {}
            }
        });
    action
}

fn host_bar(ui: &mut egui::Ui, share: &mut Share) -> Option<BarAction> {
    let p = ui::pal(ui);
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(icons::BROADCAST)
                .font(ui::icon_font(15.0))
                .color(p.danger),
        );
        let watching = match share.viewers.len() {
            0 => "nadie mirando todavía".to_string(),
            1 => "1 persona mirando".to_string(),
            n => format!("{n} personas mirando"),
        };
        ui.label(
            RichText::new(format!(
                "Compartiendo con «{}» · {watching}",
                share.team_name
            ))
            .color(p.text),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui::secondary_button(ui, &ui::with_icon(icons::STOP, "Dejar de compartir")).clicked()
            {
                action = Some(BarAction::Stop);
            }
        });
    });
    if let Some((_, email, key)) = share.confirm.clone() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!(
                "Para dar el control a {email}, comprueba antes su huella:"
            ))
            .color(p.warning),
        );
        ui.label(
            RichText::new(key.fingerprint())
                .font(FontId::monospace(13.0))
                .color(p.text),
        );
        ui.label(RichText::new(FINGERPRINT_HELP).size(12.0).color(p.muted));
        ui.horizontal(|ui| {
            if ui::primary_button(ui, "Coincide, dar el control").clicked() {
                action = Some(BarAction::Confirm);
            }
            if ui::secondary_button(ui, "Cancelar").clicked() {
                share.confirm = None;
            }
        });
    }
    let mut kick = None;
    let mut revoke = None;
    let mut ignore = None;
    for (conn, viewer) in &share.viewers {
        ui.horizontal(|ui| {
            ui.add_space(22.0);
            ui.label(RichText::new(&viewer.email).size(12.5));
            let requesting = share.requests.contains(conn);
            if viewer.control {
                ui::chip(ui, "con el control", p.accent);
            } else if requesting {
                ui::chip(ui, "pide el control", p.warning);
            }
            let looking_up = share.looking_up == Some(*conn);
            if looking_up {
                ui.spinner();
            } else if viewer.control {
                if ui::secondary_button(ui, "Quitar el control").clicked() {
                    revoke = Some(*conn);
                }
            } else {
                let label = if requesting {
                    "Dar el control"
                } else {
                    "Dar el control…"
                };
                if ui::secondary_button(ui, label).clicked() {
                    action = Some(BarAction::Grant(*conn));
                }
                if requesting && ui::secondary_button(ui, "Ignorar").clicked() {
                    ignore = Some(*conn);
                }
            }
            if ui::icon_button(ui, icons::CLOSE, "Sacar de la sesión").clicked() {
                kick = Some(*conn);
            }
        });
    }
    if let Some(conn) = revoke {
        if let Some(viewer) = share.viewers.get_mut(&conn) {
            viewer.control = false;
        }
        share.host.revoke(conn);
    }
    if let Some(conn) = ignore {
        share.requests.retain(|c| *c != conn);
    }
    if let Some(conn) = kick {
        share.host.kick(conn);
        share.forget(conn);
    }
    action
}

fn viewer_bar(ui: &mut egui::Ui, watching: &mut Watching) {
    let p = ui::pal(ui);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(icons::EYE)
                .font(ui::icon_font(15.0))
                .color(p.accent),
        );
        ui.label(
            RichText::new(format!(
                "Sesión de {} en «{}»",
                watching.owner, watching.team_name
            ))
            .color(p.text),
        );
        if watching.control {
            ui::chip(ui, "Tienes el control", p.accent);
        } else {
            ui::chip(ui, "Solo lectura", p.muted);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if watching.control {
                return;
            }
            let label = if watching.requested {
                "Volver a pedir"
            } else {
                "Pedir el control"
            };
            if ui::secondary_button(ui, &ui::with_icon(icons::KEYBOARD, label)).clicked() {
                watching.viewer.request_control();
                watching.requested = true;
            }
            if watching.requested {
                ui.label(RichText::new("Control pedido").size(12.0).color(p.muted));
            }
        });
    });
    if let Some(fingerprint) = &watching.unverified {
        ui.label(
            RichText::new(format!(
                "No has comprobado la huella de {}: {fingerprint}. Compruébala antes de escribir \
                 nada delicado.",
                watching.owner
            ))
            .size(12.0)
            .color(p.warning),
        );
    }
}
