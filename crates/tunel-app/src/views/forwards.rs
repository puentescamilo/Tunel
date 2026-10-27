//! Reglas de reenvío de puertos y su estado.

use crate::app::TunelApp;
use crate::editor::Editor;
use crate::ui::{self, icons};
use egui::{Rect, RichText, Sense, Vec2};
use tunel_core::{ForwardKind, PortForward};
use tunel_ssh::forward::is_loopback;

fn kind_label(kind: ForwardKind) -> &'static str {
    match kind {
        ForwardKind::Local => "Local",
        ForwardKind::Remote => "Remoto",
        ForwardKind::Dynamic => "SOCKS5",
    }
}

/// Aviso cuando la regla acepta conexiones de otros equipos de la red.
pub fn exposure_warning(rule: &PortForward) -> Option<&'static str> {
    if is_loopback(&rule.bind_address) {
        return None;
    }
    Some(match rule.kind {
        ForwardKind::Dynamic => {
            "Escucha en la red y el proxy SOCKS5 no pide contraseña: cualquiera que lo alcance podrá usar tu servidor."
        }
        ForwardKind::Local => "Escucha en la red: otros equipos podrán usar este túnel.",
        ForwardKind::Remote => {
            "El servidor escuchará en todas sus interfaces si su GatewayPorts lo permite."
        }
    })
}

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let p = ui::pal(ui);
    let first_host = data.hosts.first().map(|h| h.id);
    ui::page_header(
        ui,
        "Túneles",
        "Reenvío de puertos local, remoto y proxy SOCKS5",
        |ui| {
            ui.add_enabled_ui(first_host.is_some(), |ui| {
                if ui::primary_button(ui, &ui::with_icon(icons::PLUS, "Regla")).clicked()
                    && let Some(host) = first_host
                {
                    app.editor = Some(Editor::forward(PortForward::local(
                        host,
                        8080,
                        "localhost",
                        80,
                    )));
                }
            });
        },
    );
    let mut start = None;
    let mut stop = None;
    let mut delete = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if data.forwards.is_empty() {
                ui::empty_state(
                    ui,
                    icons::TUNNEL,
                    "Sin túneles",
                    "Crea una regla para llevar un puerto de un servidor a tu equipo o al revés.",
                );
            }
            for rule in &data.forwards {
                let running = app.forwards.contains_key(&rule.id);
                let host = data
                    .host(rule.host)
                    .map(|h| h.display_name())
                    .unwrap_or("host eliminado");
                ui::list_row(ui, rule.id, |ui| {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
                        let color = if running { p.success } else { p.muted };
                        ui::avatar(
                            ui,
                            Rect::from_min_size(rect.min, rect.size()),
                            icons::TUNNEL,
                            color,
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.horizontal(|ui| {
                                let title = if rule.label.is_empty() {
                                    rule.describe()
                                } else {
                                    rule.label.clone()
                                };
                                ui.label(RichText::new(title).strong());
                                ui::chip(ui, kind_label(rule.kind), p.accent);
                                if running {
                                    ui::chip(ui, "activo", p.success);
                                }
                            });
                            ui.label(
                                RichText::new(format!("{} · vía {host}", rule.describe()))
                                    .size(12.0)
                                    .color(p.muted),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui::icon_button(ui, icons::TRASH, "Eliminar").clicked() {
                                delete = Some(rule.id);
                            }
                            if ui::icon_button(ui, icons::PENCIL, "Editar").clicked() {
                                app.editor = Some(Editor::forward(rule.clone()));
                            }
                            if running {
                                if ui::secondary_button(ui, &ui::with_icon(icons::STOP, "Detener"))
                                    .clicked()
                                {
                                    stop = Some(rule.id);
                                }
                            } else if ui::primary_button(ui, &ui::with_icon(icons::PLAY, "Iniciar"))
                                .clicked()
                            {
                                start = Some(rule.clone());
                            }
                        });
                    });
                    if let Some(error) = app.forward_errors.get(&rule.id) {
                        ui.label(
                            RichText::new(format!("{}  {error}", icons::WARNING))
                                .size(12.0)
                                .color(p.danger),
                        );
                    }
                    if let Some(warning) = exposure_warning(rule) {
                        ui.label(
                            RichText::new(format!("{}  {warning}", icons::WARNING))
                                .size(12.0)
                                .color(p.warning),
                        );
                    }
                });
                ui.add_space(2.0);
            }
        });
    if let Some(rule) = start
        && let Err(e) = app.engine.start_forward(&data, rule)
    {
        app.notify(format!("No se pudo iniciar el túnel: {e:#}"));
    }
    if let Some(active) = stop.and_then(|id| app.forwards.remove(&id)) {
        app.engine.stop_forward(active);
    }
    if let Some(id) = delete {
        if let Some(active) = app.forwards.remove(&id) {
            app.engine.stop_forward(active);
        }
        app.commit(data.without_forward(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::HostId;

    #[test]
    fn warns_only_when_listening_beyond_loopback() {
        let rule = PortForward::local(HostId::new(), 8080, "localhost", 80);
        assert_eq!(exposure_warning(&rule), None);
        let exposed = PortForward {
            bind_address: "0.0.0.0".into(),
            kind: ForwardKind::Dynamic,
            ..rule
        };
        assert!(exposure_warning(&exposed).unwrap().contains("SOCKS5"));
    }
}
