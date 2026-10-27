//! Claves de servidor en las que se confía.

use crate::app::TunelApp;
use crate::ui::{self, icons};
use egui::{Rect, RichText, Sense, Vec2};

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let p = ui::pal(ui);
    ui::page_header(
        ui,
        "Known hosts",
        "Huellas de servidores en los que confías. Si una cambia, Túnel te avisará antes de conectar.",
        |_| {},
    );
    let mut forget = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if data.known_hosts.is_empty() {
                ui::empty_state(
                    ui,
                    icons::SHIELD,
                    "Aún no hay servidores de confianza",
                    "Se añaden al aceptar la huella la primera vez que te conectas.",
                );
            }
            for entry in &data.known_hosts {
                ui::list_row(ui, (&entry.host, entry.port), |ui| {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
                        ui::avatar(
                            ui,
                            Rect::from_min_size(rect.min, rect.size()),
                            icons::FINGERPRINT,
                            p.accent,
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("{}:{}", entry.host, entry.port))
                                        .strong(),
                                );
                                ui::chip(ui, &entry.algorithm, p.muted);
                            });
                            ui.label(
                                RichText::new(&entry.fingerprint)
                                    .monospace()
                                    .size(12.0)
                                    .color(p.muted),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui::secondary_button(ui, "Olvidar")
                                .on_hover_text(
                                    "Volverá a pedir confirmación en la próxima conexión",
                                )
                                .clicked()
                            {
                                forget = Some((entry.host.clone(), entry.port));
                            }
                            if ui::icon_button(ui, icons::COPY, "Copiar huella").clicked() {
                                ui.ctx().copy_text(entry.fingerprint.clone());
                            }
                        });
                    });
                });
                ui.add_space(2.0);
            }
        });
    if let Some((host, port)) = forget {
        app.commit(data.forget_host_key(&host, port));
    }
}
