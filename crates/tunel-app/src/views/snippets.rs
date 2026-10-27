//! Snippets: comandos guardados que se envían a una o a todas las terminales.

use crate::app::{Tab, TunelApp};
use crate::editor::Editor;
use crate::ui::{self, icons};
use egui::{CornerRadius, RichText};
use tunel_core::Snippet;

const PREVIEW_LINES: usize = 4;

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let p = ui::pal(ui);
    ui::page_header(
        ui,
        "Snippets",
        "Comandos guardados para enviar a una terminal o a todas a la vez",
        |ui| {
            if ui::primary_button(ui, &ui::with_icon(icons::PLUS, "Snippet")).clicked() {
                app.editor = Some(Editor::Snippet(Snippet::new("Nuevo snippet", "")));
            }
        },
    );
    let terminals = app
        .tabs
        .iter()
        .filter(|t| matches!(t, Tab::Terminal(t) if t.is_alive()))
        .count();
    let mut run = None;
    let mut delete = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if data.snippets.is_empty() {
                ui::empty_state(
                    ui,
                    icons::CODE,
                    "Sin snippets",
                    "Guarda comandos que repites a menudo y ejecútalos con un clic.",
                );
            }
            for snippet in &data.snippets {
                ui::list_row(ui, snippet.id, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(icons::CODE)
                                .font(ui::icon_font(16.0))
                                .color(p.accent),
                        );
                        ui.label(RichText::new(&snippet.label).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui::icon_button(ui, icons::TRASH, "Eliminar").clicked() {
                                delete = Some(snippet.id);
                            }
                            if ui::icon_button(ui, icons::PENCIL, "Editar").clicked() {
                                app.editor = Some(Editor::Snippet(snippet.clone()));
                            }
                            ui.add_enabled_ui(terminals > 0, |ui| {
                                let all = ui::secondary_button(
                                    ui,
                                    &ui::with_icon(icons::BROADCAST, "En todas"),
                                )
                                .on_hover_text(format!(
                                    "Enviar a las {terminals} terminales abiertas"
                                ))
                                .on_disabled_hover_text("Abre una terminal primero");
                                if all.clicked() {
                                    run = Some((snippet.script.clone(), true));
                                }
                                let one =
                                    ui::primary_button(ui, &ui::with_icon(icons::PLAY, "Ejecutar"))
                                        .on_hover_text("Enviar a la última terminal activa")
                                        .on_disabled_hover_text("Abre una terminal primero");
                                if one.clicked() {
                                    run = Some((snippet.script.clone(), false));
                                }
                            });
                        });
                    });
                    let preview: Vec<&str> = snippet.script.lines().take(PREVIEW_LINES).collect();
                    let more = snippet.script.lines().count().saturating_sub(PREVIEW_LINES);
                    egui::Frame::new()
                        .fill(ui.visuals().extreme_bg_color)
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(preview.join("\n")).monospace().color(p.text));
                            if more > 0 {
                                ui.label(
                                    RichText::new(format!("… {more} líneas más"))
                                        .size(11.0)
                                        .color(p.muted),
                                );
                            }
                        });
                });
                ui.add_space(2.0);
            }
        });
    if let Some((script, all)) = run {
        let script = if script.ends_with('\n') {
            script
        } else {
            format!("{script}\n")
        };
        // Desde esta sección no hay pestaña activa: usar la última terminal abierta.
        if app.active.is_none() {
            app.active = app.tabs.iter().rposition(|t| matches!(t, Tab::Terminal(_)));
        }
        app.send_to_terminals(&script, all);
    }
    if let Some(id) = delete {
        app.commit(data.without_snippet(id));
    }
}
