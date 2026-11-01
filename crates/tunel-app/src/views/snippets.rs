//! Snippets: comandos guardados que se envían a una o a todas las terminales.

use crate::app::{Tab, TunelApp};
use crate::editor::Editor;
use crate::ui::{self, icons};
use egui::{CornerRadius, RichText};
use std::collections::BTreeMap;
use tunel_core::Snippet;
use tunel_core::template;

const PREVIEW_LINES: usize = 4;

/// Un snippet con variables esperando a que se escriban sus valores.
pub struct SnippetPrompt {
    label: String,
    script: String,
    /// Enviar a todas las terminales.
    all: bool,
    /// Nombre y valor de cada variable, en el orden en que aparecen.
    fields: Vec<(String, String)>,
}

/// Ejecuta `snippet`: si tiene variables, primero pide sus valores.
pub fn run(app: &mut TunelApp, snippet: &Snippet, all: bool) {
    let names = template::variables(&snippet.script);
    if names.is_empty() {
        return send(app, &snippet.script, all);
    }
    let fields = names
        .into_iter()
        .map(|name| {
            let last = app.snippet_values.get(&name).cloned().unwrap_or_default();
            (name, last)
        })
        .collect();
    app.snippet_prompt = Some(SnippetPrompt {
        label: snippet.label.clone(),
        script: snippet.script.clone(),
        all,
        fields,
    });
}

fn send(app: &mut TunelApp, script: &str, all: bool) {
    let script = if script.ends_with('\n') {
        script.to_string()
    } else {
        format!("{script}\n")
    };
    // Desde esta sección no hay pestaña activa: usar la última terminal abierta.
    if app.active.is_none() {
        app.active = app.tabs.iter().rposition(|t| matches!(t, Tab::Terminal(_)));
    }
    app.send_to_terminals(&script, all);
}

/// Ventana para escribir los valores de las variables de un snippet. Recuerda el último
/// valor de cada variable mientras la bóveda está abierta.
pub fn prompt_dialog(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(prompt) = app.snippet_prompt.as_mut() else {
        return;
    };
    let p = ui::theme::palette(ctx);
    let frame = egui::Frame::popup(&ctx.global_style())
        .inner_margin(egui::Margin::same(20))
        .corner_radius(CornerRadius::same(14));
    let mut done = None;
    let modal = egui::Modal::new(egui::Id::unique("variables-snippet"))
        .frame(frame)
        .show(ctx, |ui| {
            ui.set_width(380.0);
            ui.label(RichText::new(&prompt.label).size(16.0).strong());
            let target = if prompt.all {
                "todas las terminales abiertas"
            } else {
                "la terminal activa"
            };
            ui.label(RichText::new(format!("Se enviará a {target}.")).color(p.muted));
            ui.add_space(10.0);
            let mut enter = false;
            for (i, (name, value)) in prompt.fields.iter_mut().enumerate() {
                ui.label(name.as_str());
                let field = ui.add(
                    egui::TextEdit::singleline(value)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                if i == 0 && !ui.memory(|m| m.focused().is_some()) {
                    field.request_focus();
                }
                enter |= field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(4.0);
            }
            // Las variables sin valor se ven tal cual en la vista previa.
            let values: BTreeMap<String, String> = prompt
                .fields
                .iter()
                .filter(|(_, v)| !v.trim().is_empty())
                .cloned()
                .collect();
            let preview = template::fill(&prompt.script, &values);
            ui.add_space(6.0);
            egui::Frame::new()
                .fill(ui.visuals().extreme_bg_color)
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let lines: Vec<&str> = preview.lines().take(PREVIEW_LINES).collect();
                    ui.label(RichText::new(lines.join("\n")).monospace().color(p.text));
                });
            let complete = prompt.fields.iter().all(|(_, v)| !v.trim().is_empty());
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let send = ui
                    .add_enabled_ui(complete, |ui| {
                        ui::primary_button(ui, &ui::with_icon(icons::PLAY, "Enviar"))
                    })
                    .inner
                    .on_disabled_hover_text("Escribe todos los valores");
                if send.clicked() || (enter && complete) {
                    done = Some(true);
                }
                if ui::secondary_button(ui, "Cancelar").clicked() {
                    done = Some(false);
                }
            });
        });
    if modal.should_close() {
        done.get_or_insert(false);
    }
    match done {
        Some(true) => {
            let Some(prompt) = app.snippet_prompt.take() else {
                return;
            };
            let values: BTreeMap<String, String> = prompt
                .fields
                .into_iter()
                .map(|(name, value)| (name, template::clean_value(&value)))
                .collect();
            app.snippet_values
                .extend(values.iter().map(|(k, v)| (k.clone(), v.clone())));
            send(app, &template::fill(&prompt.script, &values), prompt.all);
        }
        Some(false) => app.snippet_prompt = None,
        None => {}
    }
}

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
    let mut chosen = None;
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
                        let names = template::variables(&snippet.script);
                        if !names.is_empty() {
                            ui::chip(ui, &format!("pide {}", names.join(", ")), p.muted);
                        }
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
                                    chosen = Some((snippet.clone(), true));
                                }
                                let one =
                                    ui::primary_button(ui, &ui::with_icon(icons::PLAY, "Ejecutar"))
                                        .on_hover_text("Enviar a la última terminal activa")
                                        .on_disabled_hover_text("Abre una terminal primero");
                                if one.clicked() {
                                    chosen = Some((snippet.clone(), false));
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
    if let Some((snippet, all)) = chosen {
        run(app, &snippet, all);
    }
    if let Some(id) = delete {
        app.commit(data.without_snippet(id));
    }
}
