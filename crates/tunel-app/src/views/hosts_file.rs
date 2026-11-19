//! El archivo hosts de este equipo, como texto: resalta direcciones, nombres y comentarios,
//! avisa de las líneas que el sistema no entiende y guarda con permisos de administrador.

use crate::app::TunelApp;
use crate::biometric::Pending;
use crate::hosts_file::{self as file, HostsFileEditor};
use crate::ui::{self, icons};
use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId, RichText};
use std::path::PathBuf;
use tunel_core::hosts_file::{line_parts, problems};

const FONT_SIZE: f32 = 13.0;
/// Cuántos avisos se listan; el resto se resume.
const MAX_PROBLEMS_SHOWN: usize = 5;

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(backups) = app.vault.as_ref().map(|v| file::backup_dir(v.path())) else {
        return;
    };
    finish_saving(app, &backups);
    if app.hosts_file.saved.is_none() && app.hosts_file.load_error.is_none() {
        app.hosts_file.load(&backups);
    }
    let p = ui::pal(ui);
    let editor = &mut app.hosts_file;
    let saving = editor.saving.is_some();
    let path = editor.path.display().to_string();
    let subtitle = format!(
        "{path}. Al guardar se pide la contraseña de administrador, se guarda antes una copia y se vacía la caché DNS."
    );
    ui::page_header(ui, "Archivo hosts", &subtitle, |ui| {
        let copies = format!("Copias ({})", editor.backups.len());
        if ui::secondary_button(ui, &copies).clicked() {
            editor.show_backups = !editor.show_backups;
        }
        let reload = ui
            .add_enabled_ui(!editor.is_modified() && !saving, |ui| {
                ui::secondary_button(ui, "Recargar")
            })
            .inner
            .on_disabled_hover_text("Guarda o descarta antes los cambios");
        if reload.clicked() {
            editor.load(&backups);
        }
    });
    if let Some(error) = &editor.load_error {
        ui::empty_state(
            ui,
            icons::FILE_TEXT,
            "No se pudo abrir el archivo hosts",
            error,
        );
        return;
    }
    if editor.show_backups {
        backups_panel(ui, editor);
    }
    problems_panel(ui, &editor.text, p.warning);
    let save = actions(ui, editor, saving, p.muted);
    text_editor(ui, editor, saving, &p);
    if save {
        start_saving(app, ui.ctx(), backups);
    }
}

fn backups_panel(ui: &mut egui::Ui, editor: &mut HostsFileEditor) {
    let p = ui::pal(ui);
    ui.add_space(6.0);
    if editor.backups.is_empty() {
        ui.label(
            RichText::new("Aún no hay copias: se hace una cada vez que guardas.").color(p.muted),
        );
        return;
    }
    ui.label(
        RichText::new("Al cargar una copia, su contenido pasa al editor; se aplica al guardar.")
            .color(p.muted),
    );
    let mut chosen = None;
    egui::ScrollArea::vertical()
        .id_salt("copias-hosts")
        .max_height(140.0)
        .show(ui, |ui| {
            for backup in &editor.backups {
                ui.horizontal(|ui| {
                    ui.label(backup.date.format("%Y-%m-%d %H:%M:%S").to_string());
                    if ui::secondary_button(ui, "Cargar en el editor").clicked() {
                        chosen = Some(backup.path.clone());
                    }
                });
            }
        });
    if let Some(path) = chosen {
        match std::fs::read(&path) {
            Ok(bytes) => {
                editor.text = tunel_core::hosts_file::HostsText::from_bytes(&bytes).text;
                editor.show_backups = false;
            }
            Err(e) => {
                ui.label(RichText::new(format!("No se pudo leer la copia: {e}")).color(p.danger));
            }
        }
    }
}

fn problems_panel(ui: &mut egui::Ui, text: &str, color: Color32) {
    let found = problems(text);
    if found.is_empty() {
        return;
    }
    ui.add_space(6.0);
    for problem in found.iter().take(MAX_PROBLEMS_SHOWN) {
        ui.label(
            RichText::new(format!("Línea {}: {}", problem.line, problem.message)).color(color),
        );
    }
    if found.len() > MAX_PROBLEMS_SHOWN {
        ui.label(
            RichText::new(format!(
                "…y {} líneas más. El sistema ignora las líneas que no entiende.",
                found.len() - MAX_PROBLEMS_SHOWN
            ))
            .color(color),
        );
    } else {
        ui.label(RichText::new("El sistema ignora las líneas que no entiende.").color(color));
    }
}

/// Descartar y Guardar. Devuelve si se pidió guardar.
fn actions(ui: &mut egui::Ui, editor: &mut HostsFileEditor, saving: bool, muted: Color32) -> bool {
    let modified = editor.is_modified();
    let mut save = false;
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if saving {
            ui.spinner();
            ui.label(RichText::new("Esperando el permiso de administrador…").color(muted));
        } else if modified {
            ui.label(RichText::new("Cambios sin guardar").color(muted));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let enabled = modified && !saving;
            save = ui
                .add_enabled_ui(enabled, |ui| ui::primary_button(ui, "Guardar…"))
                .inner
                .clicked();
            let discard = ui
                .add_enabled_ui(enabled, |ui| ui::secondary_button(ui, "Descartar"))
                .inner;
            if discard.clicked() {
                editor.discard();
            }
        });
    });
    ui.add_space(4.0);
    save
}

fn text_editor(ui: &mut egui::Ui, editor: &mut HostsFileEditor, saving: bool, p: &ui::Palette) {
    let colors = Colors {
        text: p.text,
        address: p.accent,
        comment: p.muted,
    };
    let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, wrap_width: f32| {
        let mut job = highlight(text.as_str(), colors);
        job.wrap.max_width = wrap_width;
        ui.fonts_mut(|f| f.layout_job(job))
    };
    egui::ScrollArea::vertical()
        .id_salt("archivo-hosts")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let response = ui.add_enabled(
                !saving,
                egui::TextEdit::multiline(&mut editor.text)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .desired_rows(24)
                    .layouter(&mut layouter),
            );
            ui::describe(
                &response,
                egui::Role::MultilineTextInput,
                "Contenido del archivo hosts",
            );
        });
}

#[derive(Clone, Copy)]
struct Colors {
    text: Color32,
    address: Color32,
    comment: Color32,
}

/// Dirección en el color de acento, nombres en el normal y comentarios apagados.
fn highlight(text: &str, colors: Colors) -> LayoutJob {
    let font = FontId::monospace(FONT_SIZE);
    let format = |color| TextFormat::simple(font.clone(), color);
    let mut job = LayoutJob::default();
    for line in text.split_inclusive('\n') {
        let parts = line_parts(line);
        let mut marks: Vec<(std::ops::Range<usize>, Color32)> = Vec::new();
        if let Some(address) = parts.address {
            marks.push((address, colors.address));
        }
        if let Some(comment) = parts.comment {
            marks.push((comment, colors.comment));
        }
        marks.sort_by_key(|(range, _)| range.start);
        let mut at = 0;
        for (range, color) in marks {
            job.append(&line[at..range.start], 0.0, format(colors.text));
            job.append(&line[range.clone()], 0.0, format(color));
            at = range.end;
        }
        job.append(&line[at..], 0.0, format(colors.text));
    }
    job
}

fn finish_saving(app: &mut TunelApp, backups: &std::path::Path) {
    let Some(result) = app.hosts_file.saving.as_ref().and_then(Pending::take) else {
        return;
    };
    app.hosts_file.saving = None;
    match result {
        Some(Ok(saved)) => {
            let editor = &mut app.hosts_file;
            editor.text = saved.text.clone();
            editor.saved = Some(saved);
            editor.backups = file::list_backups(backups);
            app.notify("Archivo hosts guardado. Se guardó una copia del anterior.");
        }
        Some(Err(error)) => app.notify(error),
        None => app.notify("Se interrumpió el guardado del archivo hosts"),
    }
}

fn start_saving(app: &mut TunelApp, ctx: &egui::Context, backups: PathBuf) {
    let editor = &mut app.hosts_file;
    let Some(text) = editor.to_save() else {
        return;
    };
    let target = editor.path.clone();
    editor.saving = Some(crate::biometric::run(ctx, move || {
        file::save(&target, &text, &backups, chrono::Local::now().naive_local())
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLORS: Colors = Colors {
        text: Color32::WHITE,
        address: Color32::RED,
        comment: Color32::GRAY,
    };

    fn colored(job: &LayoutJob) -> Vec<(String, Color32)> {
        job.sections
            .iter()
            .filter(|s| !s.byte_range.is_empty())
            .map(|s| {
                let range = s.byte_range.start.0..s.byte_range.end.0;
                (job.text[range].to_string(), s.format.color)
            })
            .collect()
    }

    #[test]
    fn addresses_and_comments_are_highlighted() {
        let job = highlight("10.0.0.1 web # nota\n# todo\n", COLORS);

        assert_eq!(job.text, "10.0.0.1 web # nota\n# todo\n");
        assert_eq!(
            colored(&job),
            [
                ("10.0.0.1".to_string(), Color32::RED),
                (" web ".to_string(), Color32::WHITE),
                ("# nota\n".to_string(), Color32::GRAY),
                ("# todo\n".to_string(), Color32::GRAY),
            ]
        );
    }
}
