//! Elegir las fuentes de la terminal y de la interfaz, e importar otras de Google Fonts.

use crate::fonts::{FontState, MAX_FAMILY_CHARS, TERMINAL_FONTS, UI_FONTS};
use crate::ui::{self, icons};
use egui::RichText;

const SYSTEM: &str = "Del sistema";

/// Desplegable con «Del sistema», las sugeridas y las importadas; debajo, si la elegida se
/// está descargando o falló.
fn picker(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut Option<String>,
    suggested: &[&str],
    custom: &[String],
    state: &FontState,
) {
    let p = ui::pal(ui);
    let selected = value.clone().unwrap_or_else(|| SYSTEM.to_string());
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt(id)
            .selected_text(&selected)
            .width(200.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(value, None, SYSTEM);
                ui.separator();
                for family in suggested {
                    ui.selectable_value(value, Some(family.to_string()), *family);
                }
                if !custom.is_empty() {
                    ui.separator();
                    for family in custom {
                        ui.selectable_value(value, Some(family.clone()), family);
                    }
                }
            });
        if let Some(family) = value.as_deref() {
            if state.is_pending(family) {
                ui.spinner();
                ui.label(RichText::new("descargando…").size(12.0).color(p.muted));
            } else if let Some(error) = state.failed.get(family) {
                ui.label(
                    RichText::new(icons::WARNING)
                        .font(ui::icon_font(14.0))
                        .color(p.warning),
                )
                .on_hover_text(error);
            }
        }
    });
}

/// Filas de fuentes de la tarjeta «Apariencia».
pub fn rows(ui: &mut egui::Ui, settings: &mut tunel_core::Settings, state: &FontState) {
    let custom = settings.custom_fonts.clone();
    super::settings::setting_row(
        ui,
        "Fuente de la terminal",
        "Se descarga de Google Fonts la primera vez",
        |ui| {
            picker(
                ui,
                "fuente-terminal",
                &mut settings.terminal_font,
                TERMINAL_FONTS,
                &custom,
                state,
            )
        },
    );
    super::settings::setting_row(ui, "Fuente de la interfaz", "", |ui| {
        picker(
            ui,
            "fuente-interfaz",
            &mut settings.ui_font,
            UI_FONTS,
            &custom,
            state,
        )
    });
}

/// Importar una familia escribiendo su nombre de Google Fonts. Si ya estaba descargada,
/// se añade en el acto a `settings`.
pub fn import_row(
    app: &mut crate::app::TunelApp,
    ui: &mut egui::Ui,
    settings: &mut tunel_core::Settings,
) {
    let p = ui::pal(ui);
    let id = egui::Id::unique("importar-fuente");
    let mut text = ui.data(|d| d.get_temp::<String>(id).unwrap_or_default());
    let mut import = false;
    ui.horizontal(|ui| {
        let edit = ui.add(
            egui::TextEdit::singleline(&mut text)
                .hint_text("Otra familia, p. ej. Fira Sans")
                .char_limit(MAX_FAMILY_CHARS)
                .desired_width(300.0),
        );
        let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        let busy = app.fonts.importing().is_some();
        let clicked = ui
            .add_enabled_ui(!busy && !text.trim().is_empty(), |ui| {
                ui::secondary_button(ui, &ui::with_icon(icons::DOWNLOAD, "Importar"))
            })
            .inner
            .clicked();
        import = (clicked || enter) && !busy && !text.trim().is_empty();
        if let Some(family) = app.fonts.importing() {
            ui.spinner();
            ui.label(
                RichText::new(format!("descargando «{family}»…"))
                    .size(12.0)
                    .color(p.muted),
            );
        }
    });
    ui.label(
        RichText::new(
            "Busca la familia en fonts.google.com y escribe su nombre tal cual. Queda disponible \
             en los dos desplegables.",
        )
        .size(12.0)
        .color(p.muted),
    );
    if import {
        match crate::fonts::import(app, &text) {
            Ok(ready) => {
                text.clear();
                if let Some(family) = ready {
                    crate::fonts::remember(settings, &family);
                    app.notify(format!(
                        "«{family}» ya está disponible en las listas de fuentes"
                    ));
                }
            }
            Err(e) => app.notify(format!("No se puede importar: {e}")),
        }
    }
    if !app.fonts.failed.is_empty()
        && ui
            .small_button("Reintentar las descargas fallidas")
            .clicked()
    {
        crate::fonts::retry(app);
    }
    ui.data_mut(|d| d.insert_temp(id, text));
}
