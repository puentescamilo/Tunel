//! Elegir el icono de un grupo entre los de Phosphor, buscándolo por su nombre en inglés.

use crate::ui::{self, icon_catalog, icons};
use egui::{RichText, Vec2};

/// Cuántos iconos se muestran a la vez; con más, se pide afinar la búsqueda.
const MAX_SHOWN: usize = 240;
const CELL: f32 = 34.0;

/// `icon` es el nombre del icono elegido; `None` es la carpeta de siempre.
pub fn icon_picker(ui: &mut egui::Ui, icon: &mut Option<String>) {
    let p = ui::pal(ui);
    let current: Option<&'static str> = icon
        .as_deref()
        .and_then(icon_catalog::find)
        .map(|(n, _)| *n);
    let label = ui
        .horizontal(|ui| {
            let label = ui.label("Icono");
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.0), egui::Sense::hover());
            let glyph = current.and_then(icon_catalog::glyph).map(String::from);
            ui::avatar(
                ui,
                rect,
                glyph.as_deref().unwrap_or(icons::FOLDER),
                p.accent,
            );
            ui.label(RichText::new(current.unwrap_or(icon_catalog::DEFAULT)).color(p.muted));
            if current.is_some() && ui.button("Volver a la carpeta").clicked() {
                *icon = None;
            }
            label
        })
        .inner;

    let id = egui::Id::unique("buscar-icono-grupo");
    let mut query = ui.data(|d| d.get_temp::<String>(id).unwrap_or_default());
    ui.add(
        egui::TextEdit::singleline(&mut query)
            .hint_text("Buscar en inglés: server, database, cloud…")
            .desired_width(f32::INFINITY),
    )
    .labelled_by(label.id);

    let matches = icon_catalog::search(&query);
    egui::ScrollArea::vertical()
        .id_salt("iconos")
        .max_height(CELL * 4.5)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::splat(4.0);
                for (name, glyph) in matches.iter().take(MAX_SHOWN) {
                    let selected = current.unwrap_or(icon_catalog::DEFAULT) == *name;
                    let button = egui::Button::new(
                        RichText::new(glyph.to_string()).font(ui::icon_font(18.0)),
                    )
                    .selected(selected)
                    .min_size(Vec2::splat(CELL));
                    let response = ui.add(button);
                    // El nombre, no el carácter del icono, que un lector de pantalla no sabe leer.
                    ui::describe_selected(&response, egui::Role::Button, selected, name);
                    if response.on_hover_text(*name).clicked() {
                        *icon = (*name != icon_catalog::DEFAULT).then(|| name.to_string());
                    }
                }
            });
        });
    let hidden = matches.len().saturating_sub(MAX_SHOWN);
    let note = match (matches.len(), hidden) {
        _ if query.trim().is_empty() => Some(format!(
            "Escribe para buscar entre los {} de phosphoricons.com",
            icon_catalog::ICONS.len()
        )),
        (0, _) => Some("Ningún icono se llama así".to_string()),
        (_, 0) => None,
        (_, n) => Some(format!("y {n} más: afina la búsqueda")),
    };
    if let Some(note) = note {
        ui.label(RichText::new(note).size(12.0).color(p.muted));
    }
    ui.data_mut(|d| d.insert_temp(id, query));
}
