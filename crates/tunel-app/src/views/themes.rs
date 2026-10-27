//! Galería de temas de la terminal: vista previa, selección e importación.

use crate::app::TunelApp;
use crate::ui::{self, icons};
use egui::{Align2, Color32, CornerRadius, FontId, Rect, Sense, Stroke, Vec2};
use tunel_core::Settings;
use tunel_core::theme::{CursorStyle, UiThemeMode};
use tunel_term::palette::{self, Theme};

const CARD_WIDTH: f32 = 196.0;
const PREVIEW_HEIGHT: f32 = 92.0;
const CARD_HEIGHT: f32 = PREVIEW_HEIGHT + 30.0;
const GAP: f32 = 12.0;

fn c([r, g, b]: [u8; 3]) -> Color32 {
    Color32::from_rgb(r, g, b)
}

/// Mini terminal con prompt, salida coloreada y la paleta ANSI.
fn paint_preview(painter: &egui::Painter, rect: Rect, theme: &Theme) {
    painter.rect_filled(rect, CornerRadius::same(8), c(theme.background));
    let mono = FontId::monospace(11.0);
    let x = rect.left() + 10.0;
    let mut y = rect.top() + 9.0;
    let line_height = 15.0;
    let segment = |painter: &egui::Painter, x: &mut f32, y: f32, text: &str, color: Color32| {
        let galley = painter.layout_no_wrap(text.to_string(), mono.clone(), color);
        let width = galley.size().x;
        painter.galley(egui::pos2(*x, y), galley, color);
        *x += width;
    };
    let mut cx = x;
    segment(painter, &mut cx, y, "ana@web", c(theme.ansi[2]));
    segment(painter, &mut cx, y, ":", c(theme.foreground));
    segment(painter, &mut cx, y, "~", c(theme.ansi[4]));
    segment(painter, &mut cx, y, "$ ls -l", c(theme.foreground));
    let cursor = Rect::from_min_size(egui::pos2(cx + 3.0, y), Vec2::new(6.0, 12.0));
    painter.rect_filled(cursor, CornerRadius::ZERO, c(theme.cursor));
    y += line_height;
    let mut cx = x;
    segment(painter, &mut cx, y, "app/ ", c(theme.ansi[12]));
    segment(painter, &mut cx, y, "run.sh ", c(theme.ansi[10]));
    segment(painter, &mut cx, y, "log", c(theme.foreground));
    y += line_height;
    let mut cx = x;
    segment(painter, &mut cx, y, "error: ", c(theme.ansi[1]));
    segment(painter, &mut cx, y, "aviso", c(theme.ansi[3]));
    y += line_height + 6.0;
    for (i, color) in theme.ansi[..8].iter().chain(&theme.ansi[8..]).enumerate() {
        let col = (i % 8) as f32;
        let row = (i / 8) as f32;
        let dot = Rect::from_min_size(
            egui::pos2(x + col * 14.0, y + row * 9.0),
            Vec2::new(11.0, 6.0),
        );
        painter.rect_filled(dot, CornerRadius::same(2), c(*color));
    }
}

/// Tarjeta seleccionable de un tema. Devuelve (seleccionar, eliminar).
fn theme_card(ui: &mut egui::Ui, theme: &Theme, selected: bool) -> (bool, bool) {
    let p = ui::pal(ui);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), CARD_HEIGHT), Sense::click());
    let preview = Rect::from_min_size(rect.min, Vec2::new(rect.width(), PREVIEW_HEIGHT));
    paint_preview(ui.painter(), preview, theme);
    let (border, width) = if selected {
        (p.accent, 2.0)
    } else if response.hovered() {
        (p.muted, 1.0)
    } else {
        (p.border, 1.0)
    };
    ui.painter().rect_stroke(
        preview,
        CornerRadius::same(8),
        Stroke::new(width, border),
        egui::StrokeKind::Outside,
    );
    let label_y = preview.bottom() + 15.0;
    let mut name_x = rect.left() + 2.0;
    if selected {
        ui.painter().text(
            egui::pos2(name_x, label_y),
            Align2::LEFT_CENTER,
            icons::CHECK,
            ui::icon_font(13.0),
            p.accent,
        );
        name_x += 18.0;
    }
    ui.painter().text(
        egui::pos2(name_x, label_y),
        Align2::LEFT_CENTER,
        &theme.name,
        FontId::proportional(13.0),
        if selected { p.text } else { p.muted },
    );
    let mut delete = false;
    if theme.is_custom() && response.hovered() {
        let button = Rect::from_center_size(
            egui::pos2(preview.right() - 14.0, preview.top() + 14.0),
            Vec2::splat(22.0),
        );
        let r = ui.interact(button, response.id.with("borrar"), Sense::click());
        ui.painter().rect_filled(
            button,
            CornerRadius::same(5),
            Color32::from_black_alpha(160),
        );
        ui.painter().text(
            button.center(),
            Align2::CENTER_CENTER,
            icons::TRASH,
            ui::icon_font(12.0),
            Color32::WHITE,
        );
        delete = r.on_hover_text("Eliminar tema importado").clicked();
    }
    let badge = if theme.has_low_contrast() {
        Some(("bajo contraste", p.warning))
    } else if theme.is_custom() {
        Some(("importado", p.accent))
    } else {
        None
    };
    if let Some((text, color)) = badge {
        let galley = ui
            .painter()
            .layout_no_wrap(text.into(), FontId::proportional(10.5), color);
        let size = galley.size() + Vec2::new(10.0, 4.0);
        let chip = Rect::from_min_size(
            egui::pos2(rect.right() - size.x, label_y - size.y / 2.0),
            size,
        );
        ui.painter()
            .rect_filled(chip, CornerRadius::same(8), color.gamma_multiply(0.16));
        ui.painter()
            .galley(chip.center() - galley.size() / 2.0, galley, color);
    }
    let tooltip = if theme.has_low_contrast() {
        "El texto no llega al contraste 4.5:1 recomendado (WCAG AA)"
    } else {
        "Usar este tema"
    };
    let clicked = response
        .on_hover_text(tooltip)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked();
    (clicked && !delete, delete)
}

fn segmented<T: Copy + PartialEq>(ui: &mut egui::Ui, value: &mut T, options: &[(T, &str, &str)]) {
    let p = ui::pal(ui);
    egui::Frame::new()
        .fill(p.surface_hover)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(3))
        .show(ui, |ui| {
            // En contenedores alineados a la derecha egui coloca de derecha a izquierda:
            // se recorren al revés para que siempre se lean en el orden declarado.
            let reversed = ui.layout().prefer_right_to_left();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                let ordered: Vec<&(T, &str, &str)> = if reversed {
                    options.iter().rev().collect()
                } else {
                    options.iter().collect()
                };
                for (option, icon, label) in ordered {
                    let selected = *value == *option;
                    let text = egui::RichText::new(ui::with_icon(icon, label)).color(if selected {
                        p.text
                    } else {
                        p.muted
                    });
                    let button = egui::Button::new(text)
                        .fill(if selected {
                            p.surface
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(Stroke::NONE)
                        .corner_radius(CornerRadius::same(6))
                        .min_size(Vec2::new(0.0, 26.0));
                    if ui.add(button).clicked() {
                        *value = *option;
                    }
                }
            });
        });
}

pub fn ui_mode_selector(ui: &mut egui::Ui, mode: &mut UiThemeMode) {
    segmented(
        ui,
        mode,
        &[
            (UiThemeMode::Auto, icons::CIRCLE_HALF, "Automático"),
            (UiThemeMode::Dark, icons::MOON, "Oscuro"),
            (UiThemeMode::Light, icons::SUN, "Claro"),
        ],
    );
}

pub fn cursor_selector(ui: &mut egui::Ui, style: &mut CursorStyle) {
    segmented(
        ui,
        style,
        &[
            (CursorStyle::Block, icons::CURSOR_BLOCK, "Bloque"),
            (CursorStyle::Bar, icons::CURSOR_BAR, "Barra"),
            (CursorStyle::Underline, icons::CURSOR_UNDERLINE, "Subrayado"),
        ],
    );
}

/// Galería con todos los temas; modifica `settings` al elegir o eliminar uno.
pub fn gallery(ui: &mut egui::Ui, settings: &mut Settings) {
    let themes: Vec<Theme> = settings
        .custom_themes
        .iter()
        .chain(palette::builtin())
        .cloned()
        .collect();
    let cols = ((ui.available_width() + GAP) / (CARD_WIDTH + GAP))
        .floor()
        .max(1.0) as usize;
    let width = (ui.available_width() - GAP * (cols as f32 - 1.0)) / cols as f32;
    let mut delete = None;
    for row in themes.chunks(cols) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            for theme in row {
                ui.allocate_ui(Vec2::new(width, CARD_HEIGHT), |ui| {
                    let (select, remove) = theme_card(ui, theme, settings.theme == theme.id);
                    if select {
                        settings.theme = theme.id.clone();
                    }
                    if remove {
                        delete = Some(theme.id.clone());
                    }
                });
            }
        });
        ui.add_space(GAP - ui.spacing().item_spacing.y);
    }
    if let Some(id) = delete {
        settings.custom_themes.retain(|t| t.id != id);
        if settings.theme == id {
            settings.theme = palette::DEFAULT_ID.into();
        }
    }
}

/// Añade temas importados, sustituyendo los que tengan el mismo id; devuelve los nuevos ajustes.
pub fn merge_imported(settings: &Settings, imported: Vec<Theme>) -> Settings {
    let first = imported.first().map(|t| t.id.clone());
    let mut custom: Vec<Theme> = settings
        .custom_themes
        .iter()
        .filter(|t| !imported.iter().any(|i| i.id == t.id))
        .cloned()
        .collect();
    custom.extend(imported);
    Settings {
        custom_themes: custom,
        theme: first.unwrap_or_else(|| settings.theme.clone()),
        ..settings.clone()
    }
}

/// Pide un archivo de tema al usuario y lo importa a la bóveda.
pub fn import_dialog(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Importar tema de terminal")
        .add_filter("Temas (iTerm2, Windows Terminal)", &["itermcolors", "json"])
        .pick_file()
    else {
        return;
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let result = std::fs::metadata(&path)
        .map_err(|e| e.to_string())
        .and_then(|meta| {
            if meta.len() > tunel_term::theme_import::MAX_FILE_BYTES as u64 {
                Err(tunel_term::theme_import::ImportError::TooLarge.to_string())
            } else {
                std::fs::read(&path).map_err(|e| e.to_string())
            }
        })
        .and_then(|bytes| {
            tunel_term::theme_import::import(&name, &bytes).map_err(|e| e.to_string())
        });
    let Some(data) = app.data().cloned() else {
        return;
    };
    match result {
        Ok(themes) => {
            let names: Vec<String> = themes.iter().map(|t| t.name.clone()).collect();
            app.commit(data.with_settings(merge_imported(&data.settings, themes)));
            app.apply_theme(ctx);
            app.notify(format!("Tema importado: {}", names.join(", ")));
        }
        Err(e) => app.notify(format!("No se pudo importar {name}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(name: &str) -> Theme {
        Theme {
            id: Theme::custom_id(name),
            name: name.into(),
            ..palette::default_theme().clone()
        }
    }

    #[test]
    fn importing_selects_first_theme_and_replaces_same_id() {
        let settings = Settings {
            custom_themes: vec![custom("Viejo"), custom("Mio")],
            ..Settings::default()
        };
        let mut updated_mio = custom("Mio");
        updated_mio.background = [1, 2, 3];
        let merged = merge_imported(&settings, vec![updated_mio]);
        assert_eq!(merged.theme, "usuario:mio");
        assert_eq!(merged.custom_themes.len(), 2);
        assert_eq!(
            merged
                .custom_themes
                .iter()
                .find(|t| t.id == "usuario:mio")
                .unwrap()
                .background,
            [1, 2, 3]
        );
    }

    #[test]
    fn importing_nothing_keeps_current_theme() {
        let settings = Settings {
            theme: "nord".into(),
            ..Settings::default()
        };
        assert_eq!(merge_imported(&settings, vec![]).theme, "nord");
    }
}
