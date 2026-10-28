//! Widget de terminal: dibuja la pantalla del emulador y traduce teclado, ratón y portapapeles.

use crate::session::TerminalSession;
use egui::{Align2, Color32, CornerRadius, EventFilter, FontId, Pos2, Rect, Sense, Stroke, Vec2};
use tunel_term::keys::{self, Key, Modifiers};
use tunel_term::palette::{Rgb, Theme};
use tunel_term::{CursorKind, Screen, ScreenCell};

const PADDING: f32 = 12.0;
const SCROLL_POINTS_PER_LINE: f32 = 18.0;

fn c32(rgb: Rgb) -> Color32 {
    Color32::from_rgb(rgb.r, rgb.g, rgb.b)
}

/// Medidas de una celda con la fuente monoespaciada actual.
#[derive(Debug, Clone, Copy)]
pub struct CellMetrics {
    pub width: f32,
    pub height: f32,
}

pub fn metrics(ctx: &egui::Context, font: &FontId) -> CellMetrics {
    ctx.fonts_mut(|f| CellMetrics {
        width: f.glyph_width(font, 'M').max(1.0),
        height: f.row_height(font).max(1.0),
    })
}

/// Columnas y filas que caben en un rectángulo.
pub fn grid_size(rect: Rect, m: CellMetrics) -> (u16, u16) {
    let cols = ((rect.width() - 2.0 * PADDING) / m.width)
        .floor()
        .clamp(2.0, 1000.0) as u16;
    let rows = ((rect.height() - 2.0 * PADDING) / m.height)
        .floor()
        .clamp(1.0, 500.0) as u16;
    (cols, rows)
}

fn map_key(key: egui::Key) -> Option<Key> {
    use egui::Key as K;
    Some(match key {
        K::Enter => Key::Enter,
        K::Tab => Key::Tab,
        K::Backspace => Key::Backspace,
        K::Escape => Key::Escape,
        K::ArrowUp => Key::Up,
        K::ArrowDown => Key::Down,
        K::ArrowLeft => Key::Left,
        K::ArrowRight => Key::Right,
        K::Home => Key::Home,
        K::End => Key::End,
        K::PageUp => Key::PageUp,
        K::PageDown => Key::PageDown,
        K::Insert => Key::Insert,
        K::Delete => Key::Delete,
        K::F1 => Key::F(1),
        K::F2 => Key::F(2),
        K::F3 => Key::F(3),
        K::F4 => Key::F(4),
        K::F5 => Key::F(5),
        K::F6 => Key::F(6),
        K::F7 => Key::F(7),
        K::F8 => Key::F(8),
        K::F9 => Key::F(9),
        K::F10 => Key::F(10),
        K::F11 => Key::F(11),
        K::F12 => Key::F(12),
        other => {
            // Letras, números y símbolos: solo como combinación con Ctrl (el texto llega por Event::Text).
            let name = other.symbol_or_name();
            let mut chars = name.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            Key::Char(c.to_ascii_lowercase())
        }
    })
}

/// Atajos de la aplicación que no deben llegar al programa remoto.
fn is_app_shortcut(m: &egui::Modifiers) -> bool {
    m.command && !m.ctrl || (cfg!(not(target_os = "macos")) && m.ctrl && m.shift)
}

fn handle_input(ui: &egui::Ui, session: &mut TerminalSession) {
    let modes = session.emulator.input_modes();
    let events = ui.input(|i| i.events.clone());
    let mut output = Vec::new();
    for event in events {
        match event {
            egui::Event::Text(text) => output.extend(text.into_bytes()),
            egui::Event::Paste(text) => output.extend(keys::encode_paste(&text, modes)),
            egui::Event::Copy | egui::Event::Cut => {
                if let Some(text) = session.emulator.selection_text() {
                    ui.ctx().copy_text(text);
                }
            }
            egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } => {
                if is_app_shortcut(&modifiers) {
                    continue;
                }
                let Some(mapped) = map_key(key) else { continue };
                // Las teclas imprimibles sin Ctrl ya llegan como texto.
                if matches!(mapped, Key::Char(_)) && !modifiers.ctrl {
                    continue;
                }
                let mods = Modifiers {
                    shift: modifiers.shift,
                    ctrl: modifiers.ctrl,
                    alt: modifiers.alt,
                };
                if let Some(bytes) = keys::encode(mapped, mods, modes) {
                    output.extend(bytes);
                }
            }
            _ => {}
        }
    }
    if !output.is_empty() {
        session.emulator.scroll_to_bottom();
        session.emulator.clear_selection();
        session.send(output);
    }
}

fn cell_at(rect: Rect, m: CellMetrics, pos: Pos2, screen: &Screen) -> (usize, usize) {
    let col = ((pos.x - rect.min.x - PADDING) / m.width).floor().max(0.0) as usize;
    let row = ((pos.y - rect.min.y - PADDING) / m.height).floor().max(0.0) as usize;
    (
        row.min(screen.rows.saturating_sub(1)),
        col.min(screen.cols.saturating_sub(1)),
    )
}

fn same_style(a: &ScreenCell, b: &ScreenCell) -> bool {
    a.fg == b.fg && a.bold == b.bold && a.italic == b.italic && !a.wide && !b.wide
}

fn paint(
    painter: &egui::Painter,
    rect: Rect,
    m: CellMetrics,
    font: &FontId,
    screen: &Screen,
    focused: bool,
) {
    painter.rect_filled(rect, CornerRadius::ZERO, c32(screen.background));
    let origin = rect.min + Vec2::splat(PADDING);
    let selection = c32(screen.selection_color);
    for row in 0..screen.rows {
        let y = origin.y + row as f32 * m.height;
        // Fondos.
        for col in 0..screen.cols {
            let cell = screen.cell(row, col);
            let bg = if cell.selected {
                selection
            } else {
                c32(cell.bg)
            };
            if bg != c32(screen.background) {
                let width = if cell.wide { 2.0 } else { 1.0 } * m.width;
                let r = Rect::from_min_size(
                    Pos2::new(origin.x + col as f32 * m.width, y),
                    Vec2::new(width, m.height),
                );
                painter.rect_filled(r, CornerRadius::ZERO, bg);
            }
        }
        // Texto agrupado en tramos con el mismo estilo.
        let mut col = 0;
        while col < screen.cols {
            let start = col;
            let first = *screen.cell(row, col);
            let mut text = String::new();
            while col < screen.cols {
                let cell = screen.cell(row, col);
                if col > start && !same_style(&first, cell) {
                    break;
                }
                if !cell.spacer {
                    text.push(if cell.ch == '\0' { ' ' } else { cell.ch });
                }
                col += 1;
                if first.wide {
                    break;
                }
            }
            let x = origin.x + start as f32 * m.width;
            if !text.trim().is_empty() {
                painter.text(
                    Pos2::new(x, y),
                    Align2::LEFT_TOP,
                    &text,
                    font.clone(),
                    c32(first.fg),
                );
                if first.bold {
                    // Negrita simulada: segunda pasada desplazada medio píxel.
                    painter.text(
                        Pos2::new(x + 0.5, y),
                        Align2::LEFT_TOP,
                        &text,
                        font.clone(),
                        c32(first.fg),
                    );
                }
            }
            for (offset, cell) in (start..col).map(|c| (c, screen.cell(row, c))) {
                if cell.underline || cell.strikeout {
                    let cx = origin.x + offset as f32 * m.width;
                    let line_y = if cell.underline {
                        y + m.height - 1.5
                    } else {
                        y + m.height / 2.0
                    };
                    painter.line_segment(
                        [Pos2::new(cx, line_y), Pos2::new(cx + m.width, line_y)],
                        Stroke::new(1.0, c32(cell.fg)),
                    );
                }
            }
        }
    }
    if let Some((row, col)) = screen.cursor {
        paint_cursor(painter, origin, m, font, screen, row, col, focused);
    }
}

/// Grosor de la barra y del subrayado del cursor, en puntos.
const CURSOR_LINE: f32 = 2.0;

#[allow(clippy::too_many_arguments)]
fn paint_cursor(
    painter: &egui::Painter,
    origin: Pos2,
    m: CellMetrics,
    font: &FontId,
    screen: &Screen,
    row: usize,
    col: usize,
    focused: bool,
) {
    let cell = screen.cell(row, col);
    let width = if cell.wide { 2.0 * m.width } else { m.width };
    let r = Rect::from_min_size(
        Pos2::new(
            origin.x + col as f32 * m.width,
            origin.y + row as f32 * m.height,
        ),
        Vec2::new(width, m.height),
    );
    let color = c32(screen.cursor_color);
    let shape = if focused {
        screen.cursor_shape
    } else {
        CursorKind::Hollow
    };
    match shape {
        CursorKind::Block => {
            painter.rect_filled(r, CornerRadius::ZERO, color);
            if !cell.ch.is_whitespace() {
                // El carácter bajo el cursor se redibuja con el fondo para que siga legible.
                painter.text(
                    r.min,
                    Align2::LEFT_TOP,
                    cell.ch,
                    font.clone(),
                    c32(screen.background),
                );
            }
        }
        CursorKind::Bar => {
            painter.rect_filled(
                Rect::from_min_size(r.min, Vec2::new(CURSOR_LINE, m.height)),
                CornerRadius::ZERO,
                color,
            );
        }
        CursorKind::Underline => {
            let line = Rect::from_min_size(
                Pos2::new(r.left(), r.bottom() - CURSOR_LINE),
                Vec2::new(width, CURSOR_LINE),
            );
            painter.rect_filled(line, CornerRadius::ZERO, color);
        }
        CursorKind::Hollow => {
            painter.rect_stroke(
                r,
                CornerRadius::ZERO,
                Stroke::new(1.0, color),
                egui::StrokeKind::Inside,
            );
        }
    }
}

/// Caracteres del texto pedido que se enseñan en el aviso del portapapeles.
const CLIPBOARD_PREVIEW_CHARS: usize = 60;

/// Pide permiso antes de que la salida remota (OSC 52) escriba en el portapapeles.
fn clipboard_banner(ui: &mut egui::Ui, session: &mut TerminalSession) {
    let Some(text) = session.clipboard_request() else {
        return;
    };
    let chars = text.chars().count();
    let mut preview: String = text
        .chars()
        .take(CLIPBOARD_PREVIEW_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if chars > CLIPBOARD_PREVIEW_CHARS {
        preview.push('…');
    }
    let p = crate::ui::pal(ui);
    let mut answer = None;
    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "El servidor quiere copiar {chars} caracteres al portapapeles:"
                    ))
                    .color(p.muted),
                );
                ui.label(egui::RichText::new(preview).monospace());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::ui::secondary_button(ui, "Ignorar").clicked() {
                        answer = Some(false);
                    }
                    if crate::ui::primary_button(ui, "Copiar").clicked() {
                        answer = Some(true);
                    }
                });
            });
        });
    if let Some(text) = answer.and_then(|allow| session.answer_clipboard(allow)) {
        ui.ctx().copy_text(text);
    }
}

/// Muestra la terminal ocupando el espacio disponible.
pub fn show(
    ui: &mut egui::Ui,
    session: &mut TerminalSession,
    theme: &Theme,
    settings: &tunel_core::Settings,
) {
    let copy_on_select = settings.copy_on_select;
    session.emulator.set_cursor_style(settings.cursor_style);
    let font = FontId::monospace(settings.font_size);
    let m = metrics(ui.ctx(), &font);
    clipboard_banner(ui, session);
    let (rect, response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
    let (cols, rows) = grid_size(rect, m);
    session.resize(cols, rows);

    let id = response.id;
    if response.clicked() || response.drag_started() || std::mem::take(&mut session.wants_focus) {
        response.request_focus();
    }
    let focused = response.has_focus();
    if focused {
        ui.memory_mut(|mem| {
            mem.set_focus_lock_filter(
                id,
                EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            )
        });
        handle_input(ui, session);
    }

    let screen = session.emulator.screen(theme);
    if response.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta().y);
        let lines = (scroll / SCROLL_POINTS_PER_LINE).round() as i32;
        if lines != 0 && !session.emulator.input_modes().alt_screen {
            session.emulator.scroll(lines);
        }
    }
    if let Some(pos) = response.interact_pointer_pos() {
        let (row, col) = cell_at(rect, m, pos, &screen);
        if response.double_clicked() {
            session.emulator.start_selection(row, col, true);
            session.emulator.update_selection(row, col);
        } else if response.drag_started() {
            session.emulator.start_selection(row, col, false);
        } else if response.dragged() {
            session.emulator.update_selection(row, col);
        }
    }
    if response.drag_stopped()
        && copy_on_select
        && let Some(text) = session.emulator.selection_text()
    {
        ui.ctx().copy_text(text);
    }
    let screen = session.emulator.screen(theme);
    paint(ui.painter(), rect, m, &font, &screen, focused);
    if screen.scrolled_back {
        ui.painter().text(
            rect.right_top() + Vec2::new(-PADDING, PADDING),
            Align2::RIGHT_TOP,
            "↑ historial",
            FontId::proportional(11.0),
            c32(tunel_term::palette::rgb(theme.cursor)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_size_fits_cells_inside_padding() {
        let m = CellMetrics {
            width: 10.0,
            height: 20.0,
        };
        let rect = Rect::from_min_size(
            Pos2::ZERO,
            Vec2::new(800.0 + 2.0 * PADDING, 400.0 + 2.0 * PADDING),
        );
        assert_eq!(grid_size(rect, m), (80, 20));
    }

    #[test]
    fn grid_size_never_goes_below_minimum() {
        let m = CellMetrics {
            width: 10.0,
            height: 20.0,
        };
        assert_eq!(
            grid_size(Rect::from_min_size(Pos2::ZERO, Vec2::new(1.0, 1.0)), m),
            (2, 1)
        );
    }

    #[test]
    fn letters_map_to_lowercase_chars_for_ctrl_combos() {
        assert_eq!(map_key(egui::Key::C), Some(Key::Char('c')));
        assert_eq!(map_key(egui::Key::ArrowUp), Some(Key::Up));
        assert_eq!(map_key(egui::Key::F12), Some(Key::F(12)));
    }
}
