//! Componentes visuales reutilizables construidos sobre egui.

use super::theme::{self, Palette, RADIUS, RADIUS_SMALL};
use egui::{
    Align2, Color32, CornerRadius, FontFamily, FontId, Rect, Response, RichText, Sense, Stroke, Ui,
    Vec2,
};

pub fn icon_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(theme::ICON_FONT.into()))
}

pub fn pal(ui: &Ui) -> Palette {
    theme::palette(ui.ctx())
}

/// Texto con un icono delante, para botones y etiquetas.
pub fn with_icon(icon: &str, text: &str) -> String {
    if text.is_empty() {
        icon.to_string()
    } else {
        format!("{icon}  {text}")
    }
}

/// Elemento del menú lateral con barra de acento cuando está seleccionado.
pub fn nav_item(
    ui: &mut Ui,
    icon: &str,
    label: &str,
    selected: bool,
    badge: Option<usize>,
) -> Response {
    let p = pal(ui);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::click());
    let painter = ui.painter();
    let fill = if selected {
        p.accent_soft
    } else if response.hovered() {
        p.surface_hover
    } else {
        Color32::TRANSPARENT
    };
    painter.rect_filled(rect, CornerRadius::same(RADIUS_SMALL), fill);
    if selected {
        let bar = Rect::from_min_size(
            rect.left_top() + Vec2::new(0.0, 8.0),
            Vec2::new(3.0, rect.height() - 16.0),
        );
        painter.rect_filled(bar, CornerRadius::same(2), p.accent);
    }
    let color = if selected { p.accent } else { p.muted };
    painter.text(
        rect.left_center() + Vec2::new(14.0, 0.0),
        Align2::LEFT_CENTER,
        icon,
        icon_font(17.0),
        color,
    );
    let text_color = if selected {
        p.text
    } else {
        p.text.gamma_multiply(0.85)
    };
    painter.text(
        rect.left_center() + Vec2::new(40.0, 0.0),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(14.0),
        text_color,
    );
    if let Some(count) = badge.filter(|c| *c > 0) {
        painter.text(
            rect.right_center() - Vec2::new(12.0, 0.0),
            Align2::RIGHT_CENTER,
            count.to_string(),
            FontId::proportional(12.0),
            p.muted,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Elemento del menú compacto (solo icono) con indicador de selección.
pub fn rail_item(ui: &mut Ui, icon: &str, tooltip: &str, selected: bool) -> Response {
    let p = pal(ui);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 40.0), Sense::click());
    let fill = if selected {
        p.accent_soft
    } else if response.hovered() {
        p.surface_hover
    } else {
        Color32::TRANSPARENT
    };
    let square = Rect::from_center_size(rect.center(), Vec2::splat(38.0));
    ui.painter()
        .rect_filled(square, CornerRadius::same(RADIUS), fill);
    let color = if selected { p.accent } else { p.muted };
    ui.painter().text(
        square.center(),
        Align2::CENTER_CENTER,
        icon,
        icon_font(19.0),
        color,
    );
    response
        .on_hover_text(tooltip)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Interruptor de encendido/apagado.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> Response {
    let p = pal(ui);
    let (rect, mut response) = ui.allocate_exact_size(Vec2::new(38.0, 22.0), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let t = ui.ctx().animate_bool_responsive(response.id, *on);
    let track = if *on { p.accent } else { p.border };
    ui.painter()
        .rect_filled(rect, CornerRadius::same(11), track);
    let x = egui::lerp(rect.left() + 11.0..=rect.right() - 11.0, t);
    let knob = if *on { p.accent_text } else { p.muted };
    ui.painter()
        .circle_filled(egui::pos2(x, rect.center().y), 8.0, knob);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Botón cuadrado solo con icono; el texto de ayuda aparece al pasar el ratón.
pub fn icon_button(ui: &mut Ui, icon: &str, tooltip: &str) -> Response {
    icon_button_colored(ui, icon, tooltip, None)
}

pub fn icon_button_colored(
    ui: &mut Ui,
    icon: &str,
    tooltip: &str,
    color: Option<Color32>,
) -> Response {
    let p = pal(ui);
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
    if response.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(RADIUS_SMALL), p.surface_hover);
    }
    let fg = color.unwrap_or(if response.hovered() { p.text } else { p.muted });
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        icon,
        icon_font(16.0),
        fg,
    );
    response
        .on_hover_text(tooltip)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Botón de ojo para mostrar u ocultar un dato; cambia `revealed` al pulsarlo.
pub fn reveal_button(ui: &mut Ui, revealed: &mut bool) -> Response {
    let (icon, tooltip) = if *revealed {
        (super::icons::EYE_SLASH, "Ocultar")
    } else {
        (super::icons::EYE, "Mostrar")
    };
    let response = icon_button(ui, icon, tooltip);
    if response.clicked() {
        *revealed = !*revealed;
    }
    response
}

/// Un dato que se muestra como puntos hasta que se pulsa el ojo.
pub fn masked(text: &str, revealed: bool) -> String {
    if revealed {
        text.to_string()
    } else {
        "••••••••••••".to_string()
    }
}

pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    let p = pal(ui);
    let button = egui::Button::new(RichText::new(text).color(p.accent_text).strong())
        .fill(p.accent)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(RADIUS_SMALL))
        .min_size(Vec2::new(0.0, 30.0));
    ui.add(button)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn secondary_button(ui: &mut Ui, text: &str) -> Response {
    secondary_button_sized(ui, text, 0.0)
}

pub fn secondary_button_sized(ui: &mut Ui, text: &str, width: f32) -> Response {
    let p = pal(ui);
    let button = egui::Button::new(RichText::new(text).color(p.text))
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(RADIUS_SMALL))
        .min_size(Vec2::new(width, 30.0));
    ui.add(button)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    let p = pal(ui);
    let button = egui::Button::new(RichText::new(text).color(p.danger))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, p.danger.gamma_multiply(0.6)))
        .corner_radius(CornerRadius::same(RADIUS_SMALL))
        .min_size(Vec2::new(0.0, 30.0));
    ui.add(button)
}

/// Campo de búsqueda con lupa que ocupa `width` (o todo el ancho si es infinito).
pub fn search_box(ui: &mut Ui, text: &mut String, hint: &str, width: f32) -> Response {
    let p = pal(ui);
    let width = width.min(ui.available_width());
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::symmetric(12, 6))
        .show(ui, |ui| {
            let row = Vec2::new(width - 26.0, 24.0);
            ui.allocate_ui_with_layout(
                row,
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_min_size(row);
                    ui.label(
                        RichText::new(super::icons::SEARCH)
                            .font(icon_font(15.0))
                            .color(p.muted),
                    );
                    ui.add(
                        egui::TextEdit::singleline(text)
                            .hint_text(hint)
                            .frame(egui::Frame::NONE)
                            .align(egui::Align2::LEFT_CENTER)
                            .desired_width(f32::INFINITY),
                    )
                },
            )
            .inner
        })
        .inner
}

/// Etiqueta pequeña con fondo suave.
pub fn chip(ui: &mut Ui, text: &str, color: Color32) -> Response {
    let font = FontId::proportional(11.5);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = galley.size() + Vec2::new(14.0, 6.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::same(10), color.gamma_multiply(0.16));
    ui.painter()
        .galley(rect.center() - galley.size() / 2.0, galley, color);
    response
}

/// Cuadrado redondeado con un icono, coloreado por host o grupo.
pub fn avatar(ui: &Ui, rect: Rect, icon: &str, color: Color32) {
    ui.painter()
        .rect_filled(rect, CornerRadius::same(RADIUS), color.gamma_multiply(0.18));
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        icon,
        icon_font(rect.height() * 0.5),
        color,
    );
}

pub fn status_dot(ui: &Ui, center: egui::Pos2, color: Color32) {
    ui.painter().circle_filled(center, 4.0, color);
}

/// Título de página, subtítulo opcional y acciones alineadas a la derecha.
pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str, actions: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).size(22.0).strong().color(p.text));
            if !subtitle.is_empty() {
                ui.label(RichText::new(subtitle).color(p.muted));
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
    });
    ui.add_space(10.0);
}

pub fn section_label(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add_space(6.0);
    ui.label(
        RichText::new(text.to_uppercase())
            .size(11.0)
            .strong()
            .color(p.muted),
    );
    ui.add_space(2.0);
}

/// Mensaje centrado para listas vacías, con una acción opcional.
pub fn empty_state(ui: &mut Ui, icon: &str, title: &str, body: &str) {
    let p = pal(ui);
    ui.vertical_centered(|ui| {
        ui.add_space(48.0);
        ui.label(
            RichText::new(icon)
                .font(icon_font(40.0))
                .color(p.muted.gamma_multiply(0.7)),
        );
        ui.add_space(8.0);
        ui.label(RichText::new(title).size(16.0).strong());
        ui.label(RichText::new(body).color(p.muted));
        ui.add_space(12.0);
    });
}

/// Marco de tarjeta; `highlight` resalta el borde (hover o selección).
pub fn card_frame(ui: &Ui, highlight: bool) -> egui::Frame {
    let p = pal(ui);
    egui::Frame::new()
        .fill(if highlight {
            p.surface_hover
        } else {
            p.surface
        })
        .stroke(Stroke::new(
            1.0,
            if highlight {
                p.accent.gamma_multiply(0.6)
            } else {
                p.border
            },
        ))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(12))
}

/// Fila de lista con fondo al pasar el ratón; devuelve la respuesta de toda la fila.
pub fn list_row<R>(
    ui: &mut Ui,
    key: impl std::hash::Hash + std::fmt::Debug,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> (Response, R) {
    let p = pal(ui);
    let id = ui.scope_id().with(("fila", key));
    let hovered = ui.ctx().read_response(id).is_some_and(|r| r.hovered());
    let inner = egui::Frame::new()
        .fill(if hovered { p.surface_hover } else { p.surface })
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        });
    let response = ui.interact(inner.response.rect, id, Sense::hover());
    (response, inner.inner)
}
