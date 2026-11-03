//! Botones de «Iniciar sesión con…» con el aspecto que piden Google y Microsoft: fondo
//! blanco, borde gris y su logotipo a la izquierda.

use super::icons;
use egui::{
    Align2, Color32, CornerRadius, FontId, Pos2, Rect, Response, Sense, Shape, Stroke, Ui, Vec2,
};
use std::f32::consts::PI;

const HEIGHT: f32 = 34.0;
const LOGO: f32 = 16.0;
const PADDING: f32 = 12.0;
/// Separación entre el logotipo y el texto.
const LOGO_GAP: f32 = 10.0;
const FONT_SIZE: f32 = 13.0;
const RADIUS: u8 = 4;

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

/// Colores del botón de cada marca.
struct Look {
    border: Color32,
    text: Color32,
}

const GOOGLE: Look = Look {
    border: hex(0x747775),
    text: hex(0x1f1f1f),
};
const MICROSOFT: Look = Look {
    border: hex(0x8c8c8c),
    text: hex(0x5e5e5e),
};
const GENERIC: Look = Look {
    border: hex(0x8c8c8c),
    text: hex(0x1f1f1f),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Brand {
    Google,
    Microsoft,
    Other,
}

fn brand(id: &str) -> Brand {
    match id {
        "google" => Brand::Google,
        "microsoft" => Brand::Microsoft,
        _ => Brand::Other,
    }
}

/// Texto del botón del proveedor `id` con nombre `name`.
pub fn sign_in_label(id: &str, name: &str) -> String {
    match brand(id) {
        Brand::Google => "Iniciar sesión con Google".into(),
        Brand::Microsoft => "Iniciar sesión con Microsoft".into(),
        Brand::Other => format!("Iniciar sesión con {name}"),
    }
}

/// Texto del botón para pasar una cuenta con contraseña al proveedor `id`.
pub fn link_label(id: &str, name: &str) -> String {
    match brand(id) {
        Brand::Google => "Pasar mi cuenta a Google".into(),
        Brand::Microsoft => "Pasar mi cuenta a Microsoft".into(),
        Brand::Other => format!("Pasar mi cuenta a {name}"),
    }
}

/// Puntos de un arco de la circunferencia de centro `center` y radio `radius`, entre dos
/// ángulos en grados medidos en el sentido de las agujas del reloj desde la derecha.
fn arc(center: Pos2, radius: f32, from: f32, to: f32) -> Vec<Pos2> {
    const STEPS: usize = 16;
    (0..=STEPS)
        .map(|i| {
            let degrees = from + (to - from) * i as f32 / STEPS as f32;
            let angle = degrees * PI / 180.0;
            center + Vec2::new(angle.cos(), angle.sin()) * radius
        })
        .collect()
}

/// La «G» de Google en cuatro colores.
fn google_logo(painter: &egui::Painter, rect: Rect) {
    let center = rect.center();
    let width = rect.width() * 0.2;
    let radius = rect.width() / 2.0 - width / 2.0;
    let segments = [
        (hex(0xea4335), -150.0, -42.0),
        (hex(0xfbbc05), 145.0, 210.0),
        (hex(0x34a853), 40.0, 145.0),
        (hex(0x4285f4), 0.0, 40.0),
    ];
    for (color, from, to) in segments {
        painter.add(Shape::line(
            arc(center, radius, from, to),
            Stroke::new(width, color),
        ));
    }
    let bar = Rect::from_min_max(
        Pos2::new(center.x - 0.5, center.y - width / 2.0),
        Pos2::new(rect.right(), center.y + width / 2.0),
    );
    painter.rect_filled(bar, CornerRadius::ZERO, hex(0x4285f4));
}

/// Los cuatro cuadrados de Microsoft.
fn microsoft_logo(painter: &egui::Painter, rect: Rect) {
    let gap = (rect.width() / 21.0).max(1.0);
    let side = (rect.width() - gap) / 2.0;
    let squares = [
        (0.0, 0.0, hex(0xf25022)),
        (1.0, 0.0, hex(0x7fba00)),
        (0.0, 1.0, hex(0x00a4ef)),
        (1.0, 1.0, hex(0xffb900)),
    ];
    for (col, row, color) in squares {
        let min = rect.min + Vec2::new(col * (side + gap), row * (side + gap));
        painter.rect_filled(
            Rect::from_min_size(min, Vec2::splat(side)),
            CornerRadius::ZERO,
            color,
        );
    }
}

/// Botón para iniciar sesión con el proveedor `id`, como los que muestran Google y
/// Microsoft en sus guías de marca.
pub fn sign_in_button(ui: &mut Ui, id: &str, name: &str) -> Response {
    button(ui, id, &sign_in_label(id, name))
}

/// Botón con el logotipo y los colores del proveedor `id` y el texto `label`.
pub fn button(ui: &mut Ui, id: &str, label: &str) -> Response {
    let brand = brand(id);
    let look = match brand {
        Brand::Google => GOOGLE,
        Brand::Microsoft => MICROSOFT,
        Brand::Other => GENERIC,
    };
    // El ancho se ajusta al texto, para que quepan varios botones en una línea.
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        FontId::proportional(FONT_SIZE),
        look.text,
    );
    let width = PADDING + LOGO + LOGO_GAP + galley.size().x + PADDING;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, HEIGHT), Sense::click());
    let painter = ui.painter();
    let fill = if response.hovered() {
        hex(0xf2f2f2)
    } else {
        Color32::WHITE
    };
    painter.rect(
        rect,
        CornerRadius::same(RADIUS),
        fill,
        Stroke::new(1.0, look.border),
        egui::StrokeKind::Inside,
    );
    let logo = Rect::from_min_size(
        Pos2::new(rect.left() + PADDING, rect.center().y - LOGO / 2.0),
        Vec2::splat(LOGO),
    );
    match brand {
        Brand::Google => google_logo(painter, logo),
        Brand::Microsoft => microsoft_logo(painter, logo),
        Brand::Other => {
            painter.text(
                logo.center(),
                Align2::CENTER_CENTER,
                icons::IDENTITY,
                super::icon_font(LOGO),
                look.text,
            );
        }
    }
    let text_pos = Pos2::new(
        logo.right() + LOGO_GAP,
        rect.center().y - galley.size().y / 2.0,
    );
    painter.galley(text_pos, galley, look.text);
    super::describe(&response, egui::Role::Button, label);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_providers_use_their_brand_names() {
        assert_eq!(
            sign_in_label("google", "Google"),
            "Iniciar sesión con Google"
        );
        assert_eq!(
            sign_in_label("microsoft", "Microsoft 365"),
            "Iniciar sesión con Microsoft"
        );
        assert_eq!(
            sign_in_label("oidc", "Keycloak"),
            "Iniciar sesión con Keycloak"
        );
    }

    #[test]
    fn arcs_start_and_end_on_the_circle() {
        let points = arc(Pos2::ZERO, 10.0, 0.0, 90.0);
        assert!((points[0] - Pos2::new(10.0, 0.0)).length() < 1e-4);
        assert!((*points.last().unwrap() - Pos2::new(0.0, 10.0)).length() < 1e-4);
    }
}
