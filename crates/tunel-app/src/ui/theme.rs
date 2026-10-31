//! Tokens de diseño (colores, radios, espaciado) y su aplicación al estilo de egui.

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow, Stroke,
    TextStyle, Vec2,
};
use std::sync::Arc;

pub const RADIUS: u8 = 8;
pub const RADIUS_SMALL: u8 = 6;
pub const ICON_FONT: &str = "phosphor";
const PHOSPHOR: &[u8] = include_bytes!("../../assets/fonts/Phosphor.ttf");

/// Paleta de la interfaz. La terminal tiene su propio tema (`tunel_term::palette`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub dark: bool,
    /// Fondo de la ventana y de la zona de contenido.
    pub bg: Color32,
    /// Menú lateral y barra de pestañas.
    pub sidebar: Color32,
    /// Tarjetas, campos y ventanas.
    pub surface: Color32,
    pub surface_hover: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_text: Color32,
    pub accent_soft: Color32,
    pub danger: Color32,
    pub warning: Color32,
    pub success: Color32,
}

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

pub const DARK: Palette = Palette {
    dark: true,
    bg: hex(0x0f1218),
    sidebar: hex(0x13171e),
    surface: hex(0x1a1f29),
    surface_hover: hex(0x232a37),
    border: hex(0x29303d),
    text: hex(0xe6eaf2),
    muted: hex(0x8a93a6),
    accent: hex(0x3dd6b0),
    accent_text: hex(0x07261f),
    accent_soft: Color32::from_rgba_premultiplied(0x0f, 0x36, 0x2e, 0xff),
    danger: hex(0xf2667a),
    warning: hex(0xf5b94e),
    success: hex(0x5ad38c),
};

pub const LIGHT: Palette = Palette {
    dark: false,
    bg: hex(0xf6f7f9),
    sidebar: hex(0xeceff3),
    surface: hex(0xffffff),
    surface_hover: hex(0xf0f2f6),
    border: hex(0xdfe3ea),
    text: hex(0x1b2130),
    muted: hex(0x667085),
    accent: hex(0x0b7f65),
    accent_text: hex(0xffffff),
    accent_soft: hex(0xd9f3ec),
    danger: hex(0xd9364d),
    warning: hex(0xb7791f),
    success: hex(0x1f9d55),
};

/// Colores de avatar para distinguir hosts de un vistazo (se elige por el nombre).
const AVATAR_COLORS: [u32; 8] = [
    0x3dd6b0, 0x5b9cff, 0xb17cff, 0xff8a5b, 0xf5b94e, 0xff6f9f, 0x4fc3f7, 0x9ccc65,
];

pub fn avatar_color(seed: &str) -> Color32 {
    let hash = seed
        .bytes()
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)));
    hex(AVATAR_COLORS[(hash as usize) % AVATAR_COLORS.len()])
}

fn palette_id() -> egui::Id {
    egui::Id::unique("tunel-paleta")
}

/// Paleta activa (la guarda `apply`).
pub fn palette(ctx: &egui::Context) -> Palette {
    ctx.data(|d| d.get_temp(palette_id())).unwrap_or(DARK)
}

/// Paleta de la interfaz para el modo elegido; en automático sigue al fondo de la terminal.
pub fn for_mode(mode: tunel_core::theme::UiThemeMode, terminal_is_dark: bool) -> Palette {
    use tunel_core::theme::UiThemeMode;
    match mode {
        UiThemeMode::Dark => DARK,
        UiThemeMode::Light => LIGHT,
        UiThemeMode::Auto if terminal_is_dark => DARK,
        UiThemeMode::Auto => LIGHT,
    }
}

fn widget(fill: Color32, stroke: Color32, text: Color32) -> egui::style::WidgetVisuals {
    egui::style::WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: fill,
        bg_stroke: Stroke::new(1.0, stroke),
        fg_stroke: Stroke::new(1.0, text),
        corner_radius: CornerRadius::same(RADIUS_SMALL),
        expansion: 0.0,
    }
}

fn visuals(p: Palette) -> egui::Visuals {
    let mut v = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(12);
    v.menu_corner_radius = CornerRadius::same(RADIUS);
    v.extreme_bg_color = if p.dark { hex(0x0b0e13) } else { hex(0xffffff) };
    v.text_edit_bg_color = Some(if p.dark { hex(0x10141b) } else { hex(0xffffff) });
    v.faint_bg_color = p.surface;
    v.code_bg_color = p.surface_hover;
    v.override_text_color = Some(p.text);
    v.weak_text_color = Some(p.muted);
    v.hyperlink_color = p.accent;
    v.warn_fg_color = p.warning;
    v.error_fg_color = p.danger;
    v.selection.bg_fill = p.accent.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, p.accent);
    let shadow_alpha = if p.dark { 110 } else { 40 };
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 28,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };
    v.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };
    v.widgets.noninteractive = widget(p.surface, p.border, p.text);
    v.widgets.inactive = widget(p.surface_hover, Color32::TRANSPARENT, p.text);
    v.widgets.hovered = widget(p.surface_hover, p.border, p.text);
    v.widgets.active = widget(p.accent_soft, p.accent, p.text);
    v.widgets.open = widget(p.surface_hover, p.border, p.text);
    v.collapsing_header_frame = false;
    v.indent_has_left_vline = false;
    v.striped = true;
    v.slider_trailing_fill = true;
    v
}

/// Aplica tipografía, espaciado y colores a todo el contexto.
pub fn apply(ctx: &egui::Context, p: Palette) {
    let theme = if p.dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    ctx.set_theme(theme);
    ctx.style_mut_of(theme, |style| {
        style.visuals = visuals(p);
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.interact_size.y = 28.0;
        style.spacing.window_margin = Margin::same(20);
        style.spacing.menu_margin = Margin::same(6);
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(22.0)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into();
    });
    ctx.data_mut(|d| d.insert_temp(palette_id(), p));
}

/// Fuentes del sistema que se prueban en orden (no se redistribuyen: se leen del equipo).
const UI_FONTS: &[&str] = &[
    "/System/Library/Fonts/SFNS.ttf",
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "/usr/share/fonts/truetype/inter/Inter-Regular.ttf",
    "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
];
const MONO_FONTS: &[&str] = &[
    "/System/Applications/Utilities/Terminal.app/Contents/Resources/Fonts/SF-Mono-Regular.otf",
    "/System/Library/Fonts/SFNSMono.ttf",
    "C:\\Windows\\Fonts\\CascadiaMono.ttf",
    "C:\\Windows\\Fonts\\consola.ttf",
    "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
];

fn first_readable(paths: &[&str]) -> Option<(String, Vec<u8>)> {
    paths
        .iter()
        .find_map(|p| std::fs::read(p).ok().map(|bytes| (p.to_string(), bytes)))
}

/// Pone `name` con los datos `bytes` la primera de `family`.
fn prefer(fonts: &mut FontDefinitions, family: FontFamily, name: &str, bytes: Vec<u8>) {
    fonts
        .font_data
        .insert(name.into(), Arc::new(FontData::from_owned(bytes)));
    fonts
        .families
        .entry(family)
        .or_default()
        .insert(0, name.into());
}

/// Instala las fuentes: las elegidas en Ajustes (`ui` y `mono`, con su familia), o si no
/// las del sistema, más los iconos. Las del sistema y las de egui quedan detrás como
/// respaldo para los glifos que no tenga la elegida.
pub fn install_fonts(
    ctx: &egui::Context,
    ui: Option<(String, Vec<u8>)>,
    mono: Option<(String, Vec<u8>)>,
) {
    let mut fonts = FontDefinitions::default();
    fonts
        .font_data
        .insert(ICON_FONT.into(), Arc::new(FontData::from_static(PHOSPHOR)));
    if let Some((path, bytes)) = first_readable(UI_FONTS) {
        tracing::info!(path, "fuente de interfaz del sistema");
        prefer(&mut fonts, FontFamily::Proportional, "ui", bytes);
    }
    if let Some((path, bytes)) = first_readable(MONO_FONTS) {
        tracing::info!(path, "fuente monoespaciada del sistema");
        prefer(&mut fonts, FontFamily::Monospace, "mono", bytes);
    }
    if let Some((family, bytes)) = ui {
        tracing::info!(%family, "fuente de interfaz elegida");
        prefer(&mut fonts, FontFamily::Proportional, "ui-elegida", bytes);
    }
    if let Some((family, bytes)) = mono {
        tracing::info!(%family, "fuente de terminal elegida");
        prefer(&mut fonts, FontFamily::Monospace, "mono-elegida", bytes);
    }
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push(ICON_FONT.into());
    }
    fonts
        .families
        .insert(FontFamily::Name(ICON_FONT.into()), vec![ICON_FONT.into()]);
    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avatar_color_is_stable_per_name() {
        assert_eq!(avatar_color("web-01"), avatar_color("web-01"));
    }

    #[test]
    fn ui_mode_selects_palette() {
        use tunel_core::theme::UiThemeMode;
        assert!(for_mode(UiThemeMode::Auto, true).dark);
        assert!(!for_mode(UiThemeMode::Auto, false).dark);
        assert!(for_mode(UiThemeMode::Dark, false).dark);
        assert!(!for_mode(UiThemeMode::Light, true).dark);
    }

    #[test]
    fn text_has_enough_contrast_on_surfaces() {
        // Contraste WCAG AA (4.5:1) para texto normal y 3:1 para el texto secundario.
        for p in [DARK, LIGHT] {
            assert!(contrast(p.text, p.surface) >= 4.5, "texto/superficie");
            assert!(contrast(p.text, p.bg) >= 4.5, "texto/fondo");
            assert!(contrast(p.muted, p.surface) >= 3.0, "secundario/superficie");
            assert!(contrast(p.accent_text, p.accent) >= 4.5, "botón principal");
        }
    }

    fn luminance(c: Color32) -> f64 {
        let channel = |v: u8| {
            let v = f64::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
    }
}
