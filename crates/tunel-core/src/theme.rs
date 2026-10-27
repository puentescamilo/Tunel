//! Esquemas de color de la terminal que se guardan en la bóveda (los importados por el usuario).

use serde::{Deserialize, Serialize};

pub type Rgb = [u8; 3];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalTheme {
    /// Identificador estable; los temas importados usan el prefijo `usuario:`.
    pub id: String,
    pub name: String,
    pub foreground: Rgb,
    pub background: Rgb,
    pub cursor: Rgb,
    pub selection: Rgb,
    /// Colores ANSI 0–15: normales y brillantes.
    pub ansi: [Rgb; 16],
}

pub const CUSTOM_PREFIX: &str = "usuario:";
pub const WCAG_AA_TEXT: f64 = 4.5;

fn relative_luminance([r, g, b]: Rgb) -> f64 {
    let channel = |v: u8| {
        let v = f64::from(v) / 255.0;
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

/// Relación de contraste WCAG entre dos colores (1–21).
pub fn contrast(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

impl TerminalTheme {
    pub fn is_dark(&self) -> bool {
        relative_luminance(self.background) < 0.18
    }

    /// `true` si el texto normal no alcanza el contraste 4.5:1 de WCAG AA sobre el fondo.
    pub fn has_low_contrast(&self) -> bool {
        contrast(self.foreground, self.background) < WCAG_AA_TEXT
    }

    pub fn is_custom(&self) -> bool {
        self.id.starts_with(CUSTOM_PREFIX)
    }

    /// Identificador para un tema importado, derivado de su nombre.
    pub fn custom_id(name: &str) -> String {
        let slug: String = name
            .trim()
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect();
        let slug = slug
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        format!(
            "{CUSTOM_PREFIX}{}",
            if slug.is_empty() { "tema".into() } else { slug }
        )
    }
}

/// Modo de color de la interfaz (independiente del tema de la terminal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiThemeMode {
    /// Oscura o clara según el fondo del tema de la terminal.
    #[default]
    Auto,
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorStyle {
    #[default]
    Block,
    Bar,
    Underline,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn theme(background: Rgb) -> TerminalTheme {
        TerminalTheme {
            id: "x".into(),
            name: "x".into(),
            foreground: [255; 3],
            background,
            cursor: [255; 3],
            selection: [80; 3],
            ansi: [[0; 3]; 16],
        }
    }

    #[test]
    fn dark_and_light_backgrounds_are_detected() {
        assert!(theme([0x28, 0x2a, 0x36]).is_dark());
        assert!(!theme([0xfd, 0xf6, 0xe3]).is_dark());
    }

    #[test]
    fn contrast_matches_wcag_extremes() {
        assert!((contrast([0; 3], [255; 3]) - 21.0).abs() < 0.01);
        assert!((contrast([10; 3], [10; 3]) - 1.0).abs() < 0.01);
    }

    #[test]
    fn custom_ids_are_slugs_with_prefix() {
        assert_eq!(
            TerminalTheme::custom_id("Mi Tema  Favorito!"),
            "usuario:mi-tema-favorito"
        );
        assert_eq!(TerminalTheme::custom_id("  "), "usuario:tema");
        assert!(theme([0; 3]).id == "x" && !theme([0; 3]).is_custom());
    }
}
