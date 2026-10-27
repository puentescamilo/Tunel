//! Temas de la terminal incluidos y resolución de colores ANSI a RGB.

pub use alacritty_terminal::vte::ansi::Rgb;
use alacritty_terminal::vte::ansi::{Color, NamedColor};
use std::sync::LazyLock;
pub use tunel_core::theme::TerminalTheme as Theme;

pub const DEFAULT_ID: &str = "tunel-oscuro";
pub const LIGHT_ID: &str = "tunel-claro";

/// (id, nombre, [primer plano, fondo, cursor, selección, ANSI 0–15]) en hexadecimal.
type Row = (&'static str, &'static str, [u32; 20]);

#[rustfmt::skip]
const BUILTIN_TABLE: &[Row] = &[
    ("tunel-oscuro", "Túnel Oscuro", [
        0xd8dee9, 0x0f1218, 0x5ed0b4, 0x3b4a63,
        0x1f242e, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xd8dee9,
        0x5c6370, 0xff7b86, 0xb5e890, 0xffd88a, 0x82c4ff, 0xdd95f0, 0x7fd6e0, 0xffffff]),
    ("tunel-claro", "Túnel Claro", [
        0x2b303b, 0xfafaf7, 0x108a70, 0xc8d8f0,
        0x2b303b, 0xc0392b, 0x2e8b57, 0xb58900, 0x265dc8, 0x8e44ad, 0x168f99, 0xd0d0d0,
        0x6b7280, 0xe74c3c, 0x3cb371, 0xd4a017, 0x3b82f6, 0xa85cd6, 0x1ab3c0, 0x111111]),
    ("dracula", "Dracula", [
        0xf8f8f2, 0x282a36, 0xf8f8f2, 0x44475a,
        0x21222c, 0xff5555, 0x50fa7b, 0xf1fa8c, 0xbd93f9, 0xff79c6, 0x8be9fd, 0xf8f8f2,
        0x6272a4, 0xff6e6e, 0x69ff94, 0xffffa5, 0xd6acff, 0xff92df, 0xa4ffff, 0xffffff]),
    ("nord", "Nord", [
        0xd8dee9, 0x2e3440, 0xd8dee9, 0x434c5e,
        0x3b4252, 0xbf616a, 0xa3be8c, 0xebcb8b, 0x81a1c1, 0xb48ead, 0x88c0d0, 0xe5e9f0,
        0x4c566a, 0xbf616a, 0xa3be8c, 0xebcb8b, 0x81a1c1, 0xb48ead, 0x8fbcbb, 0xeceff4]),
    ("tokyo-night", "Tokyo Night", [
        0xc0caf5, 0x1a1b26, 0xc0caf5, 0x33467c,
        0x15161e, 0xf7768e, 0x9ece6a, 0xe0af68, 0x7aa2f7, 0xbb9af7, 0x7dcfff, 0xa9b1d6,
        0x414868, 0xf7768e, 0x9ece6a, 0xe0af68, 0x7aa2f7, 0xbb9af7, 0x7dcfff, 0xc0caf5]),
    ("catppuccin-mocha", "Catppuccin Mocha", [
        0xcdd6f4, 0x1e1e2e, 0xf5e0dc, 0x585b70,
        0x45475a, 0xf38ba8, 0xa6e3a1, 0xf9e2af, 0x89b4fa, 0xf5c2e7, 0x94e2d5, 0xbac2de,
        0x585b70, 0xf38ba8, 0xa6e3a1, 0xf9e2af, 0x89b4fa, 0xf5c2e7, 0x94e2d5, 0xa6adc8]),
    ("one-dark", "One Dark", [
        0xabb2bf, 0x282c34, 0x528bff, 0x3e4451,
        0x282c34, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xabb2bf,
        0x5c6370, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xffffff]),
    ("gruvbox-dark", "Gruvbox Oscuro", [
        0xebdbb2, 0x282828, 0xebdbb2, 0x504945,
        0x282828, 0xcc241d, 0x98971a, 0xd79921, 0x458588, 0xb16286, 0x689d6a, 0xa89984,
        0x928374, 0xfb4934, 0xb8bb26, 0xfabd2f, 0x83a598, 0xd3869b, 0x8ec07c, 0xebdbb2]),
    ("solarized-dark", "Solarized Oscuro", [
        0x839496, 0x002b36, 0x93a1a1, 0x073642,
        0x073642, 0xdc322f, 0x859900, 0xb58900, 0x268bd2, 0xd33682, 0x2aa198, 0xeee8d5,
        0x002b36, 0xcb4b16, 0x586e75, 0x657b83, 0x839496, 0x6c71c4, 0x93a1a1, 0xfdf6e3]),
    ("monokai", "Monokai", [
        0xf8f8f2, 0x272822, 0xf8f8f0, 0x49483e,
        0x272822, 0xf92672, 0xa6e22e, 0xf4bf75, 0x66d9ef, 0xae81ff, 0xa1efe4, 0xf8f8f2,
        0x75715e, 0xf92672, 0xa6e22e, 0xf4bf75, 0x66d9ef, 0xae81ff, 0xa1efe4, 0xf9f8f5]),
    ("solarized-light", "Solarized Claro", [
        0x657b83, 0xfdf6e3, 0x586e75, 0xeee8d5,
        0x073642, 0xdc322f, 0x859900, 0xb58900, 0x268bd2, 0xd33682, 0x2aa198, 0xeee8d5,
        0x002b36, 0xcb4b16, 0x586e75, 0x657b83, 0x839496, 0x6c71c4, 0x93a1a1, 0xfdf6e3]),
    ("catppuccin-latte", "Catppuccin Latte", [
        0x4c4f69, 0xeff1f5, 0xdc8a78, 0xacb0be,
        0x5c5f77, 0xd20f39, 0x40a02b, 0xdf8e1d, 0x1e66f5, 0xea76cb, 0x179299, 0xacb0be,
        0x6c6f85, 0xd20f39, 0x40a02b, 0xdf8e1d, 0x1e66f5, 0xea76cb, 0x179299, 0xbcc0cc]),
    ("github-light", "GitHub Claro", [
        0x24292f, 0xffffff, 0x0969da, 0xb6e3ff,
        0x24292f, 0xcf222e, 0x116329, 0x4d2d00, 0x0969da, 0x8250df, 0x1b7c83, 0x6e7781,
        0x57606a, 0xa40e26, 0x1a7f37, 0x633c01, 0x218bff, 0xa475f9, 0x3192aa, 0x8c959f]),
];

const fn split(hex: u32) -> [u8; 3] {
    [(hex >> 16) as u8, (hex >> 8) as u8, hex as u8]
}

fn from_row((id, name, c): &Row) -> Theme {
    let mut ansi = [[0u8; 3]; 16];
    for (slot, hex) in ansi.iter_mut().zip(&c[4..]) {
        *slot = split(*hex);
    }
    Theme {
        id: (*id).to_string(),
        name: (*name).to_string(),
        foreground: split(c[0]),
        background: split(c[1]),
        cursor: split(c[2]),
        selection: split(c[3]),
        ansi,
    }
}

static BUILTIN: LazyLock<Vec<Theme>> =
    LazyLock::new(|| BUILTIN_TABLE.iter().map(from_row).collect());

/// Temas incluidos, primero los oscuros.
pub fn builtin() -> &'static [Theme] {
    &BUILTIN
}

pub fn default_theme() -> &'static Theme {
    &BUILTIN[0]
}

/// Busca un tema por id entre los importados y los incluidos; si no existe usa el oscuro.
pub fn find<'a>(id: &str, custom: &'a [Theme]) -> &'a Theme {
    let builtin: &'a [Theme] = builtin();
    custom
        .iter()
        .chain(builtin)
        .find(|t| t.id == id)
        .unwrap_or(&builtin[0])
}

pub fn rgb([r, g, b]: [u8; 3]) -> Rgb {
    Rgb { r, g, b }
}

const CUBE_LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

/// Color de la paleta xterm de 256 colores.
pub fn indexed(theme: &Theme, index: u8) -> Rgb {
    match index {
        0..=15 => rgb(theme.ansi[usize::from(index)]),
        16..=231 => {
            let i = index - 16;
            Rgb {
                r: CUBE_LEVELS[usize::from(i / 36)],
                g: CUBE_LEVELS[usize::from((i / 6) % 6)],
                b: CUBE_LEVELS[usize::from(i % 6)],
            }
        }
        232..=255 => {
            let level = 8 + (index - 232) * 10;
            Rgb {
                r: level,
                g: level,
                b: level,
            }
        }
    }
}

fn dim(c: Rgb) -> Rgb {
    let scale = |v: u8| (u16::from(v) * 2 / 3) as u8;
    Rgb {
        r: scale(c.r),
        g: scale(c.g),
        b: scale(c.b),
    }
}

fn named(theme: &Theme, color: NamedColor) -> Rgb {
    let ansi = |i: usize| rgb(theme.ansi[i]);
    match color {
        NamedColor::Foreground | NamedColor::BrightForeground => rgb(theme.foreground),
        NamedColor::Background => rgb(theme.background),
        NamedColor::Cursor => rgb(theme.cursor),
        NamedColor::DimForeground => dim(rgb(theme.foreground)),
        NamedColor::DimBlack => dim(ansi(0)),
        NamedColor::DimRed => dim(ansi(1)),
        NamedColor::DimGreen => dim(ansi(2)),
        NamedColor::DimYellow => dim(ansi(3)),
        NamedColor::DimBlue => dim(ansi(4)),
        NamedColor::DimMagenta => dim(ansi(5)),
        NamedColor::DimCyan => dim(ansi(6)),
        NamedColor::DimWhite => dim(ansi(7)),
        other => {
            let index = other as usize;
            if index < 16 {
                ansi(index)
            } else {
                rgb(theme.foreground)
            }
        }
    }
}

/// Resuelve un color de celda, respetando los cambios de paleta hechos por el programa (OSC 4).
pub fn resolve(theme: &Theme, overrides: &dyn Fn(usize) -> Option<Rgb>, color: Color) -> Rgb {
    match color {
        Color::Spec(rgb) => rgb,
        Color::Indexed(i) => overrides(usize::from(i)).unwrap_or_else(|| indexed(theme, i)),
        Color::Named(n) => overrides(n as usize).unwrap_or_else(|| named(theme, n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::theme::contrast;

    #[test]
    fn indexed_covers_ansi_cube_and_grayscale() {
        let t = default_theme();
        assert_eq!(indexed(t, 1), rgb(t.ansi[1]));
        assert_eq!(indexed(t, 16), Rgb { r: 0, g: 0, b: 0 });
        assert_eq!(indexed(t, 196), Rgb { r: 255, g: 0, b: 0 });
        assert_eq!(
            indexed(t, 231),
            Rgb {
                r: 255,
                g: 255,
                b: 255
            }
        );
        assert_eq!(indexed(t, 232), Rgb { r: 8, g: 8, b: 8 });
        assert_eq!(
            indexed(t, 255),
            Rgb {
                r: 238,
                g: 238,
                b: 238
            }
        );
    }

    #[test]
    fn resolve_prefers_program_overrides() {
        let t = default_theme();
        let custom = Rgb { r: 1, g: 2, b: 3 };
        let overrides = |i: usize| (i == 4).then_some(custom);
        assert_eq!(resolve(t, &overrides, Color::Indexed(4)), custom);
        assert_eq!(
            resolve(t, &|_| None, Color::Named(NamedColor::Red)),
            rgb(t.ansi[1])
        );
        assert_eq!(
            resolve(t, &|_| None, Color::Named(NamedColor::Background)),
            rgb(t.background)
        );
    }

    #[test]
    fn find_prefers_custom_and_falls_back_to_default() {
        let custom = Theme {
            id: "usuario:x".into(),
            ..default_theme().clone()
        };
        assert_eq!(
            find("usuario:x", std::slice::from_ref(&custom)).id,
            "usuario:x"
        );
        assert_eq!(find("dracula", &[]).name, "Dracula");
        assert_eq!(find("no-existe", &[]).id, DEFAULT_ID);
    }

    #[test]
    fn builtin_ids_are_unique_and_include_light_theme() {
        let mut ids: Vec<&str> = builtin().iter().map(|t| t.id.as_str()).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total);
        assert!(!find(LIGHT_ID, &[]).is_dark());
    }

    /// Se respetan las paletas oficiales; las que no llegan a AA se señalan en la interfaz.
    #[test]
    fn every_builtin_theme_has_readable_text() {
        const MIN_CONTRAST: f64 = 3.0;
        for theme in builtin() {
            let ratio = contrast(theme.foreground, theme.background);
            assert!(
                ratio >= MIN_CONTRAST,
                "{}: contraste {ratio:.2}",
                theme.name
            );
        }
        let low: Vec<&str> = builtin()
            .iter()
            .filter(|t| t.has_low_contrast())
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(low, vec!["Solarized Claro"]);
    }
}
