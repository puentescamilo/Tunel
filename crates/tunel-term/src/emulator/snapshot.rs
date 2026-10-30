//! Instantánea de la pantalla como secuencias de escape, para quien empieza a mirar una
//! sesión compartida cuando ya estaba en marcha.
//!
//! Recoge lo visible, los colores y atributos, el cursor y los modos que cambian cómo se
//! codifica la entrada. No recoge el historial, la región de desplazamiento ni la pantalla
//! principal cuando se está en la alternativa: los programas de pantalla completa la
//! redibujan en cuanto cambia algo.

use super::Emulator;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::TermMode;
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::vte::ansi::{Color, NamedColor};
use std::fmt::Write;

/// Atributos con los que se dibuja una celda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pen {
    fg: Color,
    bg: Color,
    flags: Flags,
}

const STYLE_FLAGS: Flags = Flags::BOLD
    .union(Flags::DIM)
    .union(Flags::ITALIC)
    .union(Flags::ALL_UNDERLINES)
    .union(Flags::INVERSE)
    .union(Flags::HIDDEN)
    .union(Flags::STRIKEOUT);

impl Pen {
    const DEFAULT: Self = Self {
        fg: Color::Named(NamedColor::Foreground),
        bg: Color::Named(NamedColor::Background),
        flags: Flags::empty(),
    };

    fn of(cell: &Cell) -> Self {
        Self {
            fg: cell.fg,
            bg: cell.bg,
            flags: cell.flags & STYLE_FLAGS,
        }
    }

    /// SGR completo: empieza por 0, así no depende de los atributos anteriores.
    fn sgr(&self, out: &mut String) {
        out.push_str("\x1b[0");
        let attributes = [
            (Flags::BOLD, "1"),
            (Flags::DIM, "2"),
            (Flags::ITALIC, "3"),
            (Flags::INVERSE, "7"),
            (Flags::HIDDEN, "8"),
            (Flags::STRIKEOUT, "9"),
        ];
        for (flag, code) in attributes {
            if self.flags.contains(flag) {
                out.push(';');
                out.push_str(code);
            }
        }
        if self.flags.intersects(Flags::ALL_UNDERLINES) {
            out.push_str(";4");
        }
        color(out, self.fg, 30);
        color(out, self.bg, 40);
        out.push('m');
    }
}

/// `base` es 30 para el texto y 40 para el fondo.
fn color(out: &mut String, color: Color, base: u16) {
    let _ = match color {
        Color::Named(named) => match named as u16 {
            n @ 0..8 => write!(out, ";{}", base + n),
            n @ 8..16 => write!(out, ";{}", base + 60 + n - 8),
            // El color por defecto, el del cursor y las variantes atenuadas, que el
            // emulador saca del atributo DIM.
            _ => Ok(()),
        },
        Color::Indexed(index) => write!(out, ";{};5;{index}", base + 8),
        Color::Spec(rgb) => write!(out, ";{};2;{};{};{}", base + 8, rgb.r, rgb.g, rgb.b),
    };
}

/// Un carácter de control en una celda (C1, como U+009B, que algunas terminales leen
/// como el inicio de una secuencia) no se copia tal cual.
fn printable(c: char) -> char {
    if c.is_control() { ' ' } else { c }
}

/// Modos privados (DECSET) que se reproducen si están activos.
const PRIVATE_MODES: [(TermMode, u16); 7] = [
    (TermMode::APP_CURSOR, 1),
    (TermMode::MOUSE_REPORT_CLICK, 1000),
    (TermMode::MOUSE_DRAG, 1002),
    (TermMode::MOUSE_MOTION, 1003),
    (TermMode::FOCUS_IN_OUT, 1004),
    (TermMode::SGR_MOUSE, 1006),
    (TermMode::BRACKETED_PASTE, 2004),
];

impl Emulator {
    /// Bytes que, procesados por una terminal vacía del mismo tamaño, reproducen lo que
    /// se ve ahora.
    pub fn snapshot(&self) -> Vec<u8> {
        let mode = *self.term.mode();
        let grid = self.term.grid();
        let mut out = String::new();
        if mode.contains(TermMode::ALT_SCREEN) {
            out.push_str("\x1b[?1049h");
        }
        out.push_str("\x1b[0m\x1b[H\x1b[2J");
        for row in 0..grid.screen_lines() {
            let line = &grid[Line(row as i32)];
            // Las celdas en blanco del final no hace falta escribirlas.
            let end = (0..grid.columns())
                .rev()
                .find(|&col| {
                    let cell = &line[Column(col)];
                    cell.c != ' ' || Pen::of(cell) != Pen::DEFAULT
                })
                .map_or(0, |col| col + 1);
            if end == 0 {
                continue;
            }
            let _ = write!(out, "\x1b[{};1H", row + 1);
            let mut pen = Pen::DEFAULT;
            for col in 0..end {
                let cell = &line[Column(col)];
                if cell
                    .flags
                    .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
                {
                    continue;
                }
                let cell_pen = Pen::of(cell);
                if cell_pen != pen {
                    cell_pen.sgr(&mut out);
                    pen = cell_pen;
                }
                out.push(printable(cell.c));
                out.extend(
                    cell.zerowidth()
                        .into_iter()
                        .flatten()
                        .map(|&c| printable(c)),
                );
            }
            out.push_str("\x1b[0m");
        }
        let cursor = grid.cursor.point;
        let _ = write!(out, "\x1b[{};{}H", cursor.line.0 + 1, cursor.column.0 + 1);
        for (flag, number) in PRIVATE_MODES {
            if mode.contains(flag) {
                let _ = write!(out, "\x1b[?{number}h");
            }
        }
        if mode.contains(TermMode::APP_KEYPAD) {
            out.push_str("\x1b=");
        }
        if !mode.contains(TermMode::LINE_WRAP) {
            out.push_str("\x1b[?7l");
        }
        if !mode.contains(TermMode::SHOW_CURSOR) {
            out.push_str("\x1b[?25l");
        }
        out.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::palette::default_theme;

    /// Pasa la instantánea de `source` a una terminal nueva del mismo tamaño.
    fn replay(source: &Emulator) -> Emulator {
        let (cols, rows) = source.size();
        let mut copy = Emulator::new(cols, rows, 0);
        copy.feed(&source.snapshot());
        copy
    }

    fn assert_same_screen(a: &Emulator, b: &Emulator) {
        let theme = default_theme();
        assert_eq!(a.screen(theme), b.screen(theme));
        assert_eq!(a.input_modes(), b.input_modes());
    }

    #[test]
    fn text_colors_and_cursor_are_reproduced() {
        let mut emu = Emulator::new(30, 6, 100);
        emu.feed(b"\x1b[1;31mrojo\x1b[0m normal \x1b[38;5;208mnaranja\r\n");
        emu.feed(b"\x1b[48;2;10;20;30m fondo \x1b[0m\x1b[4msub\x1b[7minv\x1b[0m\r\n");
        emu.feed(b"\x1b[2;3;9mtenue\x1b[0m \x1b[94mbrillante\x1b[0m\r\n$ ");
        assert_same_screen(&emu, &replay(&emu));
    }

    #[test]
    fn wide_and_combining_characters_are_reproduced() {
        let mut emu = Emulator::new(12, 2, 0);
        emu.feed("日本 e\u{301}".as_bytes());
        assert_same_screen(&emu, &replay(&emu));
    }

    #[test]
    fn a_full_last_line_does_not_scroll() {
        let mut emu = Emulator::new(4, 2, 0);
        emu.feed(b"abcd\r\nefgh");
        assert_same_screen(&emu, &replay(&emu));
    }

    #[test]
    fn only_the_visible_screen_is_copied() {
        let mut emu = Emulator::new(10, 2, 100);
        emu.feed(b"1\r\n2\r\n3\r\n4");
        let copy = replay(&emu);
        assert_same_screen(&emu, &copy);
        assert_eq!(copy.screen(default_theme()).row_text(0), "3");
    }

    #[test]
    fn full_screen_programs_and_input_modes_are_reproduced() {
        let mut emu = Emulator::new(20, 4, 100);
        emu.feed(b"shell\r\n");
        emu.feed(b"\x1b[?1049h\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[?25l");
        emu.feed(b"\x1b[2;5Heditor");
        let copy = replay(&emu);
        assert_same_screen(&emu, &copy);
        let modes = copy.input_modes();
        assert!(modes.alt_screen && modes.app_cursor && modes.bracketed_paste);
        assert!(modes.mouse_reporting);
        assert_eq!(copy.screen(default_theme()).cursor, None);
    }

    #[test]
    fn control_characters_in_cells_are_not_copied() {
        let mut emu = Emulator::new(10, 2, 0);
        emu.feed("a\u{9b}b".as_bytes());
        let snapshot = String::from_utf8(emu.snapshot()).unwrap();
        assert!(!snapshot.contains('\u{9b}'));
    }

    #[test]
    fn an_empty_screen_is_short() {
        let emu = Emulator::new(80, 24, 0);
        assert!(emu.snapshot().len() < 32);
        assert_same_screen(&emu, &replay(&emu));
    }
}
