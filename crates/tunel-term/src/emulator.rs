//! Emulador de terminal: alacritty_terminal + una vista de pantalla independiente de la UI.

use crate::palette::{self, Theme, rgb};
use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{CursorShape, CursorStyle as AnsiCursorStyle, Processor, Rgb};
use std::sync::{Arc, Mutex};
use tunel_core::theme::CursorStyle;

/// Eventos que el emulador produce y que la aplicación debe atender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermEvent {
    Title(String),
    Bell,
    /// Respuesta que hay que devolver al programa remoto (p. ej. informe de cursor).
    Reply(String),
    CopyToClipboard(String),
}

#[derive(Clone, Default)]
struct Listener(Arc<Mutex<Vec<TermEvent>>>);

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        let mapped = match event {
            Event::Title(title) => Some(TermEvent::Title(title)),
            Event::Bell => Some(TermEvent::Bell),
            Event::PtyWrite(text) => Some(TermEvent::Reply(text)),
            Event::ClipboardStore(_, text) => Some(TermEvent::CopyToClipboard(text)),
            _ => None,
        };
        if let (Some(event), Ok(mut queue)) = (mapped, self.0.lock()) {
            queue.push(event);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenCell {
    pub ch: char,
    pub fg: Rgb,
    pub bg: Rgb,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikeout: bool,
    /// Primera mitad de un carácter de doble ancho.
    pub wide: bool,
    /// Segunda mitad de un carácter ancho: no se dibuja.
    pub spacer: bool,
    pub selected: bool,
}

/// Instantánea de lo visible, lista para dibujar.
#[derive(Debug, Clone, PartialEq)]
pub struct Screen {
    pub cols: usize,
    pub rows: usize,
    pub cells: Vec<ScreenCell>,
    pub cursor: Option<(usize, usize)>,
    pub cursor_shape: CursorKind,
    pub background: Rgb,
    pub cursor_color: Rgb,
    pub selection_color: Rgb,
    pub scrolled_back: bool,
}

impl Screen {
    pub fn cell(&self, row: usize, col: usize) -> &ScreenCell {
        &self.cells[row * self.cols + col]
    }

    pub fn row_text(&self, row: usize) -> String {
        (0..self.cols)
            .map(|c| self.cell(row, c))
            .filter(|c| !c.spacer)
            .map(|c| c.ch)
            .collect::<String>()
            .trim_end()
            .to_string()
    }
}

/// Forma con la que se dibuja el cursor (la elige el usuario o el programa con DECSCUSR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorKind {
    Block,
    Bar,
    Underline,
    Hollow,
}

fn ansi_shape(style: CursorStyle) -> CursorShape {
    match style {
        CursorStyle::Block => CursorShape::Block,
        CursorStyle::Bar => CursorShape::Beam,
        CursorStyle::Underline => CursorShape::Underline,
    }
}

/// Modos del terminal que afectan a cómo se codifica la entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputModes {
    pub app_cursor: bool,
    pub bracketed_paste: bool,
    pub mouse_reporting: bool,
    pub alt_screen: bool,
}

pub struct Emulator {
    term: Term<Listener>,
    parser: Processor,
    listener: Listener,
    size: Size,
    config: Config,
}

pub const MIN_COLS: u16 = 2;
pub const MIN_ROWS: u16 = 1;

impl Emulator {
    pub fn new(cols: u16, rows: u16, scrollback: usize) -> Self {
        let size = Size {
            cols: usize::from(cols.max(MIN_COLS)),
            rows: usize::from(rows.max(MIN_ROWS)),
        };
        let listener = Listener::default();
        let config = Config {
            scrolling_history: scrollback,
            ..Config::default()
        };
        Self {
            term: Term::new(config.clone(), &size, listener.clone()),
            parser: Processor::new(),
            listener,
            size,
            config,
        }
    }

    /// Forma de cursor por defecto; los programas pueden cambiarla temporalmente.
    pub fn set_cursor_style(&mut self, style: CursorStyle) {
        let shape = ansi_shape(style);
        if self.config.default_cursor_style.shape == shape {
            return;
        }
        self.config.default_cursor_style = AnsiCursorStyle {
            shape,
            blinking: false,
        };
        self.term.set_options(self.config.clone());
    }

    /// Procesa la salida del programa y devuelve los eventos que generó.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<TermEvent> {
        self.parser.advance(&mut self.term, bytes);
        self.listener
            .0
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    pub fn size(&self) -> (u16, u16) {
        (self.size.cols as u16, self.size.rows as u16)
    }

    /// Cambia el tamaño; devuelve `true` si realmente cambió.
    pub fn resize(&mut self, cols: u16, rows: u16) -> bool {
        let size = Size {
            cols: usize::from(cols.max(MIN_COLS)),
            rows: usize::from(rows.max(MIN_ROWS)),
        };
        if size == self.size {
            return false;
        }
        self.size = size;
        self.term.resize(size);
        true
    }

    pub fn input_modes(&self) -> InputModes {
        let mode = *self.term.mode();
        InputModes {
            app_cursor: mode.contains(TermMode::APP_CURSOR),
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            mouse_reporting: mode.intersects(TermMode::MOUSE_MODE),
            alt_screen: mode.contains(TermMode::ALT_SCREEN),
        }
    }

    pub fn scroll(&mut self, lines: i32) {
        self.term.scroll_display(Scroll::Delta(lines));
    }

    pub fn scroll_to_bottom(&mut self) {
        self.term.scroll_display(Scroll::Bottom);
    }

    fn point(&self, row: usize, col: usize) -> Point {
        let offset = self.term.grid().display_offset() as i32;
        Point::new(
            Line(row as i32 - offset),
            Column(col.min(self.size.cols - 1)),
        )
    }

    pub fn start_selection(&mut self, row: usize, col: usize, word: bool) {
        let ty = if word {
            SelectionType::Semantic
        } else {
            SelectionType::Simple
        };
        self.term.selection = Some(Selection::new(ty, self.point(row, col), Side::Left));
    }

    pub fn update_selection(&mut self, row: usize, col: usize) {
        let point = self.point(row, col);
        if let Some(selection) = self.term.selection.as_mut() {
            selection.update(point, Side::Right);
        }
    }

    pub fn clear_selection(&mut self) {
        self.term.selection = None;
    }

    pub fn selection_text(&self) -> Option<String> {
        self.term.selection_to_string().filter(|s| !s.is_empty())
    }

    pub fn screen(&self, theme: &Theme) -> Screen {
        let content = self.term.renderable_content();
        let colors = content.colors;
        let overrides = |i: usize| colors[i];
        let blank = ScreenCell {
            ch: ' ',
            fg: rgb(theme.foreground),
            bg: rgb(theme.background),
            bold: false,
            italic: false,
            underline: false,
            strikeout: false,
            wide: false,
            spacer: false,
            selected: false,
        };
        let mut cells = vec![blank; self.size.cols * self.size.rows];
        let offset = content.display_offset as i32;
        let selection = content.selection;
        for indexed in content.display_iter {
            let row = indexed.point.line.0 + offset;
            let col = indexed.point.column.0;
            if row < 0 || row as usize >= self.size.rows || col >= self.size.cols {
                continue;
            }
            let cell = indexed.cell;
            let flags = cell.flags;
            let mut fg = palette::resolve(theme, &overrides, cell.fg);
            let mut bg = palette::resolve(theme, &overrides, cell.bg);
            if flags.contains(Flags::INVERSE) {
                std::mem::swap(&mut fg, &mut bg);
            }
            if flags.contains(Flags::HIDDEN) {
                fg = bg;
            }
            cells[row as usize * self.size.cols + col] = ScreenCell {
                ch: cell.c,
                fg,
                bg,
                bold: flags.contains(Flags::BOLD),
                italic: flags.contains(Flags::ITALIC),
                underline: flags.intersects(Flags::ALL_UNDERLINES),
                strikeout: flags.contains(Flags::STRIKEOUT),
                wide: flags.contains(Flags::WIDE_CHAR),
                spacer: flags.contains(Flags::WIDE_CHAR_SPACER),
                selected: selection.is_some_and(|s| s.contains(indexed.point)),
            };
        }
        let cursor_row = content.cursor.point.line.0 + offset;
        let cursor_visible = content.cursor.shape != CursorShape::Hidden
            && cursor_row >= 0
            && (cursor_row as usize) < self.size.rows;
        Screen {
            cols: self.size.cols,
            rows: self.size.rows,
            cells,
            cursor: cursor_visible.then_some((cursor_row as usize, content.cursor.point.column.0)),
            cursor_shape: match content.cursor.shape {
                CursorShape::Beam => CursorKind::Bar,
                CursorShape::Underline => CursorKind::Underline,
                CursorShape::HollowBlock => CursorKind::Hollow,
                CursorShape::Block | CursorShape::Hidden => CursorKind::Block,
            },
            background: rgb(theme.background),
            cursor_color: rgb(theme.cursor),
            selection_color: rgb(theme.selection),
            scrolled_back: content.display_offset > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::palette::{default_theme, rgb};

    #[test]
    fn cursor_style_setting_and_program_requests_change_shape() {
        let mut emu = Emulator::new(10, 2, 0);
        assert_eq!(emu.screen(default_theme()).cursor_shape, CursorKind::Block);
        emu.set_cursor_style(CursorStyle::Bar);
        assert_eq!(emu.screen(default_theme()).cursor_shape, CursorKind::Bar);
        // DECSCUSR 4 = subrayado fijo, pedido por el programa (p. ej. vim en modo inserción).
        emu.feed(b"\x1b[4 q");
        assert_eq!(
            emu.screen(default_theme()).cursor_shape,
            CursorKind::Underline
        );
    }

    #[test]
    fn plain_text_appears_on_first_row() {
        let mut emu = Emulator::new(20, 5, 100);
        emu.feed(b"hola mundo");
        let screen = emu.screen(default_theme());
        assert_eq!(screen.row_text(0), "hola mundo");
        assert_eq!(screen.cursor, Some((0, 10)));
    }

    #[test]
    fn newline_and_carriage_return_move_cursor() {
        let mut emu = Emulator::new(20, 5, 100);
        emu.feed(b"uno\r\ndos");
        let screen = emu.screen(default_theme());
        assert_eq!(screen.row_text(1), "dos");
    }

    #[test]
    fn sgr_red_foreground_is_resolved_from_theme() {
        let mut emu = Emulator::new(10, 2, 0);
        emu.feed(b"\x1b[31mX\x1b[0mY");
        let screen = emu.screen(default_theme());
        assert_eq!(screen.cell(0, 0).fg, rgb(default_theme().ansi[1]));
        assert_eq!(screen.cell(0, 1).fg, rgb(default_theme().foreground));
    }

    #[test]
    fn truecolor_and_bold_are_preserved() {
        let mut emu = Emulator::new(10, 2, 0);
        emu.feed(b"\x1b[1;38;2;10;20;30mZ");
        let cell = *emu.screen(default_theme()).cell(0, 0);
        assert!(cell.bold);
        assert_eq!(
            cell.fg,
            Rgb {
                r: 10,
                g: 20,
                b: 30
            }
        );
    }

    #[test]
    fn osc_title_produces_event() {
        let mut emu = Emulator::new(10, 2, 0);
        let events = emu.feed(b"\x1b]0;mi servidor\x07");
        assert_eq!(events, vec![TermEvent::Title("mi servidor".into())]);
    }

    #[test]
    fn cursor_position_request_produces_reply() {
        let mut emu = Emulator::new(10, 5, 0);
        let events = emu.feed(b"ab\x1b[6n");
        assert_eq!(events, vec![TermEvent::Reply("\x1b[1;3R".into())]);
    }

    #[test]
    fn bell_produces_event() {
        let mut emu = Emulator::new(10, 2, 0);
        assert_eq!(emu.feed(b"\x07"), vec![TermEvent::Bell]);
    }

    #[test]
    fn resize_changes_dimensions_once() {
        let mut emu = Emulator::new(10, 2, 0);
        assert!(emu.resize(40, 10));
        assert!(!emu.resize(40, 10));
        let screen = emu.screen(default_theme());
        assert_eq!((screen.cols, screen.rows), (40, 10));
    }

    #[test]
    fn app_cursor_and_bracketed_paste_modes_are_tracked() {
        let mut emu = Emulator::new(10, 2, 0);
        assert_eq!(emu.input_modes(), InputModes::default());
        emu.feed(b"\x1b[?1h\x1b[?2004h");
        let modes = emu.input_modes();
        assert!(modes.app_cursor);
        assert!(modes.bracketed_paste);
    }

    #[test]
    fn scrollback_keeps_old_lines() {
        let mut emu = Emulator::new(10, 2, 100);
        emu.feed(b"1\r\n2\r\n3\r\n4");
        emu.scroll(2);
        let screen = emu.screen(default_theme());
        assert!(screen.scrolled_back);
        assert_eq!(screen.row_text(0), "1");
    }

    #[test]
    fn selection_returns_selected_text() {
        let mut emu = Emulator::new(20, 2, 0);
        emu.feed(b"copiar esto");
        emu.start_selection(0, 0, false);
        emu.update_selection(0, 5);
        assert_eq!(emu.selection_text().as_deref(), Some("copiar"));
        assert!(emu.screen(default_theme()).cell(0, 2).selected);
        emu.clear_selection();
        assert_eq!(emu.selection_text(), None);
    }

    #[test]
    fn wide_characters_mark_spacer_cell() {
        let mut emu = Emulator::new(10, 2, 0);
        emu.feed("日本".as_bytes());
        let screen = emu.screen(default_theme());
        assert!(screen.cell(0, 0).wide);
        assert!(screen.cell(0, 1).spacer);
        assert_eq!(screen.row_text(0), "日本");
    }
}
