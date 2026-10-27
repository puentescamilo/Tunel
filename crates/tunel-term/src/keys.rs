//! Traducción de teclas a secuencias de bytes para el programa remoto (estilo xterm).

use crate::emulator::InputModes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Tab,
    Backspace,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    F(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
}

impl Modifiers {
    /// Parámetro de modificador de xterm (1 = ninguno).
    fn xterm_param(self) -> u8 {
        1 + u8::from(self.shift) + 2 * u8::from(self.alt) + 4 * u8::from(self.ctrl)
    }

    fn any(self) -> bool {
        self.shift || self.ctrl || self.alt
    }
}

fn csi_with_mods(final_byte: char, mods: Modifiers) -> Vec<u8> {
    format!("\x1b[1;{}{final_byte}", mods.xterm_param()).into_bytes()
}

fn tilde(code: u8, mods: Modifiers) -> Vec<u8> {
    if mods.any() {
        format!("\x1b[{code};{}~", mods.xterm_param()).into_bytes()
    } else {
        format!("\x1b[{code}~").into_bytes()
    }
}

fn ctrl_char(c: char) -> Option<u8> {
    match c.to_ascii_lowercase() {
        c @ 'a'..='z' => Some(c as u8 - b'a' + 1),
        '@' | ' ' | '2' => Some(0),
        '[' | '3' => Some(0x1b),
        '\\' | '4' => Some(0x1c),
        ']' | '5' => Some(0x1d),
        '^' | '6' => Some(0x1e),
        '_' | '-' | '7' => Some(0x1f),
        '?' | '8' => Some(0x7f),
        _ => None,
    }
}

fn function_key(n: u8, mods: Modifiers) -> Option<Vec<u8>> {
    match n {
        1..=4 => {
            let final_byte = ['P', 'Q', 'R', 'S'][usize::from(n - 1)];
            Some(if mods.any() {
                csi_with_mods(final_byte, mods)
            } else {
                format!("\x1bO{final_byte}").into_bytes()
            })
        }
        5 => Some(tilde(15, mods)),
        6..=10 => Some(tilde(n + 11, mods)),
        11 | 12 => Some(tilde(n + 12, mods)),
        _ => None,
    }
}

pub fn encode(key: Key, mods: Modifiers, modes: InputModes) -> Option<Vec<u8>> {
    let cursor = |final_byte: char| {
        if mods.any() {
            csi_with_mods(final_byte, mods)
        } else if modes.app_cursor {
            format!("\x1bO{final_byte}").into_bytes()
        } else {
            format!("\x1b[{final_byte}").into_bytes()
        }
    };
    let bytes = match key {
        Key::Char(c) if mods.ctrl => {
            let code = ctrl_char(c)?;
            if mods.alt {
                vec![0x1b, code]
            } else {
                vec![code]
            }
        }
        Key::Char(c) => {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf).as_bytes().to_vec();
            if mods.alt {
                [vec![0x1b], encoded].concat()
            } else {
                encoded
            }
        }
        Key::Enter => {
            if mods.alt {
                b"\x1b\r".to_vec()
            } else {
                b"\r".to_vec()
            }
        }
        Key::Tab if mods.shift => b"\x1b[Z".to_vec(),
        Key::Tab => b"\t".to_vec(),
        Key::Backspace if mods.ctrl => vec![0x08],
        Key::Backspace if mods.alt => vec![0x1b, 0x7f],
        Key::Backspace => vec![0x7f],
        Key::Escape => vec![0x1b],
        Key::Up => cursor('A'),
        Key::Down => cursor('B'),
        Key::Right => cursor('C'),
        Key::Left => cursor('D'),
        Key::Home => cursor('H'),
        Key::End => cursor('F'),
        Key::Insert => tilde(2, mods),
        Key::Delete => tilde(3, mods),
        Key::PageUp => tilde(5, mods),
        Key::PageDown => tilde(6, mods),
        Key::F(n) => function_key(n, mods)?,
    };
    Some(bytes)
}

/// Prepara texto pegado; con bracketed paste se envuelve para que la shell no lo ejecute línea a línea.
///
/// Se eliminan los caracteres de control (salvo tabulador y saltos de línea), incluidos ESC y el
/// CSI de 8 bits: así ningún contenido del portapapeles puede cerrar el pegado ni inyectar teclas.
pub fn encode_paste(text: &str, modes: InputModes) -> Vec<u8> {
    let normalized = text.replace("\r\n", "\r").replace('\n', "\r");
    let safe: String = normalized
        .chars()
        .filter(|&c| c == '\t' || c == '\r' || !(c.is_control()))
        .collect();
    if modes.bracketed_paste {
        format!("\x1b[200~{safe}\x1b[201~").into_bytes()
    } else {
        safe.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Modifiers = Modifiers {
        shift: false,
        ctrl: false,
        alt: false,
    };
    const CTRL: Modifiers = Modifiers {
        shift: false,
        ctrl: true,
        alt: false,
    };
    const ALT: Modifiers = Modifiers {
        shift: false,
        ctrl: false,
        alt: true,
    };

    fn enc(key: Key, mods: Modifiers) -> Vec<u8> {
        encode(key, mods, InputModes::default()).unwrap()
    }

    #[test]
    fn printable_and_unicode_characters_are_utf8() {
        assert_eq!(enc(Key::Char('a'), NONE), b"a");
        assert_eq!(enc(Key::Char('ñ'), NONE), "ñ".as_bytes());
    }

    #[test]
    fn ctrl_letters_map_to_control_codes() {
        assert_eq!(enc(Key::Char('c'), CTRL), vec![3]);
        assert_eq!(enc(Key::Char('D'), CTRL), vec![4]);
        assert_eq!(enc(Key::Char('['), CTRL), vec![0x1b]);
        assert_eq!(encode(Key::Char('é'), CTRL, InputModes::default()), None);
    }

    #[test]
    fn alt_prefixes_escape() {
        assert_eq!(enc(Key::Char('b'), ALT), b"\x1bb");
        assert_eq!(enc(Key::Backspace, ALT), vec![0x1b, 0x7f]);
    }

    #[test]
    fn arrows_respect_application_cursor_mode() {
        assert_eq!(enc(Key::Up, NONE), b"\x1b[A");
        let app = InputModes {
            app_cursor: true,
            ..InputModes::default()
        };
        assert_eq!(encode(Key::Up, NONE, app).unwrap(), b"\x1bOA");
        assert_eq!(enc(Key::Left, CTRL), b"\x1b[1;5D");
    }

    #[test]
    fn editing_and_function_keys() {
        assert_eq!(enc(Key::Delete, NONE), b"\x1b[3~");
        assert_eq!(enc(Key::PageUp, NONE), b"\x1b[5~");
        assert_eq!(enc(Key::F(1), NONE), b"\x1bOP");
        assert_eq!(enc(Key::F(5), NONE), b"\x1b[15~");
        assert_eq!(enc(Key::F(12), NONE), b"\x1b[24~");
        assert_eq!(encode(Key::F(13), NONE, InputModes::default()), None);
        assert_eq!(
            enc(
                Key::Tab,
                Modifiers {
                    shift: true,
                    ..NONE
                }
            ),
            b"\x1b[Z"
        );
    }

    #[test]
    fn paste_normalizes_newlines_and_brackets() {
        assert_eq!(encode_paste("a\nb", InputModes::default()), b"a\rb");
        let bracketed = InputModes {
            bracketed_paste: true,
            ..InputModes::default()
        };
        assert_eq!(encode_paste("ls\n", bracketed), b"\x1b[200~ls\r\x1b[201~");
    }

    #[test]
    fn paste_strips_embedded_bracket_terminator() {
        let bracketed = InputModes {
            bracketed_paste: true,
            ..InputModes::default()
        };
        let out = encode_paste("x\x1b[201~rm -rf ~\n", bracketed);
        assert_eq!(out, b"\x1b[200~x[201~rm -rf ~\r\x1b[201~");
    }

    #[test]
    fn paste_strips_nested_terminator_that_survives_single_pass() {
        let bracketed = InputModes {
            bracketed_paste: true,
            ..InputModes::default()
        };
        let out = encode_paste("\x1b[20\x1b[201~1~rm -rf ~\n", bracketed);
        let inner = &out[6..out.len() - 6];
        assert!(
            !inner.contains(&0x1b),
            "quedó un ESC dentro del pegado: {out:?}"
        );
    }

    #[test]
    fn paste_drops_control_characters_but_keeps_tabs_and_newlines() {
        let out = encode_paste("a\tb\x03c\x1bd\u{9b}e\n", InputModes::default());
        assert_eq!(out, b"a\tbcde\r");
    }
}
