//! La rueda del ratón: qué hacer con ella según lo que pida el programa de la terminal.
//!
//! Como en xterm y Alacritty: si el programa sigue el ratón, recibe la rueda como pulsaciones
//! de los botones 4 y 5; en la pantalla alterna (nano, less, man…) se convierte en flechas,
//! porque ahí no hay historial; y en la pantalla normal recorre el historial.

use crate::emulator::InputModes;
use crate::keys::{self, Key, Modifiers};

/// Las coordenadas del protocolo antiguo van en un byte: más allá de esta columna o fila no
/// se pueden expresar.
const LEGACY_MAX_POSITION: usize = 223;
const BUTTON_WHEEL_UP: u8 = 64;
const BUTTON_WHEEL_DOWN: u8 = 65;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WheelAction {
    /// Recorrer el historial: positivo hacia arriba.
    Scrollback(i32),
    /// Enviar estos bytes al programa.
    Send(Vec<u8>),
}

/// `lines` positivo es hacia arriba; `row` y `col` son la celda bajo el puntero, desde 0.
pub fn wheel(lines: i32, row: usize, col: usize, modes: InputModes) -> WheelAction {
    let up = lines > 0;
    let count = lines.unsigned_abs() as usize;
    if modes.mouse_reporting {
        let button = if up {
            BUTTON_WHEEL_UP
        } else {
            BUTTON_WHEEL_DOWN
        };
        let event = mouse_event(button, row, col, modes.sgr_mouse);
        return WheelAction::Send(event.repeat(count));
    }
    if modes.alt_screen && modes.alternate_scroll {
        let key = if up { Key::Up } else { Key::Down };
        let arrow = keys::encode(key, Modifiers::default(), modes).unwrap_or_default();
        return WheelAction::Send(arrow.repeat(count));
    }
    WheelAction::Scrollback(lines)
}

fn mouse_event(button: u8, row: usize, col: usize, sgr: bool) -> Vec<u8> {
    let (x, y) = (col + 1, row + 1);
    if sgr {
        return format!("\x1b[<{button};{x};{y}M").into_bytes();
    }
    let byte = |value: usize| (32 + value.min(LEGACY_MAX_POSITION)) as u8;
    vec![0x1b, b'[', b'M', 32 + button, byte(x), byte(y)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal() -> InputModes {
        InputModes {
            alternate_scroll: true,
            ..InputModes::default()
        }
    }

    fn alt_screen() -> InputModes {
        InputModes {
            alt_screen: true,
            ..normal()
        }
    }

    #[test]
    fn on_the_normal_screen_the_wheel_moves_through_the_history() {
        assert_eq!(wheel(3, 0, 0, normal()), WheelAction::Scrollback(3));
        assert_eq!(wheel(-2, 0, 0, normal()), WheelAction::Scrollback(-2));
    }

    #[test]
    fn in_nano_or_less_the_wheel_becomes_arrows() {
        assert_eq!(
            wheel(2, 5, 5, alt_screen()),
            WheelAction::Send(b"\x1b[A\x1b[A".to_vec())
        );
        assert_eq!(
            wheel(-1, 5, 5, alt_screen()),
            WheelAction::Send(b"\x1b[B".to_vec())
        );
    }

    #[test]
    fn the_arrows_follow_the_application_cursor_mode() {
        let modes = InputModes {
            app_cursor: true,
            ..alt_screen()
        };

        assert_eq!(wheel(1, 0, 0, modes), WheelAction::Send(b"\x1bOA".to_vec()));
    }

    #[test]
    fn a_program_that_turns_off_alternate_scroll_gets_nothing() {
        let modes = InputModes {
            alternate_scroll: false,
            ..alt_screen()
        };

        assert_eq!(wheel(1, 0, 0, modes), WheelAction::Scrollback(1));
    }

    #[test]
    fn a_program_that_follows_the_mouse_gets_wheel_buttons_where_the_pointer_is() {
        let modes = InputModes {
            mouse_reporting: true,
            sgr_mouse: true,
            ..alt_screen()
        };

        assert_eq!(
            wheel(2, 4, 9, modes),
            WheelAction::Send(b"\x1b[<64;10;5M\x1b[<64;10;5M".to_vec())
        );
        assert_eq!(
            wheel(-1, 0, 0, modes),
            WheelAction::Send(b"\x1b[<65;1;1M".to_vec())
        );
    }

    #[test]
    fn without_sgr_the_old_mouse_protocol_is_used_and_clamped() {
        let modes = InputModes {
            mouse_reporting: true,
            ..alt_screen()
        };

        assert_eq!(
            wheel(1, 1, 2, modes),
            WheelAction::Send(vec![0x1b, b'[', b'M', 96, 35, 34])
        );
        let WheelAction::Send(far) = wheel(-1, 300, 300, modes) else {
            panic!("debería enviar");
        };
        assert_eq!(far, vec![0x1b, b'[', b'M', 97, 255, 255]);
    }
}
