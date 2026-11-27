//! Cuándo aplicar un cambio de escala mientras se arrastra la ventana.
//!
//! Si la ventana queda a caballo entre dos pantallas con distinta escala, cada cambio de
//! escala la agranda o la encoge 1,5 veces y winit la recoloca bajo el ratón. Eso la vuelve a
//! dejar con más superficie en la otra pantalla, y la escala cambia otra vez. En Windows
//! puede rebotar así decenas de veces por segundo y saltar de sitio. Por eso, mientras se
//! arrastra, los cambios de escala se guardan y se aplican una sola vez al soltarla.

/// Los mensajes de la ventana que importan aquí.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    /// Empieza a arrastrarse o a cambiar de tamaño.
    EnterMove,
    /// Se suelta.
    ExitMove,
    /// Windows avisa de que la ventana cambió de escala.
    DpiChanged,
    /// El aviso que se envía la propia ventana para aplicar la escala pendiente.
    Refit,
}

/// Lo que se sabe de la ventana entre un mensaje y el siguiente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MoveState {
    moving: bool,
    deferred: bool,
}

/// Qué hacer con el mensaje.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// Pasárselo a winit sin más.
    Forward,
    /// No pasárselo: el cambio de escala queda pendiente hasta soltar la ventana.
    Hold,
    /// Pasárselo y enviar [`Message::Refit`] para aplicar la escala pendiente.
    ForwardThenRefit,
    /// Pasar a winit el cambio de escala y meter la ventana en su pantalla.
    ApplyScale,
    /// Aplicar la escala de la pantalla en la que quedó la ventana y meterla en ella.
    ApplyPendingScale,
}

pub fn react(state: MoveState, message: Message) -> (MoveState, Reaction) {
    match message {
        Message::EnterMove => (
            MoveState {
                moving: true,
                deferred: false,
            },
            Reaction::Forward,
        ),
        Message::DpiChanged if state.moving => (
            MoveState {
                deferred: true,
                ..state
            },
            Reaction::Hold,
        ),
        Message::DpiChanged => (state, Reaction::ApplyScale),
        Message::ExitMove => {
            let reaction = if state.deferred {
                Reaction::ForwardThenRefit
            } else {
                Reaction::Forward
            };
            (MoveState::default(), reaction)
        }
        Message::Refit => (state, Reaction::ApplyPendingScale),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(messages: &[Message]) -> Vec<Reaction> {
        messages
            .iter()
            .scan(MoveState::default(), |state, &message| {
                let (next, reaction) = react(*state, message);
                *state = next;
                Some(reaction)
            })
            .collect()
    }

    #[test]
    fn scale_changes_while_dragging_wait_until_the_window_is_dropped() {
        // Como en el registro del portátil al 150 %: la escala rebota mientras se arrastra.
        let reactions = run(&[
            Message::EnterMove,
            Message::DpiChanged,
            Message::DpiChanged,
            Message::DpiChanged,
            Message::ExitMove,
            Message::Refit,
        ]);
        assert_eq!(
            reactions,
            [
                Reaction::Forward,
                Reaction::Hold,
                Reaction::Hold,
                Reaction::Hold,
                Reaction::ForwardThenRefit,
                Reaction::ApplyPendingScale,
            ]
        );
    }

    #[test]
    fn a_drag_without_scale_changes_does_not_refit() {
        let reactions = run(&[Message::EnterMove, Message::ExitMove]);
        assert_eq!(reactions, [Reaction::Forward, Reaction::Forward]);
    }

    #[test]
    fn a_scale_change_outside_a_drag_is_applied_at_once() {
        // Por ejemplo, al cambiar la escala de la pantalla en Configuración.
        assert_eq!(run(&[Message::DpiChanged]), [Reaction::ApplyScale]);
    }

    #[test]
    fn the_next_drag_starts_clean() {
        let reactions = run(&[
            Message::EnterMove,
            Message::DpiChanged,
            Message::ExitMove,
            Message::EnterMove,
            Message::ExitMove,
            Message::DpiChanged,
        ]);
        assert_eq!(
            reactions,
            [
                Reaction::Forward,
                Reaction::Hold,
                Reaction::ForwardThenRefit,
                Reaction::Forward,
                Reaction::Forward,
                Reaction::ApplyScale,
            ]
        );
    }
}
