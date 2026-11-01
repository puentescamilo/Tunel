//! Escribir en varias terminales a la vez: lo que se teclea en una pestaña marcada se
//! repite en las demás marcadas. Mientras está activo, una franja lo recuerda encima de
//! la terminal.

use crate::app::{Tab, TunelApp};
use crate::ui::{self, icons};
use egui::RichText;

/// Pestañas marcadas que pueden recibir lo tecleado: índice y nombre.
pub fn members(app: &TunelApp) -> Vec<(usize, String)> {
    app.tabs
        .iter()
        .enumerate()
        .filter_map(|(i, tab)| match tab {
            Tab::Terminal(s) if s.broadcast && s.can_broadcast() => Some((i, s.title.clone())),
            _ => None,
        })
        .collect()
}

/// Marca o desmarca la pestaña `index`.
pub fn toggle(app: &mut TunelApp, index: usize) {
    if let Some(Tab::Terminal(session)) = app.tabs.get_mut(index)
        && session.can_broadcast()
    {
        session.broadcast = !session.broadcast;
    }
}

/// Desmarca todas las pestañas.
pub fn stop(app: &mut TunelApp) {
    for tab in &mut app.tabs {
        if let Tab::Terminal(session) = tab {
            session.broadcast = false;
        }
    }
}

/// Repite en las demás pestañas marcadas lo que se tecleó en la de clave `from`.
pub fn forward(tabs: &[Tab], from: u64, bytes: &[u8]) {
    for tab in tabs {
        if let Tab::Terminal(session) = tab
            && session.key != from
            && session.broadcast
            && session.can_broadcast()
        {
            session.send(bytes.to_vec());
        }
    }
}

/// Franja sobre una terminal marcada; devuelve `true` si se pulsó para dejar de escribir
/// en varias.
pub fn banner(ui: &mut egui::Ui, names: &[String]) -> bool {
    let p = ui::pal(ui);
    let mut stop = false;
    egui::Frame::new()
        .fill(p.warning.gamma_multiply(0.15))
        .inner_margin(egui::Margin::symmetric(14, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::KEYBOARD)
                        .font(ui::icon_font(16.0))
                        .color(p.warning),
                );
                let message = if names.len() < 2 {
                    "Escribir en varias a la vez: marca otra pestaña desde su menú de clic derecho"
                        .to_string()
                } else {
                    format!(
                        "Lo que escribes va a {} terminales: {}",
                        names.len(),
                        names.join(", ")
                    )
                };
                ui.label(RichText::new(message).color(p.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    stop = ui::secondary_button(ui, "Dejar de escribir en varias").clicked();
                });
            });
        });
    stop
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionStatus, TerminalSession};
    use tunel_core::io::{BackendIo, SessionInput, session_pair};

    fn terminal(broadcast: bool) -> (Tab, BackendIo) {
        let (io, backend) = session_pair();
        let mut session = TerminalSession::new("t".into(), None, 20, 4, 100, io);
        session.broadcast = broadcast;
        (Tab::Terminal(Box::new(session)), backend)
    }

    fn received(backend: &mut BackendIo) -> Vec<u8> {
        let mut out = Vec::new();
        while let Ok(SessionInput::Data(bytes)) = backend.input.try_recv() {
            out.extend(bytes);
        }
        out
    }

    fn key(tab: &Tab) -> u64 {
        let Tab::Terminal(s) = tab else {
            unreachable!()
        };
        s.key
    }

    #[test]
    fn typing_reaches_the_other_marked_terminals_only() {
        let (from, mut from_io) = terminal(true);
        let (other, mut other_io) = terminal(true);
        let (unmarked, mut unmarked_io) = terminal(false);
        let (mut ended, mut ended_io) = terminal(true);
        if let Tab::Terminal(s) = &mut ended {
            s.status = SessionStatus::Closed(None);
        }
        let tabs = [from, other, unmarked, ended];
        forward(&tabs, key(&tabs[0]), b"uptime\r");
        assert_eq!(received(&mut other_io), b"uptime\r");
        assert!(
            received(&mut from_io).is_empty(),
            "no se repite en la de origen"
        );
        assert!(received(&mut unmarked_io).is_empty());
        assert!(received(&mut ended_io).is_empty());
    }

    #[test]
    fn only_marked_terminals_keep_what_was_typed() {
        let (io, mut backend) = session_pair();
        let mut session = TerminalSession::new("t".into(), None, 20, 4, 100, io);
        session.send_typed(b"ls".to_vec());
        assert!(session.take_typed().is_empty());
        session.broadcast = true;
        session.send_typed(b"ls\r".to_vec());
        assert_eq!(session.take_typed(), b"ls\r");
        assert!(session.take_typed().is_empty());
        assert_eq!(
            received(&mut backend),
            b"lsls\r",
            "siempre se envía a la propia"
        );
    }
}
