//! La rueda del ratón sobre la terminal, con eventos de verdad: en nano y less llega al
//! programa como flechas.

use super::*;
use crate::app::Tab;
use crate::session::TerminalSession;
use tunel_core::io::{BackendIo, SessionInput, session_pair};

fn terminal() -> (TestApp, BackendIo) {
    let mut app = TestApp::unlocked(VaultData::default());
    let (io, backend) = session_pair();
    let mut session = TerminalSession::new("nano".into(), None, 80, 24, 1000, io);
    session.status = crate::session::SessionStatus::Connected;
    app.harness
        .state_mut()
        .push_tab(Tab::Terminal(Box::new(session)));
    app.settle();
    (app, backend)
}

fn session(app: &mut TestApp) -> &mut TerminalSession {
    match &mut app.harness.state_mut().tabs[0] {
        Tab::Terminal(session) => session,
        _ => unreachable!(),
    }
}

/// Una vuelta de la rueda hacia arriba con el puntero en el centro de la ventana.
fn wheel_up(app: &mut TestApp) {
    let center = egui::pos2(700.0, 450.0);
    app.harness.event(egui::Event::PointerMoved(center));
    app.harness.event(egui::Event::MouseWheel {
        unit: egui::MouseWheelUnit::Line,
        delta: egui::vec2(0.0, 3.0),
        phase: egui::TouchPhase::Move,
        modifiers: egui::Modifiers::NONE,
        source: egui::MouseWheelSource::Wheel,
    });
    for _ in 0..30 {
        app.harness.step();
    }
}

fn sent(backend: &mut BackendIo) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Ok(input) = backend.input.try_recv() {
        if let SessionInput::Data(data) = input {
            bytes.extend(data);
        }
    }
    bytes
}

#[test]
fn in_nano_the_wheel_reaches_the_program_as_arrows() {
    let (mut app, mut backend) = terminal();
    session(&mut app).emulator.feed(b"\x1b[?1049h");
    sent(&mut backend);

    wheel_up(&mut app);

    let bytes = sent(&mut backend);
    assert!(!bytes.is_empty(), "no llegó nada al programa");
    assert!(
        bytes.chunks(3).all(|c| c == b"\x1b[A"),
        "{:?}",
        String::from_utf8_lossy(&bytes)
    );
}
