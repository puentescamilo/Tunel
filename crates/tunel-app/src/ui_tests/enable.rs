//! «Enviar contraseña enable»: desde el menú de la pestaña o con el atajo, solo a la terminal
//! de esa pestaña. Sin conexión real: la terminal es un canal que la prueba lee.

use super::*;
use crate::app::Tab;
use crate::session::{SessionStatus, TerminalSession};
use tokio::sync::mpsc;
use tunel_core::io::{SessionInput, SessionIo, SessionOutput};
use tunel_core::model::{Host, Identity};

fn tab(title: &'static str) -> By<'static> {
    by().role(egui::accesskit::Role::Tab).label(title)
}

/// La app con una terminal abierta del host «sw-core», cuya identidad tiene `enable`. Devuelve
/// lo que la app escribe en esa terminal.
fn switch_open(enable: Option<&str>) -> (TestApp, mpsc::UnboundedReceiver<SessionInput>) {
    let mut identity = Identity::new("Switches", "admin").with_password("cisco");
    identity.enable_password = enable.map(str::to_string);
    let host = Host {
        identity: Some(identity.id),
        ..Host::new("sw-core", "10.0.0.1")
    };
    let id = host.id;
    let data = VaultData::default().with_identity(identity).with_host(host);
    let mut app = TestApp::unlocked(data);
    let (input, typed) = mpsc::unbounded_channel();
    let (_backend, output) = mpsc::unbounded_channel::<SessionOutput>();
    let mut session = TerminalSession::new(
        "sw-core".into(),
        Some(id),
        80,
        24,
        100,
        SessionIo { input, output },
    );
    session.status = SessionStatus::Connected;
    app.harness
        .state_mut()
        .push_tab(Tab::Terminal(Box::new(session)));
    app.settle();
    (app, typed)
}

fn sent(typed: &mut mpsc::UnboundedReceiver<SessionInput>) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Ok(input) = typed.try_recv() {
        if let SessionInput::Data(data) = input {
            bytes.extend(data);
        }
    }
    bytes
}

#[test]
fn the_tab_menu_types_the_enable_password_and_enter() {
    let (mut app, mut typed) = switch_open(Some("en4ble"));
    app.get(&tab("sw-core")).click_secondary();
    app.settle();
    app.click(&button("Enviar contraseña enable"));
    assert_eq!(sent(&mut typed), b"en4ble\r");
}

#[test]
fn the_shortcut_sends_it_to_the_active_tab() {
    let (mut app, mut typed) = switch_open(Some("en4ble"));
    app.key(
        egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
        egui::Key::E,
    );
    assert_eq!(sent(&mut typed), b"en4ble\r");
}

#[test]
fn without_an_enable_password_nothing_is_typed_and_it_says_why() {
    let (mut app, mut typed) = switch_open(None);
    app.key(
        egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
        egui::Key::E,
    );
    assert!(sent(&mut typed).is_empty(), "nunca la contraseña normal");
    let notices: Vec<String> = app
        .harness
        .state()
        .notices
        .iter()
        .map(|(_, n)| n.clone())
        .collect();
    assert!(
        notices
            .iter()
            .any(|n| n.contains("no tiene contraseña enable")),
        "{notices:?}"
    );
}

#[test]
fn a_local_terminal_has_no_enable_option() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.harness.state_mut().open_local();
    let last = app.harness.state().tabs.len() - 1;
    app.harness.state_mut().tabs[last].set_title("local".into());
    app.settle();
    app.get(&tab("local")).click_secondary();
    app.settle();
    assert!(!app.exists(&button("Enviar contraseña enable")));
    app.harness.state_mut().close_tab(last);
}

#[test]
fn a_new_identity_keeps_its_enable_password() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Llavero"));
    app.click(&button("Identidad"));
    app.fill(&field("Nombre"), "Switches");
    app.fill(&field("Usuario"), "admin");
    app.fill(&field("Contraseña enable"), "en4ble");
    app.harness.check_accessibility();
    app.click(&button("Guardar"));
    let saved = app.lock_and_read();
    let identity = &saved.identities[0];
    assert_eq!(identity.enable_password.as_deref(), Some("en4ble"));
    assert!(identity.password.is_none());
}
