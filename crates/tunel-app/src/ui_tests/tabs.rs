//! Pestañas: la conexión rápida, una terminal local y cerrarlas.

use super::*;
use crate::app::{Tab, TabState};
use std::time::{Duration, Instant};
use tunel_core::Host;

const SHORTCUT: egui::Modifiers = egui::Modifiers::COMMAND.plus(egui::Modifiers::SHIFT);

fn tab(title: &'static str) -> By<'static> {
    by().role(egui::accesskit::Role::Tab).label(title)
}

/// Hasta que la primera pestaña llegue a `state`, con un límite para no colgar la prueba.
fn wait_for(app: &mut TestApp, state: TabState) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while app.harness.state().tabs.first().map(Tab::state) != Some(state) {
        assert!(Instant::now() < deadline, "la pestaña no llegó a {state:?}");
        std::thread::sleep(Duration::from_millis(20));
        app.harness.step();
    }
    app.settle();
}

#[test]
fn quick_connect_finds_hosts_as_you_type() {
    let data = VaultData::default()
        .with_host(Host::new("web-01", "web-01.ejemplo.com"))
        .with_host(Host::new("db-01", "db-01.ejemplo.com"));
    let mut app = TestApp::unlocked(data);
    app.key(SHORTCUT, egui::Key::K);
    let search = placeholder("Buscar host o escribir usuario@servidor:puerto");
    assert!(
        app.get(&search).is_focused(),
        "el buscador no tiene el foco"
    );
    app.harness.check_accessibility();
    assert!(app.exists(&button("web-01, SSH · web-01.ejemplo.com")));

    app.type_into(&search, "db");
    assert!(app.exists(&button("db-01, SSH · db-01.ejemplo.com")));
    assert!(!app.exists(&button("web-01, SSH · web-01.ejemplo.com")));

    app.key(egui::Modifiers::NONE, egui::Key::Escape);
    assert!(app.harness.state().quick_connect.is_none());
    assert!(app.harness.state().tabs.is_empty());
}

#[test]
fn a_failed_connection_says_why_in_its_tab() {
    // Un puerto recién liberado: nadie escucha y la conexión falla enseguida.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let host = Host {
        port: Some(port),
        ..Host::new("apagado", "127.0.0.1")
    };
    let mut app = TestApp::unlocked(VaultData::default().with_host(host));
    app.key(SHORTCUT, egui::Key::K);
    app.key(egui::Modifiers::NONE, egui::Key::Enter);
    assert!(app.exists(&tab("apagado")));
    wait_for(&mut app, TabState::Failed);
    assert!(app.exists(&button("Reconectar")));
}

#[test]
fn a_local_terminal_opens_in_a_tab_and_closes() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Terminal local"));
    assert_eq!(app.harness.state().tabs.len(), 1);
    assert_eq!(app.harness.state().active, Some(0));
    wait_for(&mut app, TabState::Live);
    // Con una pestaña abierta, el menú se queda en iconos y sigue teniendo nombres.
    app.harness.check_accessibility();

    app.click(&button("Cerrar pestaña"));
    assert!(app.harness.state().tabs.is_empty());
    assert_eq!(app.harness.state().active, None);
    assert!(app.exists(&text("0 hosts · 0 grupos")));
}

#[test]
fn the_vault_tab_goes_back_to_the_sections() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Terminal local"));
    app.click(&tab("Bóveda"));
    assert_eq!(app.harness.state().active, None);
    assert_eq!(
        app.harness.state().tabs.len(),
        1,
        "la terminal sigue abierta"
    );
}
