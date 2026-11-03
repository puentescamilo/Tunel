//! Vista dividida y ventanas desacopladas, desde el menú de clic derecho de las pestañas.

use super::*;
use crate::layout::{Direction, Layout};
use egui_kittest::kittest::NodeT;

/// La app con `n` terminales locales llamadas «uno», «dos»…; la última, activa.
fn terminals(n: usize) -> TestApp {
    const NAMES: [&str; 5] = ["uno", "dos", "tres", "cuatro", "cinco"];
    let mut app = TestApp::unlocked(VaultData::default());
    for name in &NAMES[..n] {
        app.harness.state_mut().open_local();
        let last = app.harness.state().tabs.len() - 1;
        app.harness.state_mut().tabs[last].set_title(name.to_string());
    }
    app.settle();
    app
}

fn tab(title: &'static str) -> By<'static> {
    by().role(egui::accesskit::Role::Tab).label(title)
}

/// Abre el menú de la pestaña y elige `option`.
fn menu(app: &mut TestApp, title: &'static str, option: &'static str) {
    app.get(&tab(title)).click_secondary();
    app.settle();
    app.click(&button(option));
}

fn panes(app: &TestApp) -> Vec<usize> {
    app.harness
        .state()
        .layout
        .as_ref()
        .map(Layout::panes)
        .unwrap_or_default()
}

#[test]
fn a_tab_is_split_to_the_right_of_the_one_in_view() {
    let mut app = terminals(2);
    menu(&mut app, "uno", "Dividir a la derecha");
    // «dos» estaba a la vista; «uno» queda a su derecha y con el foco.
    assert_eq!(panes(&app), [1, 0]);
    assert_eq!(app.harness.state().active, Some(0));
    // Las dos pestañas se marcan como a la vista.
    for title in ["uno", "dos"] {
        let selected = app.get(&tab(title)).accesskit_node().toggled();
        assert_eq!(selected, Some(egui::accesskit::Toggled::True), "{title}");
    }
    app.harness.check_accessibility();
}

#[test]
fn up_to_four_tabs_share_the_screen() {
    let mut app = terminals(5);
    menu(&mut app, "uno", "Dividir a la derecha");
    menu(&mut app, "dos", "Dividir abajo");
    menu(&mut app, "tres", "Dividir abajo");
    assert_eq!(panes(&app).len(), 4);
    // La quinta ya no cabe: la opción se ve, pero no se puede usar.
    app.get(&tab("cuatro")).click_secondary();
    app.settle();
    let full = button("Dividir (como mucho 4)");
    assert!(app.get(&full).accesskit_node().is_disabled());
    assert!(!app.exists(&button("Dividir a la derecha")));
}

#[test]
fn removing_a_pane_or_closing_its_tab_gives_the_space_back() {
    let mut app = terminals(3);
    menu(&mut app, "uno", "Dividir a la derecha");
    menu(&mut app, "dos", "Dividir abajo");
    assert_eq!(panes(&app).len(), 3);
    menu(&mut app, "dos", "Quitar de la vista dividida");
    assert_eq!(panes(&app).len(), 2);
    assert!(!panes(&app).contains(&1));
    // Al cerrar una de las dos que quedan, la vista deja de estar dividida y se ve la otra.
    let closing = app.harness.state().active.unwrap();
    app.harness.state_mut().close_tab(closing);
    app.settle();
    assert!(app.harness.state().layout.is_none());
    assert_eq!(app.harness.state().tabs.len(), 2);
    assert!(app.harness.state().active.is_some());
}

#[test]
fn closing_a_tab_before_the_panes_keeps_them_pointing_at_the_same_terminals() {
    let mut app = terminals(3);
    // «tres» a la vista, «dos» a su derecha.
    menu(&mut app, "dos", "Dividir a la derecha");
    app.harness.state_mut().close_tab(0);
    app.settle();
    let titles: Vec<String> = panes(&app)
        .into_iter()
        .map(|t| app.harness.state().tabs[t].title().to_string())
        .collect();
    assert_eq!(titles, ["tres", "dos"]);
}

#[test]
fn a_tab_opens_in_its_own_window_and_comes_back() {
    let mut app = terminals(2);
    menu(&mut app, "dos", "Abrir en otra ventana");
    assert_eq!(app.harness.state().detached_tabs(), [1]);
    // La principal enseña la otra; la desacoplada sigue teniendo su pestaña aquí.
    assert_eq!(app.harness.state().active, Some(0));
    assert!(app.exists(&tab("dos")));
    // Sin ventanas del sistema en las pruebas, egui la dibuja como una ventana interna.
    assert!(app.exists(&text("dos — Túnel")));
    app.harness.check_accessibility();

    // La ventana interna tapa la barra de pestañas; con ventanas de verdad no pasa.
    crate::panes::apply(app.harness.state_mut(), 1, crate::panes::Place::Attach);
    app.settle();
    assert!(app.harness.state().detached.is_empty());
    assert_eq!(app.harness.state().active, Some(1));
    assert!(!app.exists(&text("dos — Túnel")));
}

#[test]
fn a_detached_tab_leaves_the_split_view() {
    let mut app = terminals(3);
    menu(&mut app, "uno", "Dividir a la derecha");
    menu(&mut app, "uno", "Abrir en otra ventana");
    assert!(
        app.harness.state().layout.is_none(),
        "con un solo panel no hay división"
    );
    assert_eq!(app.harness.state().detached_tabs(), [0]);
    assert_eq!(app.harness.state().active, Some(2));
    // Y se puede volver a dividir con ella desde la principal.
    let state = app.harness.state_mut();
    state.split_with(0, Direction::Down);
    assert_eq!(panes(&app), [2, 0]);
    assert!(app.harness.state().detached.is_empty());
}

#[test]
fn locking_closes_the_panes_and_the_windows() {
    let mut app = terminals(3);
    menu(&mut app, "uno", "Dividir a la derecha");
    menu(&mut app, "dos", "Abrir en otra ventana");
    app.click(&button("Bloquear bóveda"));
    assert!(app.harness.state().layout.is_none());
    assert!(app.harness.state().detached.is_empty());
}

#[test]
fn closing_one_detached_tab_keeps_the_other_windows() {
    let mut app = terminals(3);
    menu(&mut app, "uno", "Abrir en otra ventana");
    // La ventana interna de «uno» tapa la barra de pestañas (con ventanas de verdad no pasa).
    crate::panes::apply(app.harness.state_mut(), 1, crate::panes::Place::Detach);
    app.settle();
    let windows: Vec<_> = app
        .harness
        .state()
        .detached
        .iter()
        .map(|d| d.window)
        .collect();
    app.harness.state_mut().close_tab(0);
    app.settle();
    // «dos» pasa a ser la pestaña 0, en la misma ventana de antes.
    let state = app.harness.state();
    assert_eq!(state.detached_tabs(), [0]);
    assert_eq!(state.detached[0].window, windows[1]);
    assert_eq!(state.tabs[0].title(), "dos");
    assert!(app.exists(&text("dos — Túnel")));
    assert!(!app.exists(&text("uno — Túnel")));
}

#[test]
fn renaming_follows_its_tab_when_another_closes() {
    let mut app = terminals(3);
    menu(&mut app, "tres", "Renombrar");
    app.harness.state_mut().close_tab(0);
    app.settle();
    app.fill(&by().role(egui::accesskit::Role::TextInput), "producción");
    app.click(&button("Guardar"));
    let titles: Vec<String> = app
        .harness
        .state()
        .tabs
        .iter()
        .map(|t| t.title().to_string())
        .collect();
    assert_eq!(titles, ["dos", "producción"]);
}
