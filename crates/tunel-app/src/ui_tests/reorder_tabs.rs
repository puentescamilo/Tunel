//! Cambiar de sitio las pestañas de la barra: arrastrándolas o desde su menú.

use super::panes::{menu, panes, tab, terminals};
use super::*;

/// Los nombres de las pestañas en el orden de la barra.
fn order(app: &TestApp) -> Vec<String> {
    app.harness
        .state()
        .tabs
        .iter()
        .map(|t| t.title().to_string())
        .collect()
}

#[test]
fn the_menu_moves_a_tab_one_place_left_or_right() {
    let mut app = terminals(3);
    menu(&mut app, "uno", "Mover a la derecha");
    assert_eq!(order(&app), ["dos", "uno", "tres"]);

    menu(&mut app, "tres", "Mover a la izquierda");
    assert_eq!(order(&app), ["dos", "tres", "uno"]);
    // «tres» era la activa y lo sigue siendo en su sitio nuevo.
    assert_eq!(app.harness.state().active, Some(1));
}

#[test]
fn the_ends_of_the_bar_only_offer_the_way_that_is_left() {
    let mut app = terminals(2);
    app.get(&tab("uno")).click_secondary();
    app.settle();
    assert!(!app.exists(&button("Mover a la izquierda")));
    assert!(app.exists(&button("Mover a la derecha")));
    app.key(egui::Modifiers::NONE, egui::Key::Escape);

    app.get(&tab("dos")).click_secondary();
    app.settle();
    assert!(app.exists(&button("Mover a la izquierda")));
    assert!(!app.exists(&button("Mover a la derecha")));
}

#[test]
fn the_split_view_keeps_its_tabs_when_they_move() {
    let mut app = terminals(3);
    menu(&mut app, "uno", "Dividir a la derecha");
    let titles = |app: &TestApp| -> Vec<String> {
        let state = app.harness.state();
        panes(app)
            .into_iter()
            .map(|i| state.tabs[i].title().to_string())
            .collect()
    };
    assert_eq!(titles(&app), ["tres", "uno"]);

    menu(&mut app, "tres", "Mover a la izquierda");
    menu(&mut app, "tres", "Mover a la izquierda");
    assert_eq!(order(&app), ["tres", "uno", "dos"]);
    assert_eq!(titles(&app), ["tres", "uno"]);
    assert_eq!(
        app.harness.state().tabs[app.harness.state().active.unwrap()].title(),
        "uno"
    );
}

#[test]
fn a_tab_dragged_past_another_takes_its_place() {
    let mut app = terminals(3);
    let from = app.get(&tab("uno")).rect().center();
    let past = app.get(&tab("tres")).rect().center() + egui::vec2(20.0, 0.0);

    let input = |app: &mut TestApp, event: egui::Event| {
        app.harness.input_mut().events.push(event);
        app.harness.step();
    };
    let button = |pos, pressed| egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    input(&mut app, egui::Event::PointerMoved(from));
    input(&mut app, button(from, true));
    for step in 1..=10 {
        let pos = from.lerp(past, step as f32 / 10.0);
        input(&mut app, egui::Event::PointerMoved(pos));
    }
    input(&mut app, button(past, false));
    app.settle();

    assert_eq!(order(&app), ["dos", "tres", "uno"]);
}
