//! El color del borde de la pestaña activa, en Ajustes → Apariencia.

use super::panes::{tab, terminals};
use super::*;

fn swatch(name: &'static str) -> By<'static> {
    by().role(egui::accesskit::Role::RadioButton).label(name)
}

#[test]
fn every_tab_border_color_can_be_chosen_with_tabs_open() {
    let mut app = terminals(2);
    app.click(&tab("Bóveda"));
    app.click(&button("Ajustes"));
    for name in [
        "Turquesa", "Azul", "Morado", "Rosa", "Rojo", "Naranja", "Amarillo",
    ] {
        app.click(&swatch(name));
        assert!(
            app.harness
                .state()
                .data()
                .unwrap()
                .settings
                .tab_border
                .is_some()
        );
        app.click(&tab("uno"));
        app.click(&tab("Bóveda"));
    }
    app.click(&swatch(
        "Automático: blanco en fondos oscuros, gris en claros",
    ));
    assert_eq!(
        app.harness.state().data().unwrap().settings.tab_border,
        None
    );
    // Sigue guardado al bloquear y volver a abrir la bóveda.
    app.click(&swatch("Azul"));
    assert_eq!(
        app.lock_and_read().settings.tab_border,
        Some([0x5b, 0x9c, 0xff])
    );
}
