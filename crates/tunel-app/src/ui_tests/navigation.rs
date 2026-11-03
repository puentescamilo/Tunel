//! El menú lateral lleva a cada sección, y todas se pueden manejar con un lector de pantalla.

use super::*;
use crate::app::Section;

#[test]
fn every_section_opens_from_the_menu_and_names_its_controls() {
    let mut app = TestApp::unlocked(VaultData::default());
    let sections = Section::ALL.into_iter().chain([Section::Containers]);
    for section in sections {
        app.click(&button(section.label()));
        assert_eq!(app.harness.state().section, section);
        let title = by()
            .label(section.label())
            .role(egui::accesskit::Role::Label);
        assert!(app.exists(&title), "no se ve el título de {section:?}");
        // Ningún control sin nombre: ni un lector de pantalla ni estas pruebas lo encontrarían.
        app.harness.check_accessibility();
    }
}

#[test]
fn the_menu_shows_how_many_items_each_section_has() {
    let data = VaultData::default()
        .with_host(tunel_core::Host::new("web-01", "web-01.ejemplo.com"))
        .with_host(tunel_core::Host::new("db-01", "db-01.ejemplo.com"));
    let app = TestApp::unlocked(data);
    assert!(app.exists(&text("2 hosts · 0 grupos")));
    assert!(app.exists(&button("web-01, ssh · web-01.ejemplo.com")));
}
