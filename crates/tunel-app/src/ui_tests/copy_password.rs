//! Copiar la contraseña de un host sin verla.

use super::*;
use tunel_core::{Host, Identity};

const SECRET: &str = "secreto-de-prueba";

fn host_with_password() -> VaultData {
    let identity = Identity::new("Producción", "despliegue").with_password(SECRET);
    let host = Host {
        identity: Some(identity.id),
        ..Host::new("web-01", "web-01.ejemplo.com")
    };
    VaultData::default().with_identity(identity).with_host(host)
}

fn open_editor(app: &mut TestApp) {
    app.harness
        .get(
            by().role(egui::accesskit::Role::Button)
                .predicate(|n| n.label().is_some_and(|l| l.starts_with("web-01, "))),
        )
        .click_secondary();
    app.settle();
    app.click(&button("Editar"));
    assert!(app.exists(&text("Editar host")));
}

#[test]
fn the_password_is_copied_without_showing_it() {
    let mut app = TestApp::unlocked(host_with_password());
    crate::clipboard::tests::take_copied();
    open_editor(&mut app);
    app.harness.check_accessibility();

    app.click(&button("Copiar contraseña"));

    assert_eq!(
        crate::clipboard::tests::take_copied().as_deref(),
        Some(SECRET)
    );
    assert!(
        !app.visible_text().iter().any(|t| t.contains(SECRET)),
        "la contraseña quedó a la vista"
    );
    assert!(app.exists(&button("Mostrar")), "el ojo cambió de estado");
    assert!(
        app.visible_text()
            .iter()
            .any(|t| t.starts_with("Contraseña copiada")),
        "falta el aviso; en pantalla: {:?}",
        app.visible_text()
    );
}

#[test]
fn opening_the_host_copies_nothing() {
    let mut app = TestApp::unlocked(host_with_password());
    crate::clipboard::tests::take_copied();
    open_editor(&mut app);
    assert_eq!(crate::clipboard::tests::take_copied(), None);
    assert!(!app.visible_text().iter().any(|t| t.contains(SECRET)));
}
