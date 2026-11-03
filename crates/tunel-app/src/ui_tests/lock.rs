//! Crear la bóveda, desbloquearla y volver a bloquearla.

use super::*;

#[test]
fn the_first_run_creates_a_vault_with_a_strong_password() {
    let mut app = TestApp::first_run();
    assert!(app.exists(&text("Bienvenido a Túnel")));

    // Una contraseña débil no sirve, y se dice por qué.
    app.type_into(&placeholder("Contraseña maestra"), "corta");
    app.type_into(&placeholder("Repite la contraseña"), "corta");
    app.click(&button("Crear bóveda"));
    assert!(app.harness.state().vault.is_none());
    assert!(!UnlockedVault::exists(&app.path));
    assert!(
        app.exists(
            &by()
                .label_contains("12 caracteres")
                .role(egui::accesskit::Role::Label)
        )
    );
}

#[test]
fn both_passwords_must_match() {
    let mut app = TestApp::first_run();
    app.type_into(&placeholder("Contraseña maestra"), PASSWORD);
    app.type_into(&placeholder("Repite la contraseña"), "Otra-contraseña-2026");
    app.click(&button("Crear bóveda"));
    assert!(app.exists(&text("Las contraseñas no coinciden")));
    assert!(!UnlockedVault::exists(&app.path));
}

#[test]
fn creating_the_vault_opens_the_hosts() {
    let mut app = TestApp::first_run();
    app.type_into(&placeholder("Contraseña maestra"), PASSWORD);
    app.type_into(&placeholder("Repite la contraseña"), PASSWORD);
    app.click(&button("Crear bóveda"));
    assert!(app.harness.state().vault.is_some());
    assert!(app.exists(&text("0 hosts · 0 grupos")));
    // Queda en el disco y se abre con esa contraseña.
    assert!(app.lock_and_read().hosts.is_empty());
}

#[test]
fn a_wrong_password_does_not_unlock() {
    let mut app = TestApp::locked(VaultData::default());
    assert!(app.exists(&text("Desbloquea tu bóveda")));
    app.type_into(&placeholder("Contraseña maestra"), "No-es-la-buena-2026");
    app.click(&button("Desbloquear"));
    assert!(app.harness.state().vault.is_none());
    assert!(app.exists(&text("Contraseña incorrecta")));
    // Se borra lo escrito para el siguiente intento.
    assert_eq!(
        app.get(&placeholder("Contraseña maestra"))
            .value()
            .as_deref(),
        Some("")
    );
}

#[test]
fn enter_unlocks_like_the_button() {
    let mut app = TestApp::locked(VaultData::default());
    app.type_into(&placeholder("Contraseña maestra"), PASSWORD);
    app.key(egui::Modifiers::NONE, egui::Key::Enter);
    assert!(app.harness.state().vault.is_some());
}

#[test]
fn locking_returns_to_the_lock_screen_and_forgets_the_vault() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Bloquear bóveda"));
    assert!(app.harness.state().vault.is_none());
    assert!(app.exists(&text("Desbloquea tu bóveda")));
}
