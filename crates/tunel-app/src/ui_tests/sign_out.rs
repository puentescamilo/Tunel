//! Cerrar sesión en este equipo: se borra la bóveda local y se vuelve a la bienvenida.

use super::join::{ACCOUNT_PASSWORD, EMAIL, server_with_account, sign_in, wait_for};
use super::*;
use tunel_core::Host;

const CONFIRM: &str = "Cerrar sesión y borrar";

fn open_dialog(app: &mut TestApp) {
    app.click(&button("Ajustes"));
    app.click(&button("Cerrar sesión…"));
    assert!(app.exists(&text("Cerrar sesión en este equipo")));
}

fn confirm(app: &mut TestApp, password: &str) {
    app.fill(&field("Contraseña maestra"), password);
    app.click(&button(CONFIRM));
}

#[test]
fn a_computer_with_an_account_signs_out_and_back_in() {
    let (_runtime, server) = server_with_account();
    let mut app = TestApp::first_run();
    sign_in(&mut app, &server, ACCOUNT_PASSWORD);
    let has_hosts = |app: &TestApp| {
        app.harness
            .state()
            .data()
            .is_some_and(|d| d.hosts.iter().any(|h| h.label == "web-01"))
    };
    assert!(wait_for(&mut app, has_hosts), "no llegaron los hosts");

    open_dialog(&mut app);
    let account = by().predicate(|n| n.value().is_some_and(|v| v.contains(EMAIL)));
    assert!(app.exists(&account), "no dice qué cuenta se desconecta");
    app.harness.check_accessibility();
    confirm(&mut app, ACCOUNT_PASSWORD);

    let closed = wait_for(&mut app, |app| app.harness.state().vault.is_none());
    assert!(closed, "no se cerró; en pantalla: {:?}", app.visible_text());
    // Unos fotogramas más: ni la sincronización que quedara en marcha vuelve a crearla.
    app.settle();
    app.settle();
    assert!(!UnlockedVault::exists(&app.path));
    assert!(app.exists(&text("Bienvenido a Túnel")));

    // Se vuelve a entrar con la misma cuenta y vuelven los hosts.
    sign_in(&mut app, &server, ACCOUNT_PASSWORD);
    assert!(wait_for(&mut app, has_hosts), "no volvieron los hosts");
}

#[test]
fn without_an_account_it_warns_that_the_vault_is_lost_for_good() {
    let mut app = TestApp::unlocked(VaultData::default().with_host(Host::new("web", "10.0.0.1")));
    open_dialog(&mut app);
    assert!(app.exists(&text(
        "Este equipo no está unido a ninguna cuenta: la bóveda se borrará para siempre y no \
         se podrá recuperar."
    )));

    confirm(&mut app, "No-es-la-contraseña-1");
    let refused = wait_for(&mut app, |app| {
        app.exists(&text("La contraseña maestra no es correcta"))
    });
    assert!(refused, "no avisó de la contraseña");
    assert!(app.harness.state().vault.is_some());

    app.click(&button("Cancelar"));
    assert!(app.harness.state().sign_out.is_none());
    assert!(UnlockedVault::exists(&app.path));
}

#[test]
fn after_signing_out_a_new_vault_can_be_created() {
    let mut app = TestApp::unlocked(VaultData::default().with_host(Host::new("web", "10.0.0.1")));
    open_dialog(&mut app);
    confirm(&mut app, PASSWORD);
    assert!(wait_for(&mut app, |app| app
        .harness
        .state()
        .vault
        .is_none()));
    let leftovers: Vec<_> = std::fs::read_dir(app.path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(leftovers.is_empty(), "quedaron archivos: {leftovers:?}");

    let fresh = UnlockedVault::create(
        app.path.clone(),
        "Otra-contraseña-2026",
        KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    assert!(fresh.data.hosts.is_empty());
}
