//! Un equipo nuevo entra con la cuenta desde la pantalla de bienvenida.

use super::*;
use tunel_core::Host;
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::ServerUrl;
use zeroize::Zeroizing;

pub(super) const EMAIL: &str = "ana@ejemplo.com";
pub(super) const ACCOUNT_PASSWORD: &str = "Cuenta-de-prueba-2026";

/// Un servidor en memoria con una cuenta que ya tiene el host «web-01», como si se hubiera
/// creado en otro equipo. El runtime se devuelve para que el servidor siga en marcha.
pub(super) fn server_with_account() -> (tokio::runtime::Runtime, ServerUrl) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(async {
        let config = Config {
            auth_kdf: KdfParams::FAST_FOR_TESTS,
            open_registration: true,
            unauthenticated_burst: 1000,
            ..Config::default()
        };
        let state = AppState::new(Db::open_in_memory().unwrap(), config)
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        let server = tunel_sync::check_server_url(&format!("http://{address}")).unwrap();
        let data = VaultData::default().with_host(Host::new("web-01", "10.0.0.1"));
        let local = tunel_sync::create_account(
            &server,
            EMAIL,
            Zeroizing::new(ACCOUNT_PASSWORD.into()),
            &data,
        )
        .await
        .unwrap();
        tunel_sync::sync_once(&local, &data).await.unwrap();
        server
    });
    (runtime, server)
}

pub(super) fn sign_in(app: &mut TestApp, server: &ServerUrl, password: &str) {
    app.click(&button("Entrar con tu cuenta"));
    assert!(app.exists(&text("Entra con tu cuenta")));
    app.harness.check_accessibility();
    app.fill(&field("Servidor"), &server.base);
    app.fill(&field("Correo de la cuenta"), EMAIL);
    app.fill(&field("Contraseña de la cuenta"), password);
    app.click(&button("Entrar"));
}

/// Deja correr la app hasta que se cumpla `done`, con un tope.
pub(super) fn wait_for(app: &mut TestApp, mut done: impl FnMut(&TestApp) -> bool) -> bool {
    for _ in 0..200 {
        if done(app) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        app.settle();
    }
    false
}

#[test]
fn a_new_computer_signs_in_and_gets_its_hosts() {
    let (_runtime, server) = server_with_account();
    let mut app = TestApp::first_run();

    sign_in(&mut app, &server, ACCOUNT_PASSWORD);

    let synced = wait_for(&mut app, |app| {
        app.harness
            .state()
            .data()
            .is_some_and(|d| d.hosts.iter().any(|h| h.label == "web-01"))
    });
    assert!(
        synced,
        "no llegaron los hosts; en pantalla: {:?}",
        app.visible_text()
    );
    // La bóveda de este equipo se abre con la contraseña de la cuenta.
    app.harness.state_mut().lock_vault();
    app.settle();
    assert!(UnlockedVault::unlock(app.path.clone(), ACCOUNT_PASSWORD).is_ok());
}

#[test]
fn a_wrong_password_creates_no_vault() {
    let (_runtime, server) = server_with_account();
    let mut app = TestApp::first_run();

    sign_in(&mut app, &server, "No-es-la-contraseña-1");

    let failed = wait_for(&mut app, |app| app.harness.state().join.error.is_some());
    assert!(failed, "no avisó; en pantalla: {:?}", app.visible_text());
    assert!(app.harness.state().vault.is_none());
    assert!(!UnlockedVault::exists(&app.path));
    // Se puede volver a la bóveda nueva.
    app.click(
        &by()
            .role(egui::accesskit::Role::Link)
            .label("Volver y empezar con una bóveda nueva"),
    );
    assert!(app.exists(&text("Bienvenido a Túnel")));
}
