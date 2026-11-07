//! Vaultwarden desde la interfaz. Sin cuenta, Túnel no cambia. La prueba contra un servidor
//! real es la única de la interfaz que sale a internet, y solo con `TUNEL_VW_URL`,
//! `TUNEL_VW_EMAIL`, `TUNEL_VW_PASSWORD` y `TUNEL_VW_COLECCION` (ver
//! `crates/tunel-vaultwarden/tests/servidor.rs`).

use super::*;
use std::time::{Duration, Instant};
use tunel_core::{Host, Identity};
use tunel_vaultwarden as vw;

#[test]
fn without_vaultwarden_the_identity_editor_is_the_same_as_always() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Llavero"));
    app.click(&button("Identidad"));
    assert!(app.exists(&field("Contraseña")));
    assert!(!app.exists(&text("Credencial")), "sin cuenta no se ofrece");
    app.click(&button("Cancelar"));

    app.click(&button("Ajustes"));
    assert!(app.exists(&text("Vaultwarden")));
    assert!(app.exists(&button("Conectar")));
    let state = app.harness.state();
    assert!(state.engine.external_secrets.is_empty());
    assert!(!side_file(&app).exists(), "sin cuenta no hay archivo");
}

fn side_file(app: &TestApp) -> std::path::PathBuf {
    let mut name = app.path.file_name().unwrap().to_os_string();
    name.push(".vaultwarden");
    app.path.with_file_name(name)
}

struct Account {
    server: vw::ServerUrl,
    url: String,
    email: String,
    password: String,
    collection: String,
}

fn account() -> Option<Account> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let Some(url) = var("TUNEL_VW_URL") else {
        eprintln!("aviso: sin TUNEL_VW_URL no se prueba Vaultwarden desde la interfaz");
        return None;
    };
    Some(Account {
        server: vw::check_server_url(&url).unwrap(),
        url,
        email: var("TUNEL_VW_EMAIL").expect("falta TUNEL_VW_EMAIL"),
        password: var("TUNEL_VW_PASSWORD").expect("falta TUNEL_VW_PASSWORD"),
        collection: var("TUNEL_VW_COLECCION").expect("falta TUNEL_VW_COLECCION"),
    })
}

/// Una sesión aparte de la de la app, para preparar y limpiar el elemento de la prueba.
fn helper_session(runtime: &tokio::runtime::Runtime, account: &Account) -> vw::Session {
    let device = vw::Device {
        id: "6f1d6b8e-2c1a-4d7e-9a43-7c3e0b5d9a10".into(),
        name: "Túnel (pruebas)".into(),
    };
    runtime.block_on(async {
        vw::Credentials::new(&account.server, &account.email, &account.password)
            .await
            .unwrap()
            .sign_in(&device, None)
            .await
            .unwrap()
    })
}

/// Deja correr la app hasta que Vaultwarden termine lo que está haciendo.
fn wait_for_vaultwarden(app: &mut TestApp) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        app.harness.run_steps(1);
        if !app.harness.state().vaultwarden.busy() {
            app.settle();
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Vaultwarden no respondió a tiempo"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn an_identity_uses_a_credential_from_a_real_vaultwarden() {
    let Some(account) = account() else { return };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut helper = helper_session(&runtime, &account);
    let name = format!("Túnel interfaz {}", uuid::Uuid::new_v4());
    let item_id = runtime.block_on(async {
        let vault = helper.sync().await.unwrap();
        let collection = vault
            .collections
            .iter()
            .find(|c| c.name == account.collection)
            .expect("colección de pruebas");
        let place = vw::Place::Organization {
            organization_id: collection.organization_id.clone(),
            collection_ids: vec![collection.id.clone()],
        };
        let login = vw::NewLogin {
            name: name.clone(),
            username: Some("admin".into()),
            password: Some("cisco-de-prueba".into()),
            uris: vec!["ssh://10.255.0.9".into()],
            notes: None,
            fields: Vec::new(),
        };
        helper.create_login(&vault, &login, &place).await.unwrap()
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_the_whole_flow(&account, &name, &item_id)
    }));
    runtime
        .block_on(helper.delete_item(&item_id))
        .expect("borra el elemento de la prueba");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn check_the_whole_flow(account: &Account, name: &str, item_id: &str) {
    let identity = Identity::new("Switches de prueba", "");
    let host = Host {
        identity: Some(identity.id),
        ..Host::new("sw-prueba", "10.255.0.9")
    };
    let host_id = host.id;
    let mut app = TestApp::unlocked(VaultData::default().with_identity(identity).with_host(host));

    // Conectar la cuenta desde Ajustes.
    app.click(&button("Ajustes"));
    app.fill(
        &placeholder("Servidor, por ejemplo https://vault.tuempresa.com"),
        &account.url,
    );
    app.fill(
        &placeholder("Correo de tu cuenta de Vaultwarden"),
        &account.email,
    );
    app.fill(
        &placeholder("Contraseña maestra de Vaultwarden"),
        &account.password,
    );
    app.click(&button("Conectar"));
    wait_for_vaultwarden(&mut app);
    let status = app.harness.state().vaultwarden.status().clone();
    assert!(
        matches!(status, crate::vaultwarden::VwStatus::Ready { .. }),
        "{status:?}; en pantalla: {:?}",
        app.visible_text()
    );
    assert!(side_file(&app).exists());

    // Vincular la identidad al elemento, buscándolo por su nombre.
    app.click(&button("Llavero"));
    app.click(&button("Editar"));
    app.click(
        &by()
            .label("En Vaultwarden")
            .role(egui::accesskit::Role::RadioButton),
    );
    assert!(
        !app.exists(&field("Contraseña")),
        "la contraseña local desaparece"
    );
    app.click(&combo("Elemento"));
    app.fill(&placeholder("Buscar…"), name);
    let owned = name.to_string();
    app.click(&by().predicate(move |n| n.label().is_some_and(|l| l.starts_with(&owned))));
    app.click(&button("Guardar"));

    let state = app.harness.state();
    let saved = &state.data().unwrap().identities[0];
    let link = saved.vaultwarden.as_ref().expect("identidad vinculada");
    assert_eq!(link.item_id, item_id);
    assert!(link.organization_id.is_some());
    assert!(saved.password.is_none(), "el secreto no entra en la bóveda");

    // La conexión usa la contraseña de Vaultwarden y el usuario del elemento.
    let (target, _) = state
        .engine
        .resolve(state.data().unwrap(), host_id)
        .unwrap();
    let identity = target.identity.unwrap();
    assert_eq!(identity.password.as_deref(), Some("cisco-de-prueba"));
    assert_eq!(identity.username, "admin");

    // Al volver a entrar, la copia local está antes de que responda el servidor.
    let data = app.lock_and_read();
    assert!(
        !serde_json::to_string(&data)
            .unwrap()
            .contains("cisco-de-prueba"),
        "la bóveda no guarda el secreto"
    );
    app.type_into(&placeholder("Contraseña maestra"), PASSWORD);
    app.click(&button("Desbloquear"));
    let state = app.harness.state();
    assert_eq!(
        state.engine.external_secrets[item_id].password.as_deref(),
        Some("cisco-de-prueba")
    );
    wait_for_vaultwarden(&mut app);
    assert!(matches!(
        app.harness.state().vaultwarden.status(),
        crate::vaultwarden::VwStatus::Ready { .. }
    ));
}
