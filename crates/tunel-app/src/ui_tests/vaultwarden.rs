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

/// Conecta la cuenta desde Ajustes y espera a la primera sincronización.
fn connect(app: &mut TestApp, account: &Account) {
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
    wait_for_vaultwarden(app);
    let status = app.harness.state().vaultwarden.status().clone();
    assert!(
        matches!(status, crate::vaultwarden::VwStatus::Ready { .. }),
        "{status:?}; en pantalla: {:?}",
        app.visible_text()
    );
    assert!(side_file(app).exists());
}

fn check_the_whole_flow(account: &Account, name: &str, item_id: &str) {
    let identity = Identity::new("Switches de prueba", "");
    let host = Host {
        identity: Some(identity.id),
        ..Host::new("sw-prueba", "10.255.0.9")
    };
    let host_id = host.id;
    let mut app = TestApp::unlocked(VaultData::default().with_identity(identity).with_host(host));

    connect(&mut app, account);

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

#[test]
fn a_password_moves_from_tunel_to_a_vaultwarden_collection() {
    let Some(account) = account() else { return };
    let password = format!("clave-{}", uuid::Uuid::new_v4());
    let identity = Identity::new("Router de prueba", "admin").with_password(password.clone());
    let identity_id = identity.id;
    let host = Host {
        identity: Some(identity.id),
        ..Host::new("router-prueba", "10.255.0.7")
    };
    let mut app = TestApp::unlocked(VaultData::default().with_identity(identity).with_host(host));
    connect(&mut app, &account);

    app.click(&button("Llavero"));
    app.click(&button("Editar"));
    assert!(app.exists(&text("Mover a Vaultwarden")));
    app.click(&combo("Destino"));
    let collection: &'static str = Box::leak(account.collection.clone().into_boxed_str());
    app.click(&by().label(collection).role(egui::accesskit::Role::Button));
    app.click(&button("Mover"));
    wait_for_vaultwarden(&mut app);

    let state = app.harness.state();
    let moved = state.data().unwrap().identity(identity_id).unwrap().clone();
    let link = moved.vaultwarden.clone();
    let secret = link
        .as_ref()
        .and_then(|l| state.engine.external_secrets.get(&l.item_id))
        .and_then(|s| s.password.clone());
    // «Guardar» en el editor que seguía abierto no devuelve la contraseña.
    app.click(&button("Guardar"));
    let saved = app.lock_and_read();

    if let Some(link) = &link {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut helper = helper_session(&runtime, &account);
        runtime
            .block_on(helper.delete_item(&link.item_id))
            .expect("borra el elemento de la prueba");
    }
    let link = link.expect("la identidad quedó vinculada");
    assert!(link.organization_id.is_some(), "va a la colección");
    assert!(moved.password.is_none(), "la contraseña sale de Túnel");
    assert_eq!(
        secret.as_deref(),
        Some(password.as_str()),
        "se conecta con ella"
    );
    let saved_identity = saved.identity(identity_id).unwrap();
    assert!(saved_identity.password.is_none());
    assert_eq!(saved_identity.vaultwarden.as_ref(), Some(&link));
    assert!(
        !serde_json::to_string(&saved).unwrap().contains(&password),
        "la contraseña no queda en la bóveda"
    );
}

#[test]
fn hosts_are_imported_from_the_items_of_a_real_vaultwarden() {
    let Some(account) = account() else { return };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut helper = helper_session(&runtime, &account);
    let name: &'static str =
        Box::leak(format!("Túnel importar {}", uuid::Uuid::new_v4()).into_boxed_str());
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
            name: name.to_string(),
            username: Some("admin".into()),
            password: Some("importada".into()),
            uris: vec!["ssh://10.255.0.5:2222".into(), "https://10.255.0.5".into()],
            notes: Some("rack de pruebas".into()),
            fields: Vec::new(),
        };
        helper.create_login(&vault, &login, &place).await.unwrap()
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut app = TestApp::unlocked(VaultData::default());
        connect(&mut app, &account);
        app.click(&button("Importar de Vaultwarden…"));
        assert!(app.exists(&text("Importar de Vaultwarden")));
        app.click(&button("Ninguno"));
        app.fill(&placeholder("Buscar…"), name);
        app.click(
            &by()
                .role(egui::accesskit::Role::CheckBox)
                .predicate(move |n| n.label().is_some_and(|l| l.starts_with(name))),
        );
        app.click(&button("Importar (1)"));

        let state = app.harness.state();
        let data = state.data().unwrap();
        let host = data
            .hosts
            .iter()
            .find(|h| h.label == name)
            .expect("host importado");
        assert_eq!(
            (host.address.as_str(), host.port),
            ("10.255.0.5", Some(2222))
        );
        assert_eq!(host.notes, "rack de pruebas");
        let group = data.group(host.group.unwrap()).unwrap();
        assert_eq!(group.name, account.collection);
        assert_eq!(
            data.group(group.parent.unwrap()).unwrap().name,
            "Vaultwarden"
        );
        let (target, _) = state.engine.resolve(data, host.id).unwrap();
        let identity = target.identity.unwrap();
        assert_eq!(identity.username, "admin");
        assert_eq!(identity.password.as_deref(), Some("importada"));
        assert_eq!(data.hosts.len(), 1, "solo lo elegido");
    }));
    runtime
        .block_on(helper.delete_item(&item_id))
        .expect("borra el elemento de la prueba");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
