//! Contra un Vaultwarden de verdad, con una cuenta de prueba sin segundo factor:
//!
//! ```sh
//! TUNEL_VW_URL=https://vault.example.com TUNEL_VW_EMAIL=pruebas@example.com \
//! TUNEL_VW_PASSWORD=... cargo test -p tunel-vaultwarden --test servidor
//! ```
//!
//! Con `TUNEL_VW_COLECCION` (el nombre de una colección en la que la cuenta puede escribir)
//! también se prueba crear en una organización. Sin `TUNEL_VW_URL` la prueba avisa y no hace
//! nada. Borra lo que crea.
//!
//! Es una sola prueba que inicia sesión una vez: Vaultwarden limita los inicios de sesión por
//! minuto y con varias en paralelo responde 429.

use tunel_vaultwarden::*;

struct Account {
    server: ServerUrl,
    email: String,
    password: String,
}

fn account() -> Option<Account> {
    let Ok(url) = std::env::var("TUNEL_VW_URL") else {
        eprintln!("aviso: sin TUNEL_VW_URL no se prueba contra Vaultwarden");
        return None;
    };
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("falta {name}"));
    Some(Account {
        server: check_server_url(&url).expect("TUNEL_VW_URL válida"),
        email: var("TUNEL_VW_EMAIL"),
        password: var("TUNEL_VW_PASSWORD"),
    })
}

/// Siempre el mismo, para no llenar la lista de dispositivos de la cuenta.
fn device() -> Device {
    Device {
        id: "6f1d6b8e-2c1a-4d7e-9a43-7c3e0b5d9a10".into(),
        name: "Túnel (pruebas)".into(),
    }
}

fn new_login() -> NewLogin {
    NewLogin {
        name: format!("Túnel prueba {}", uuid::Uuid::new_v4()),
        username: Some("admin".into()),
        password: Some("contraseña-ñ-€".into()),
        uris: vec!["ssh://10.255.0.1:2222".into()],
        notes: Some("creado por las pruebas de Túnel; se borra solo".into()),
        fields: vec![Field {
            name: "enable".into(),
            value: "en4ble".into(),
            hidden: true,
        }],
    }
}

#[tokio::test]
async fn against_a_real_vaultwarden() {
    let Some(account) = account() else { return };
    a_wrong_password_is_rejected(&account).await;

    let mut session = Credentials::new(&account.server, &account.email, &account.password)
        .await
        .expect("parámetros de derivación")
        .sign_in(&device(), None)
        .await
        .expect("inicia sesión");
    let vault = session.sync().await.expect("sincroniza");
    assert!(vault.unreadable.is_empty(), "{:?}", vault.unreadable);

    a_login_created_from_tunel_reads_back_the_same_and_is_deleted(&mut session, &vault).await;
    a_login_can_go_to_an_organization_collection(&mut session, &vault).await;
    a_saved_session_resumes_without_the_password(&account, &session).await;
}

async fn a_wrong_password_is_rejected(account: &Account) {
    let result = Credentials::new(&account.server, &account.email, "no-es-la-contraseña")
        .await
        .unwrap()
        .sign_in(&device(), None)
        .await;
    assert!(
        matches!(result, Err(VwError::Rejected(_))),
        "{:?}",
        result.err()
    );
}

/// Crea, sincroniza, comprueba que se lee igual, borra y comprueba que ya no está.
async fn create_read_and_delete(session: &mut Session, vault: &Vault, place: &Place) -> Item {
    let sent = new_login();
    let id = session
        .create_login(vault, &sent, place)
        .await
        .expect("crea el elemento");
    let synced = session.sync().await.expect("sincroniza después de crear");
    session.delete_item(&id).await.expect("borra el elemento");
    assert!(
        session.sync().await.unwrap().item(&id).is_none(),
        "se borró"
    );

    let item = synced
        .item(&id)
        .expect("el elemento creado aparece al sincronizar");
    assert_eq!(item.name, sent.name);
    assert_eq!(item.notes, sent.notes);
    assert_eq!(
        item.content,
        Content::Login {
            username: sent.username.clone(),
            password: sent.password.clone(),
            uris: sent.uris.clone(),
        }
    );
    let enable = item.field("enable").expect("campo enable");
    assert!(enable.hidden && enable.value == "en4ble");
    item.clone()
}

async fn a_login_created_from_tunel_reads_back_the_same_and_is_deleted(
    session: &mut Session,
    vault: &Vault,
) {
    if vault.personal_vault_disabled {
        eprintln!(
            "aviso: una organización quita la bóveda individual; no se prueba crear en la \
             personal"
        );
        return;
    }
    let item = create_read_and_delete(session, vault, &Place::Personal).await;
    assert_eq!(item.organization_id, None, "va a la bóveda personal");
}

async fn a_login_can_go_to_an_organization_collection(session: &mut Session, vault: &Vault) {
    let Ok(name) = std::env::var("TUNEL_VW_COLECCION") else {
        eprintln!("aviso: sin TUNEL_VW_COLECCION no se prueba crear en una organización");
        return;
    };
    let collection = vault
        .collections
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| {
            let seen: Vec<&str> = vault.collections.iter().map(|c| c.name.as_str()).collect();
            panic!(
                "no hay una colección «{name}»; la cuenta ve {seen:?} en {} organizaciones",
                vault.organizations.len()
            )
        });
    let place = Place::Organization {
        organization_id: collection.organization_id.clone(),
        collection_ids: vec![collection.id.clone()],
    };
    let item = create_read_and_delete(session, vault, &place).await;
    assert_eq!(
        item.organization_id.as_ref(),
        Some(&collection.organization_id)
    );
    assert_eq!(item.collection_ids, std::slice::from_ref(&collection.id));
}

async fn a_saved_session_resumes_without_the_password(account: &Account, session: &Session) {
    let refresh = session.refresh_token().to_string();
    let mut resumed = Session::restore(
        &account.server,
        device(),
        &refresh,
        session.user_key().clone(),
    )
    .unwrap();
    resumed
        .sync()
        .await
        .expect("sincroniza con el token renovado");

    let wrong = SymmetricKey::generate();
    let mut wrong_key = Session::restore(&account.server, device(), &refresh, wrong).unwrap();
    assert!(
        wrong_key.sync().await.is_err(),
        "otra clave no abre la bóveda"
    );

    let mut revoked = Session::restore(
        &account.server,
        device(),
        "no-vale",
        SymmetricKey::generate(),
    )
    .unwrap();
    assert!(matches!(revoked.sync().await, Err(VwError::SessionExpired)));
}
