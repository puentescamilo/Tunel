//! Iniciar sesión con un proveedor de identidad de punta a punta: un `tunel-server` real,
//! un proveedor OpenID Connect falso y un «navegador» que sigue las redirecciones. La
//! sincronización se cifra con la contraseña maestra.

use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::sync::SyncLocal;
use tunel_core::vault::VaultData;
use tunel_server::oauth::ProviderConfig;
use tunel_server::{AppState, Config, Db, OAuthConfig, router};
use tunel_sync::oauth::{self, OAuthSignIn};
use tunel_sync::{
    ServerUrl, SyncError, check_server_url, create_account, sign_in as password_sign_in, sync_once,
};
use zeroize::Zeroizing;

const MASTER: &str = "Maestra-Fuerte-2026!";

type Claims = Arc<Mutex<Value>>;

/// Proveedor falso: publica su configuración y devuelve como ID token lo que haya en
/// `claims`, con el `nonce` que le llegó al autorizar.
async fn fake_idp() -> (String, Claims) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let claims: Claims = Arc::default();
    let discovery = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
    });
    let shared = claims.clone();
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move { Json(discovery) }),
        )
        .route(
            "/token",
            post(move |Form(_): Form<HashMap<String, String>>| async move {
                let payload = B64_URL.encode(shared.lock().unwrap().to_string());
                Json(json!({ "id_token": format!("e30.{payload}.firma") }))
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, claims)
}

struct World {
    server: ServerUrl,
    issuer: String,
    claims: Claims,
    /// El «navegador»: no sigue redirecciones solo, para poder pasar por el proveedor.
    browser: reqwest::Client,
}

async fn world() -> World {
    world_on(Db::open_in_memory().unwrap(), false).await
}

/// Un servidor sobre `db`; con `providers_only`, sin correo y contraseña.
async fn world_on(db: Db, providers_only: bool) -> World {
    let (issuer, claims) = fake_idp().await;
    let config = Config {
        providers_only,
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        unauthenticated_burst: 1000,
        allowed_domains: vec!["empresa.com".into()],
        oauth: Some(OAuthConfig {
            public_url: "https://tunel.empresa.com".into(),
            providers: vec![ProviderConfig {
                id: "google".into(),
                name: "Google".into(),
                issuer: issuer.clone(),
                client_id: "cliente".into(),
                client_secret: "secreto".into(),
                trusted_tenant: false,
            }],
            allow_http: true,
        }),
        ..Config::default()
    };
    let state = AppState::new(db, config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    World {
        server: check_server_url(&format!("http://{address}")).unwrap(),
        issuer,
        claims,
        browser: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

fn location(response: &reqwest::Response) -> String {
    response.headers()["location"].to_str().unwrap().to_string()
}

fn param(url: &str, name: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .unwrap()
        .1
        .into_owned()
}

impl World {
    /// Inicia sesión con Google como la persona `sub` con correo `email`.
    async fn sign_in(&self, sub: &str, email: &str) -> OAuthSignIn {
        self.attempt(sub, email, false).await.unwrap()
    }

    /// Como `sign_in`; con `link`, para pasar a Google la cuenta con contraseña.
    async fn attempt(&self, sub: &str, email: &str, link: bool) -> Result<OAuthSignIn, SyncError> {
        let providers = oauth::providers(&self.server).await.unwrap().providers;
        assert_eq!(providers.len(), 1);
        let provider = providers[0].clone();
        let start = if link {
            oauth::begin_link(&self.server, provider).await
        } else {
            oauth::begin(&self.server, provider).await
        }
        .unwrap();
        let url = start.url.clone();
        let waiting = tokio::spawn(start.wait());
        let back = self.browse(&url, sub, email).await;
        assert!(back.starts_with("http://127.0.0.1:"), "{back}");
        self.browser.get(&back).send().await.unwrap();
        waiting.await.unwrap()
    }

    /// El navegador: servidor → proveedor (que da el visto bueno) → servidor. Devuelve la
    /// dirección a la que el servidor manda de vuelta a Túnel.
    async fn browse(&self, url: &str, sub: &str, email: &str) -> String {
        let to_idp = self.browser.get(url).send().await.unwrap();
        let authorize = location(&to_idp);
        assert!(authorize.starts_with(&self.issuer));
        *self.claims.lock().unwrap() = json!({
            "iss": self.issuer,
            "aud": "cliente",
            "exp": 4_000_000_000_i64,
            "nonce": param(&authorize, "nonce"),
            "sub": sub,
            "email": email,
            "email_verified": true,
        });
        let callback = format!(
            "{}/v1/auth/google/callback?code=c&state={}",
            self.server.base,
            param(&authorize, "state")
        );
        location(&self.browser.get(&callback).send().await.unwrap())
    }

    /// Como `sign_in`, desde una app móvil: el servidor vuelve a `tunel://oauth`.
    async fn sign_in_app(&self, sub: &str, email: &str) -> Result<OAuthSignIn, SyncError> {
        let provider = oauth::providers(&self.server).await.unwrap().providers[0].clone();
        let start = oauth::begin_app(&self.server, provider).unwrap();
        let back = self.browse(&start.url.clone(), sub, email).await;
        assert!(back.starts_with(oauth::APP_REDIRECT), "{back}");
        start.finish(&back).await
    }
}

fn hosts(labels: &[&str]) -> VaultData {
    labels.iter().fold(VaultData::default(), |d, l| {
        d.with_host(Host::new(*l, "10.0.0.1"))
    })
}

async fn sync(local: &SyncLocal, data: &VaultData) -> (SyncLocal, VaultData) {
    let outcome = sync_once(local, data).await.unwrap();
    (outcome.local, outcome.data)
}

#[tokio::test]
async fn a_new_account_syncs_and_a_second_device_joins_with_the_master_password() {
    let w = world().await;
    let first = w.sign_in("ana-1", "ana@empresa.com").await;
    assert!(first.is_new());
    assert_eq!(first.email(), "ana@empresa.com");
    let data = hosts(&["web-01"]);
    let laptop = oauth::complete(first, Zeroizing::new(MASTER.into()), &data)
        .await
        .unwrap();
    let oauth = laptop.oauth.as_ref().unwrap();
    assert_eq!(oauth.provider, "google");
    assert!(laptop.auth.is_empty());
    let (laptop, _) = sync(&laptop, &data).await;
    assert_eq!(laptop.pending(), 0);

    let second = w.sign_in("ana-1", "ana@empresa.com").await;
    assert!(!second.is_new());
    let desktop = oauth::complete(second, Zeroizing::new(MASTER.into()), &VaultData::default())
        .await
        .unwrap();
    let (_, received) = sync(&desktop, &VaultData::default()).await;
    assert!(received.hosts.iter().any(|h| h.label == "web-01"));
}

#[tokio::test]
async fn another_master_password_cannot_open_the_account() {
    let w = world().await;
    let first = w.sign_in("ana-1", "ana@empresa.com").await;
    oauth::complete(first, Zeroizing::new(MASTER.into()), &VaultData::default())
        .await
        .unwrap();
    let second = w.sign_in("ana-1", "ana@empresa.com").await;
    let wrong = oauth::complete(
        second,
        Zeroizing::new("Otra-Contraseña-99!".into()),
        &VaultData::default(),
    )
    .await;
    assert!(matches!(wrong, Err(SyncError::MasterPasswordMismatch)));
}

#[tokio::test]
async fn a_new_account_needs_a_strong_master_password() {
    let w = world().await;
    let first = w.sign_in("ana-1", "ana@empresa.com").await;
    let weak = oauth::complete(first, Zeroizing::new("corta".into()), &VaultData::default()).await;
    let Err(SyncError::WeakMasterPassword(why)) = weak else {
        panic!("se esperaba una contraseña débil");
    };
    assert!(why.contains("12 caracteres"), "{why}");
}

#[tokio::test]
async fn changing_the_master_password_rewraps_the_key_on_the_server() {
    let w = world().await;
    let first = w.sign_in("ana-1", "ana@empresa.com").await;
    let data = hosts(&["db-01"]);
    let laptop = oauth::complete(first, Zeroizing::new(MASTER.into()), &data)
        .await
        .unwrap();
    let (laptop, _) = sync(&laptop, &data).await;
    let weak = oauth::rewrap(&laptop, Zeroizing::new("debil".into())).await;
    assert!(matches!(weak, Err(SyncError::WeakMasterPassword(_))));
    let laptop = oauth::rewrap(&laptop, Zeroizing::new("Nueva-Maestra-2027?".into()))
        .await
        .unwrap();
    // Cambiarla otra vez parte de la clave que quedó en el servidor.
    oauth::rewrap(&laptop, Zeroizing::new("Otra-Maestra-2028#".into()))
        .await
        .unwrap();

    let old = w.sign_in("ana-1", "ana@empresa.com").await;
    let refused = oauth::complete(old, Zeroizing::new(MASTER.into()), &VaultData::default()).await;
    assert!(matches!(refused, Err(SyncError::MasterPasswordMismatch)));
    let new = w.sign_in("ana-1", "ana@empresa.com").await;
    let desktop = oauth::complete(
        new,
        Zeroizing::new("Otra-Maestra-2028#".into()),
        &VaultData::default(),
    )
    .await
    .unwrap();
    let (_, received) = sync(&desktop, &VaultData::default()).await;
    assert!(received.hosts.iter().any(|h| h.label == "db-01"));
}

#[tokio::test]
async fn an_expired_session_asks_to_sign_in_again_through_the_provider() {
    let w = world().await;
    let first = w.sign_in("ana-1", "ana@empresa.com").await;
    let laptop = oauth::complete(first, Zeroizing::new(MASTER.into()), &VaultData::default())
        .await
        .unwrap();
    let expired = SyncLocal {
        token: None,
        ..laptop.clone()
    };
    let result = sync_once(&expired, &VaultData::default()).await;
    let Err(SyncError::SignInAgain(provider)) = result else {
        panic!("se esperaba que pidiera iniciar sesión de nuevo");
    };
    assert_eq!(provider, "Google");

    let again = w.sign_in("ana-1", "ana@empresa.com").await;
    let renewed = oauth::renew(&expired, again).unwrap();
    sync(&renewed, &VaultData::default()).await;
    // Iniciar sesión como otra persona no sirve para renovar.
    let bob = w.sign_in("bob-1", "bob@empresa.com").await;
    assert!(oauth::renew(&expired, bob).is_err());
}

#[tokio::test]
async fn a_server_without_providers_lists_none() {
    let config = Config {
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        ..Config::default()
    };
    let state = AppState::new(Db::open_in_memory().unwrap(), config)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let server = check_server_url(&format!("http://{address}")).unwrap();
    let none = oauth::providers(&server).await.unwrap();
    assert!(none.providers.is_empty());
    assert!(none.password_login);
}

const ACCOUNT_PASSWORD: &str = "contraseña de la cuenta";

#[tokio::test]
async fn a_password_account_moves_to_the_provider_and_keeps_its_data() {
    let w = world().await;
    let data = hosts(&["web-01"]);
    let laptop = create_account(
        &w.server,
        "ana@empresa.com",
        Zeroizing::new(ACCOUNT_PASSWORD.into()),
        &data,
    )
    .await
    .unwrap();
    let (laptop, _) = sync(&laptop, &data).await;
    let (laptop, team) = tunel_sync::teams::create_team(&laptop, "Operaciones")
        .await
        .unwrap();

    // Sin pedirlo, Google no sustituye a la contraseña.
    let refused = w.attempt("ana-1", "ana@empresa.com", false).await;
    let Err(SyncError::Provider(why)) = refused else {
        panic!("se esperaba el rechazo del proveedor");
    };
    assert!(why.contains("pásala a Google"), "{why}");

    // Otra persona del proveedor no puede pasar la cuenta de Ana a la suya.
    let bob = w.attempt("bob-1", "bob@empresa.com", true).await.unwrap();
    assert!(
        oauth::link(&laptop, bob, Zeroizing::new(MASTER.into()))
            .await
            .is_err()
    );

    // Sin la contraseña de la cuenta, controlar el correo en Google no basta.
    let sign_in = w.attempt("ana-1", "ana@empresa.com", true).await.unwrap();
    assert!(sign_in.is_link());
    let forged = SyncLocal {
        auth: Zeroizing::new("Y2xhdmUtZGUtYWNjZXNvLWZhbHNhLTEyMzQ1Njc4OTA".into()),
        ..laptop.clone()
    };
    assert!(
        oauth::link(&forged, sign_in, Zeroizing::new(MASTER.into()))
            .await
            .is_err()
    );

    // La contraseña maestra tiene que ser fuerte.
    let sign_in = w.attempt("ana-1", "ana@empresa.com", true).await.unwrap();
    let weak = oauth::link(&laptop, sign_in, Zeroizing::new("corta".into())).await;
    assert!(matches!(weak, Err(SyncError::WeakMasterPassword(_))));

    let sign_in = w.attempt("ana-1", "ana@empresa.com", true).await.unwrap();
    let laptop = oauth::link(&laptop, sign_in, Zeroizing::new(MASTER.into()))
        .await
        .unwrap();
    assert_eq!(laptop.oauth.as_ref().unwrap().provider, "google");
    assert!(laptop.auth.is_empty());
    assert!(laptop.teams.iter().any(|t| t.id == team));
    sync(&laptop, &data).await;

    // La contraseña de la cuenta ya no sirve, y otro equipo entra con Google y la
    // contraseña maestra, con los mismos datos.
    let old = password_sign_in(
        &w.server,
        "ana@empresa.com",
        Zeroizing::new(ACCOUNT_PASSWORD.into()),
        &VaultData::default(),
    )
    .await;
    assert!(old.is_err());
    let again = w.sign_in("ana-1", "ana@empresa.com").await;
    assert!(!again.is_new());
    let desktop = oauth::complete(again, Zeroizing::new(MASTER.into()), &VaultData::default())
        .await
        .unwrap();
    let (desktop, received) = sync(&desktop, &VaultData::default()).await;
    assert!(received.hosts.iter().any(|h| h.label == "web-01"));
    assert_eq!(
        desktop.keypair.as_ref().map(|k| k.public()),
        laptop.keypair.as_ref().map(|k| k.public())
    );
}

#[tokio::test]
async fn the_move_also_works_when_only_providers_are_allowed() {
    let db = Db::open_in_memory().unwrap();
    let before = world_on(db.clone(), false).await;
    let data = hosts(&["db-01"]);
    let laptop = create_account(
        &before.server,
        "ana@empresa.com",
        Zeroizing::new(ACCOUNT_PASSWORD.into()),
        &data,
    )
    .await
    .unwrap();
    sync(&laptop, &data).await;

    let w = world_on(db, true).await;
    let laptop = SyncLocal {
        server: w.server.base.clone(),
        ..laptop
    };
    let sign_in = w.attempt("ana-1", "ana@empresa.com", true).await.unwrap();
    let laptop = oauth::link(&laptop, sign_in, Zeroizing::new(MASTER.into()))
        .await
        .unwrap();
    sync(&laptop, &data).await;
    let again = w.sign_in("ana-1", "ana@empresa.com").await;
    let desktop = oauth::complete(again, Zeroizing::new(MASTER.into()), &VaultData::default())
        .await
        .unwrap();
    let (_, received) = sync(&desktop, &VaultData::default()).await;
    assert!(received.hosts.iter().any(|h| h.label == "db-01"));
}

#[tokio::test]
async fn a_phone_joins_through_the_app_redirect_and_receives_the_hosts() {
    let w = world().await;
    let first = w.sign_in("ana-1", "ana@empresa.com").await;
    let data = hosts(&["web-01"]);
    let laptop = oauth::complete(first, Zeroizing::new(MASTER.into()), &data)
        .await
        .unwrap();
    sync(&laptop, &data).await;

    let phone = w.sign_in_app("ana-1", "ana@empresa.com").await.unwrap();
    assert!(!phone.is_new());
    let phone = oauth::complete(phone, Zeroizing::new(MASTER.into()), &VaultData::default())
        .await
        .unwrap();
    let (phone, received) = sync(&phone, &VaultData::default()).await;

    assert!(received.hosts.iter().any(|h| h.label == "web-01"));
    assert_eq!(phone.pending(), 0);
}

#[tokio::test]
async fn the_app_rejects_a_return_from_another_sign_in() {
    let w = world().await;
    let provider = oauth::providers(&w.server).await.unwrap().providers[0].clone();
    let start = oauth::begin_app(&w.server, provider.clone()).unwrap();
    let other = oauth::begin_app(&w.server, provider).unwrap();
    let back = w
        .browse(&other.url.clone(), "ana-1", "ana@empresa.com")
        .await;

    let error = start.finish(&back).await.err().unwrap();

    assert!(matches!(error, SyncError::Provider(_)), "{error:?}");
}

#[tokio::test]
async fn the_app_rejects_a_return_to_another_address() {
    let w = world().await;
    let provider = oauth::providers(&w.server).await.unwrap().providers[0].clone();
    let start = oauth::begin_app(&w.server, provider).unwrap();
    let back = w
        .browse(&start.url.clone(), "ana-1", "ana@empresa.com")
        .await;
    let elsewhere = back.replacen("tunel://oauth", "https://otro.example/oauth", 1);

    let error = start.finish(&elsewhere).await.err().unwrap();

    assert!(matches!(error, SyncError::Provider(_)), "{error:?}");
}

#[tokio::test]
async fn the_server_only_returns_to_the_app_address() {
    let w = world().await;
    let challenge = "a".repeat(43);
    let start = |extra: &str| {
        format!(
            "{}/v1/auth/google/start?challenge={challenge}&state=0123456789abcdef{extra}",
            w.server.base
        )
    };

    let elsewhere = w
        .browser
        .get(start("&redirect=https%3A%2F%2Fotro.example%2Foauth"))
        .send()
        .await
        .unwrap();
    let both = w
        .browser
        .get(start("&redirect=tunel%3A%2F%2Foauth&port=50000"))
        .send()
        .await
        .unwrap();
    let neither = w.browser.get(start("")).send().await.unwrap();

    assert_eq!(elsewhere.status(), 400);
    assert_eq!(both.status(), 400);
    assert_eq!(neither.status(), 400);
}
