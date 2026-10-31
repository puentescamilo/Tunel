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
use tunel_core::sync::protocol::AuthProvider;
use tunel_core::vault::VaultData;
use tunel_server::oauth::ProviderConfig;
use tunel_server::{AppState, Config, Db, OAuthConfig, router};
use tunel_sync::oauth::{self, OAuthSignIn};
use tunel_sync::{ServerUrl, SyncError, check_server_url, sync_once};
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
    let (issuer, claims) = fake_idp().await;
    let config = Config {
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
    let state = AppState::new(Db::open_in_memory().unwrap(), config)
        .await
        .unwrap();
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
        let providers = oauth::providers(&self.server).await.unwrap();
        assert_eq!(providers.len(), 1);
        let start = oauth::begin(&self.server, providers[0].clone())
            .await
            .unwrap();
        let url = start.url.clone();
        let waiting = tokio::spawn(start.wait());
        // El navegador: servidor → proveedor (que da el visto bueno) → servidor → Túnel.
        let to_idp = self.browser.get(&url).send().await.unwrap();
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
        let to_app = self.browser.get(&callback).send().await.unwrap();
        let back = location(&to_app);
        assert!(back.starts_with("http://127.0.0.1:"), "{back}");
        let page = self.browser.get(&back).send().await.unwrap();
        assert!(
            page.text()
                .await
                .unwrap()
                .contains("Ya puedes volver a Túnel")
        );
        waiting.await.unwrap().unwrap()
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
    let none: Vec<AuthProvider> = oauth::providers(&server).await.unwrap();
    assert!(none.is_empty());
}
