//! Pruebas de la API con el cifrado real de `tunel-core`: lo que sube un equipo lo
//! descarga y descifra otro, y el servidor solo ve datos cifrados.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;
use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::sync::protocol::*;
use tunel_core::sync::{AccountKeys, Manifest, SyncState, VaultKey};
use tunel_core::vault::VaultData;
use tunel_server::{AppState, Config, Db, Quota, router};
use uuid::Uuid;

const SALT: &[u8; 16] = b"sal-de-la-cuenta";
const EMAIL: &str = "ana@ejemplo.com";

fn config() -> Config {
    Config {
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        login_attempts: 3,
        login_window: Duration::from_secs(60),
        unauthenticated_burst: 1000,
        ..Config::default()
    }
}

async fn app_with(config: Config) -> (Router, Db) {
    let db = Db::open_in_memory().unwrap();
    let state = AppState::new(db.clone(), config).await.unwrap();
    (router(state), db)
}

async fn app() -> Router {
    app_with(config()).await.0
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn account(password: &str) -> AccountKeys {
    AccountKeys::derive_for_tests(password.as_bytes(), SALT)
}

/// Pide a la cuenta parámetros de Argon2id válidos; la prueba deriva con unos baratos,
/// algo que el servidor no puede distinguir.
fn register_body(email: &str, keys: &AccountKeys, vault: &VaultKey) -> Value {
    serde_json::to_value(RegisterRequest {
        email: email.into(),
        kdf: KdfParams::RECOMMENDED,
        salt: B64.encode(SALT),
        auth: keys.auth_token().to_string(),
        vault_key: vault.wrap(keys).unwrap(),
    })
    .unwrap()
}

async fn register(app: &Router, email: &str, password: &str) -> (StatusCode, VaultKey) {
    let keys = account(password);
    let vault = VaultKey::generate();
    let (status, _) = send(
        app,
        "POST",
        "/v1/accounts",
        None,
        Some(register_body(email, &keys, &vault)),
    )
    .await;
    (status, vault)
}

async fn login(app: &Router, email: &str, password: &str) -> (StatusCode, Value) {
    let body = json!({"email": email, "auth": account(password).auth_token().as_str()});
    send(app, "POST", "/v1/sessions", None, Some(body)).await
}

/// Inicia sesión y recupera la clave de bóveda, como haría un equipo nuevo.
async fn device(app: &Router, password: &str) -> (String, VaultKey) {
    let (status, body) = login(app, EMAIL, password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: LoginResponse = serde_json::from_value(body).unwrap();
    let vault = VaultKey::unwrap(&response.vault_key, &account(password)).unwrap();
    (response.token, vault)
}

/// Sube los cambios pendientes de `state` con el manifiesto siguiente a `base`.
fn push_body(
    state: &SyncState,
    data: &VaultData,
    vault: &VaultKey,
    base: &Manifest,
) -> (Value, Manifest) {
    let outgoing = state.outgoing(data).unwrap();
    let manifest = base.with_pushed(outgoing.iter().map(|e| (vault.record_id(&e.key), e.hlc)));
    let request = PushRequest {
        epoch: None,
        base_version: base.version,
        manifest: ManifestBlob {
            version: manifest.version,
            blob: manifest.seal(vault).unwrap(),
        },
        records: outgoing
            .iter()
            .map(|e| vault.seal_record(e).unwrap())
            .collect(),
    };
    (serde_json::to_value(request).unwrap(), manifest)
}

async fn pull_all(app: &Router, token: &str, since: u64) -> PullResponse {
    let (status, body) = send(
        app,
        "GET",
        &format!("/v1/records?since={since}"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

#[tokio::test]
async fn a_second_device_downloads_decrypts_and_verifies_the_vault() {
    let app = app().await;
    assert_eq!(
        register(&app, EMAIL, "contraseña-larga").await.0,
        StatusCode::CREATED
    );

    // El portátil sube dos hosts.
    let (token, vault) = device(&app, "contraseña-larga").await;
    let data = VaultData::default()
        .with_host(Host::new("web", "10.0.0.1"))
        .with_host(Host::new("db", "10.0.0.2"));
    let state = SyncState::adopt(Uuid::from_u128(1), &data, 1000).unwrap();
    let (body, _) = push_body(&state, &data, &vault, &Manifest::empty());
    let (status, response) = send(&app, "POST", "/v1/records", Some(&token), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["cursor"], 2);

    // Un equipo nuevo inicia sesión, descarga, descifra, fusiona y comprueba el manifiesto.
    let (token, vault) = device(&app, "contraseña-larga").await;
    let page = pull_all(&app, &token, 0).await;
    assert_eq!(page.records.len(), 2);
    assert!(!page.more);
    for record in &page.records {
        assert!(!record.blob.ciphertext.contains("web"));
    }
    let envelopes: Vec<_> = page
        .records
        .iter()
        .map(|r| vault.open_record(r).unwrap())
        .collect();
    let fresh = SyncState::new(Uuid::from_u128(2));
    let merged = fresh
        .merge_remote(&VaultData::default(), &envelopes, page.cursor, 2000)
        .unwrap();
    let mut labels: Vec<&str> = merged.data.hosts.iter().map(|h| h.label.as_str()).collect();
    labels.sort_unstable();
    assert_eq!(labels, ["db", "web"]);

    let manifest_blob = page.manifest.unwrap();
    let manifest = Manifest::open(&manifest_blob.blob, manifest_blob.version, &vault).unwrap();
    assert_eq!(manifest.verify(&merged.state, &vault, &[]), Ok(()));
}

#[tokio::test]
async fn pushing_on_a_stale_manifest_is_a_conflict() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    let (token, vault) = device(&app, "contraseña-larga").await;
    let data = VaultData::default().with_host(Host::new("web", "1.1.1.1"));
    let state = SyncState::adopt(Uuid::from_u128(1), &data, 1000).unwrap();

    let (first, _) = push_body(&state, &data, &vault, &Manifest::empty());
    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/records",
            Some(&token),
            Some(first.clone())
        )
        .await
        .0,
        StatusCode::OK
    );
    // Otro equipo subió antes: el mismo manifiesto base ya no vale.
    assert_eq!(
        send(&app, "POST", "/v1/records", Some(&token), Some(first))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn pull_is_paged_and_returns_only_newer_changes() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    let (token, vault) = device(&app, "contraseña-larga").await;
    let data = (0..PULL_PAGE_SIZE + 3).fold(VaultData::default(), |d, i| {
        d.with_host(Host::new(format!("h{i}"), "1.1.1.1"))
    });
    let state = SyncState::adopt(Uuid::from_u128(1), &data, 1000).unwrap();
    let outgoing = state.outgoing(&data).unwrap();
    let mut base = Manifest::empty();
    for chunk in outgoing.chunks(MAX_PUSH_RECORDS) {
        let manifest = base.with_pushed(chunk.iter().map(|e| (vault.record_id(&e.key), e.hlc)));
        let request = PushRequest {
            epoch: None,
            base_version: base.version,
            manifest: ManifestBlob {
                version: manifest.version,
                blob: manifest.seal(&vault).unwrap(),
            },
            records: chunk
                .iter()
                .map(|e| vault.seal_record(e).unwrap())
                .collect(),
        };
        let (status, _) = send(
            &app,
            "POST",
            "/v1/records",
            Some(&token),
            Some(serde_json::to_value(request).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        base = manifest;
    }

    let first = pull_all(&app, &token, 0).await;
    assert_eq!(first.records.len(), PULL_PAGE_SIZE);
    assert!(first.more);
    assert!(
        first.manifest.is_none(),
        "el manifiesto solo va en la última página"
    );
    let second = pull_all(&app, &token, first.cursor).await;
    assert_eq!(second.records.len(), 3);
    assert!(!second.more);
    let none = pull_all(&app, &token, second.cursor).await;
    assert!(none.records.is_empty());
    assert_eq!(none.cursor, second.cursor);
}

#[tokio::test]
async fn only_the_first_account_can_register_unless_registration_is_open() {
    let app = app().await;
    assert_eq!(
        register(&app, EMAIL, "contraseña-larga").await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        register(&app, "otro@ejemplo.com", "contraseña-larga")
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    let (open, _) = app_with(Config {
        open_registration: true,
        ..config()
    })
    .await;
    assert_eq!(
        register(&open, EMAIL, "contraseña-larga").await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        register(&open, "Ana@Ejemplo.com ", "otra-contraseña")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        register(&open, "otro@ejemplo.com", "contraseña-larga")
            .await
            .0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn registration_rejects_weak_parameters_and_bad_input() {
    let app = app().await;
    let keys = account("contraseña-larga");
    let vault = VaultKey::generate();
    let good = register_body(EMAIL, &keys, &vault);
    let with = |field: &str, value: Value| {
        let mut body = good.clone();
        body[field] = value;
        body
    };
    let cases = [
        with(
            "kdf",
            json!({"memory_kib": 8, "iterations": 1, "parallelism": 1}),
        ),
        with("salt", json!(B64.encode([0u8; 4]))),
        with("auth", json!("corta")),
        with("email", json!("sin-arroba")),
        with("vault_key", json!({"nonce": "AAAA", "ciphertext": "AAAA"})),
    ];
    for body in cases {
        let (status, response) = send(&app, "POST", "/v1/accounts", None, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }
}

#[tokio::test]
async fn wrong_password_is_rejected_and_repeated_failures_are_throttled() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    for _ in 0..3 {
        assert_eq!(
            login(&app, EMAIL, "equivocada").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    // Bloqueada aunque ahora la contraseña sea la buena.
    assert_eq!(
        login(&app, EMAIL, "contraseña-larga").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Una cuenta inexistente responde igual que una contraseña equivocada.
    assert_eq!(
        login(&app, "nadie@ejemplo.com", "x").await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn prelogin_does_not_reveal_which_emails_have_accounts() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    let prelogin = |email: &'static str| {
        let app = app.clone();
        async move {
            send(
                &app,
                "POST",
                "/v1/prelogin",
                None,
                Some(json!({"email": email})),
            )
            .await
        }
    };
    let (status, real) = prelogin("ana@ejemplo.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(real["salt"], B64.encode(SALT));

    let (status, fake) = prelogin("nadie@ejemplo.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fake, prelogin("nadie@ejemplo.com").await.1);
    assert_eq!(
        B64.decode(fake["salt"].as_str().unwrap()).unwrap().len(),
        16
    );
    assert_eq!(fake["kdf"], real["kdf"]);
}

#[tokio::test]
async fn records_need_a_valid_session_and_logout_ends_it() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    assert_eq!(
        send(&app, "GET", "/v1/records", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "GET", "/v1/records", Some("inventado"), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let (token, _) = device(&app, "contraseña-larga").await;
    assert_eq!(
        send(&app, "GET", "/v1/records", Some(&token), None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "DELETE", "/v1/sessions/current", Some(&token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&app, "GET", "/v1/records", Some(&token), None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn malformed_pushes_are_rejected() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    let (token, vault) = device(&app, "contraseña-larga").await;
    let data = VaultData::default().with_host(Host::new("web", "1.1.1.1"));
    let state = SyncState::adopt(Uuid::from_u128(1), &data, 1000).unwrap();
    let (good, _) = push_body(&state, &data, &vault, &Manifest::empty());
    let record = good["records"][0].clone();
    let with = |field: &str, value: Value| {
        let mut body = good.clone();
        body[field] = value;
        body
    };
    let mut bad_id = record.clone();
    bad_id["id"] = json!("../../etc/passwd");
    let mut too_big = record.clone();
    too_big["ciphertext"] = json!("A".repeat(2 * 1024 * 1024));
    let cases = [
        with("records", json!([bad_id])),
        with("records", json!([too_big])),
        with("records", json!([record.clone(), record.clone()])),
        with("records", json!(vec![record; MAX_PUSH_RECORDS + 1])),
        with("base_version", json!(5)),
    ];
    for body in cases {
        let (status, response) = send(&app, "POST", "/v1/records", Some(&token), Some(body)).await;
        assert!(status.is_client_error(), "{status} {response}");
    }
    // Nada de lo anterior llegó a guardarse.
    assert!(pull_all(&app, &token, 0).await.records.is_empty());
}

#[tokio::test]
async fn the_record_quota_is_enforced() {
    let (app, _) = app_with(Config {
        quota: Quota {
            records: 1,
            bytes: u64::MAX,
        },
        ..config()
    })
    .await;
    register(&app, EMAIL, "contraseña-larga").await;
    let (token, vault) = device(&app, "contraseña-larga").await;
    let data = VaultData::default()
        .with_host(Host::new("a", "1"))
        .with_host(Host::new("b", "2"));
    let state = SyncState::adopt(Uuid::from_u128(1), &data, 1000).unwrap();
    let (body, _) = push_body(&state, &data, &vault, &Manifest::empty());
    assert_eq!(
        send(&app, "POST", "/v1/records", Some(&token), Some(body))
            .await
            .0,
        StatusCode::INSUFFICIENT_STORAGE
    );
}

#[tokio::test]
async fn parallel_logins_cannot_exceed_the_attempt_limit() {
    let app = app().await;
    register(&app, EMAIL, "contraseña-larga").await;
    let attempts = (0..12).map(|_| {
        let app = app.clone();
        tokio::spawn(async move { login(&app, EMAIL, "equivocada").await.0 })
    });
    let mut statuses = Vec::new();
    for attempt in attempts {
        statuses.push(attempt.await.unwrap());
    }
    let checked = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    let throttled = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!((checked, throttled), (3, 9), "{statuses:?}");
}

#[tokio::test]
async fn unauthenticated_routes_share_a_global_rate_limit() {
    let (app, _) = app_with(Config {
        unauthenticated_per_second: 0,
        unauthenticated_burst: 2,
        ..config()
    })
    .await;
    let body = || Some(json!({"email": "x@y.z"}));
    assert_eq!(
        send(&app, "POST", "/v1/prelogin", None, body()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "POST", "/v1/prelogin", None, body()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "POST", "/v1/prelogin", None, body()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        login(&app, EMAIL, "x").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn auth_routes_reject_large_bodies() {
    let app = app().await;
    let huge = json!({"email": "a".repeat(20 * 1024)});
    let (status, _) = send(&app, "POST", "/v1/prelogin", None, Some(huge)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn accounts_must_use_the_server_wide_parameters() {
    let app = app().await;
    let keys = account("contraseña-larga");
    let mut body = register_body(EMAIL, &keys, &VaultKey::generate());
    body["kdf"] = json!({"memory_kib": 128 * 1024, "iterations": 4, "parallelism": 1});
    assert_eq!(
        send(&app, "POST", "/v1/accounts", None, Some(body)).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn simultaneous_first_registrations_create_only_one_account() {
    let app = app().await;
    let attempts = (0..6).map(|i| {
        let app = app.clone();
        tokio::spawn(async move {
            register(&app, &format!("u{i}@ejemplo.com"), "contraseña-larga")
                .await
                .0
        })
    });
    let mut created = 0;
    for attempt in attempts {
        if attempt.await.unwrap() == StatusCode::CREATED {
            created += 1;
        }
    }
    assert_eq!(created, 1);
}

#[tokio::test]
async fn the_byte_quota_is_enforced_and_nothing_is_stored() {
    let (app, _) = app_with(Config {
        quota: Quota {
            records: 100,
            bytes: 100,
        },
        ..config()
    })
    .await;
    register(&app, EMAIL, "contraseña-larga").await;
    let (token, vault) = device(&app, "contraseña-larga").await;
    let data = VaultData::default().with_host(Host::new("a", "1"));
    let state = SyncState::adopt(Uuid::from_u128(1), &data, 1000).unwrap();
    let (body, _) = push_body(&state, &data, &vault, &Manifest::empty());
    assert_eq!(
        send(&app, "POST", "/v1/records", Some(&token), Some(body))
            .await
            .0,
        StatusCode::INSUFFICIENT_STORAGE
    );
    let page = pull_all(&app, &token, 0).await;
    assert!(page.records.is_empty() && page.manifest.is_none());
}

#[tokio::test]
async fn responses_are_not_cached() {
    let app = app().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
}
