//! Inicio de sesión con un proveedor de identidad de punta a punta, contra un proveedor
//! OpenID Connect falso que escucha en TCP: el servidor lo descubre, canjea el código y
//! comprueba el ID token, y Túnel canjea el suyo con PKCE.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tunel_core::crypto::KdfParams;
use tunel_core::sync::protocol::*;
use tunel_core::sync::{AccountKeys, SealedBlob, VaultKey};
use tunel_server::oauth::ProviderConfig;
use tunel_server::{AppState, Config, Db, OAuthConfig, router};

const CLIENT_ID: &str = "cliente-de-tunel";
const SECRET: &str = "secreto-del-cliente";
const SALT: &[u8; 16] = b"sal-de-la-cuenta";

/// Lo que el proveedor falso devolverá en el próximo ID token y lo que recibió.
#[derive(Default)]
struct Idp {
    claims: Value,
    last_form: HashMap<String, String>,
}

type Shared = Arc<Mutex<Idp>>;

async fn fake_idp() -> (String, Shared) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let shared: Shared = Arc::default();
    let discovery = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
    });
    let state = shared.clone();
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move { Json(discovery) }),
        )
        .route(
            "/token",
            post(move |Form(form): Form<HashMap<String, String>>| async move {
                let mut idp = state.lock().unwrap();
                idp.last_form = form;
                let payload = B64_URL.encode(idp.claims.to_string());
                Json(json!({ "id_token": format!("e30.{payload}.firma"), "token_type": "Bearer" }))
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, shared)
}

struct Setup {
    app: Router,
    idp: Shared,
    issuer: String,
}

async fn setup(allowed: &[&str], trusted_tenant: bool) -> Setup {
    let (issuer, idp) = fake_idp().await;
    let config = Config {
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        unauthenticated_burst: 1000,
        allowed_domains: allowed.iter().map(|d| d.to_string()).collect(),
        oauth: Some(OAuthConfig {
            public_url: "https://tunel.empresa.com".into(),
            providers: vec![ProviderConfig {
                id: "google".into(),
                name: "Google".into(),
                issuer: issuer.clone(),
                client_id: CLIENT_ID.into(),
                client_secret: SECRET.into(),
                trusted_tenant,
            }],
            allow_http: true,
        }),
        ..Config::default()
    };
    let state = AppState::new(Db::open_in_memory().unwrap(), config)
        .await
        .unwrap();
    Setup {
        app: router(state),
        idp,
        issuer,
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Option<String>, Value) {
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
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|l| l.to_str().unwrap().to_string());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        location,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn query(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Lo que hace Túnel: su reto PKCE y su `state`.
struct Client {
    verifier: String,
    challenge: String,
    state: String,
}

impl Client {
    fn new() -> Self {
        let verifier = B64_URL.encode(rand::random::<[u8; 32]>());
        let challenge = B64_URL.encode(Sha256::digest(verifier.as_bytes()));
        let state = B64_URL.encode(rand::random::<[u8; 16]>());
        Self {
            verifier,
            challenge,
            state,
        }
    }
}

/// Lo que el proveedor afirma de una persona.
fn person(sub: &str, email: &str) -> Value {
    json!({"sub": sub, "email": email, "email_verified": true})
}

impl Setup {
    /// Recorre el navegador: Túnel → servidor → proveedor → servidor. Devuelve los
    /// parámetros con los que el servidor manda volver a Túnel.
    async fn browser(&self, client: &Client, claims: Value) -> HashMap<String, String> {
        let uri = format!(
            "/v1/auth/google/start?port=41234&challenge={}&state={}",
            client.challenge, client.state
        );
        let (status, location, _) = call(&self.app, "GET", &uri, None, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let authorize = location.unwrap();
        assert!(authorize.starts_with(&format!("{}/authorize?", self.issuer)));
        let params = query(&authorize);
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(
            params["redirect_uri"],
            "https://tunel.empresa.com/v1/auth/google/callback"
        );
        assert_eq!(params["code_challenge_method"], "S256");
        let mut claims = claims;
        let defaults = json!({
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "exp": 4_000_000_000_i64,
            "nonce": params["nonce"],
        });
        for (k, v) in defaults.as_object().unwrap() {
            claims
                .as_object_mut()
                .unwrap()
                .entry(k)
                .or_insert(v.clone());
        }
        self.idp.lock().unwrap().claims = claims;
        let uri = format!(
            "/v1/auth/google/callback?code=codigo-del-idp&state={}",
            params["state"]
        );
        let (status, location, _) = call(&self.app, "GET", &uri, None, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let back = location.unwrap();
        assert!(back.starts_with("http://127.0.0.1:41234/oauth?"), "{back}");
        // El servidor canjeó el código con su secreto y el verificador PKCE correcto.
        let form = self.idp.lock().unwrap().last_form.clone();
        assert_eq!(form["client_secret"], SECRET);
        assert_eq!(form["code"], "codigo-del-idp");
        assert_eq!(
            B64_URL.encode(Sha256::digest(form["code_verifier"].as_bytes())),
            params["code_challenge"]
        );
        let back = query(&back);
        // Túnel recibe su propio `state`, para saber que la vuelta es la suya.
        assert_eq!(back["state"], client.state);
        back
    }

    async fn redeem(&self, code: &str, verifier: &str) -> (StatusCode, Value) {
        let body = serde_json::to_value(OAuthTokenRequest {
            code: code.into(),
            verifier: verifier.into(),
        })
        .unwrap();
        let (status, _, body) = call(&self.app, "POST", "/v1/auth/token", None, Some(body)).await;
        (status, body)
    }

    /// Inicia sesión por completo como `claims` y devuelve el resultado.
    async fn login(&self, claims: Value) -> OAuthLogin {
        let client = Client::new();
        let back = self.browser(&client, claims).await;
        let code = back.get("code").unwrap_or_else(|| panic!("{back:?}"));
        let (status, body) = self.redeem(code, &client.verifier).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_value(body).unwrap()
    }

    /// Crea la cuenta de `claims` con la clave envuelta con `password`; devuelve el token.
    async fn sign_up(&self, claims: Value, password: &str) -> (String, SealedBlob) {
        let OAuthLogin::New { ticket, .. } = self.login(claims).await else {
            panic!("se esperaba una cuenta nueva");
        };
        let (_, wrapped) = wrapped_key(password);
        let (status, body) = register(self, &ticket, &wrapped).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (body["token"].as_str().unwrap().to_string(), wrapped)
    }
}

fn wrapped_key(password: &str) -> (VaultKey, SealedBlob) {
    let keys = AccountKeys::derive_for_tests(password.as_bytes(), SALT);
    let vault = VaultKey::generate();
    let wrapped = vault.wrap(&keys).unwrap();
    (vault, wrapped)
}

async fn register(setup: &Setup, ticket: &str, wrapped: &SealedBlob) -> (StatusCode, Value) {
    let body = serde_json::to_value(OAuthRegisterRequest {
        ticket: ticket.into(),
        kdf: KdfParams::RECOMMENDED,
        salt: B64.encode(SALT),
        vault_key: wrapped.clone(),
    })
    .unwrap();
    let (status, _, body) = call(&setup.app, "POST", "/v1/accounts/oauth", None, Some(body)).await;
    (status, body)
}

async fn password_account(setup: &Setup, email: &str) -> String {
    let keys = AccountKeys::derive_for_tests(b"clave", SALT);
    let body = serde_json::to_value(RegisterRequest {
        email: email.into(),
        kdf: KdfParams::RECOMMENDED,
        salt: B64.encode(SALT),
        auth: keys.auth_token().to_string(),
        vault_key: VaultKey::generate().wrap(&keys).unwrap(),
    })
    .unwrap();
    let (status, _, _) = call(&setup.app, "POST", "/v1/accounts", None, Some(body)).await;
    assert_eq!(status, StatusCode::CREATED);
    let login = json!({"email": email, "auth": keys.auth_token().as_str()});
    let (_, _, body) = call(&setup.app, "POST", "/v1/sessions", None, Some(login)).await;
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn the_server_lists_its_providers() {
    let s = setup(&["empresa.com"], false).await;
    let (status, _, body) = call(&s.app, "GET", "/v1/auth/providers", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"providers": [{"id": "google", "name": "Google"}]})
    );
}

#[tokio::test]
async fn a_new_person_creates_the_account_and_later_signs_in_again() {
    let s = setup(&["empresa.com"], false).await;
    let OAuthLogin::New { email, ticket } = s.login(person("ana-1", "Ana@Empresa.com")).await
    else {
        panic!("se esperaba una cuenta nueva");
    };
    assert_eq!(email, "ana@empresa.com");
    let (vault, wrapped) = wrapped_key("Contraseña-Maestra-1");
    let (status, body) = register(&s, &ticket, &wrapped).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let (status, _, _) = call(&s.app, "GET", "/v1/records", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    // El permiso para crear la cuenta solo sirve una vez.
    assert_eq!(
        register(&s, &ticket, &wrapped).await.0,
        StatusCode::BAD_REQUEST
    );

    // Otro equipo: la misma cuenta, con la clave de bóveda que se abre con la contraseña
    // maestra.
    let OAuthLogin::Existing {
        email,
        token,
        kdf,
        salt,
        vault_key,
    } = s.login(person("ana-1", "ana@empresa.com")).await
    else {
        panic!("se esperaba la cuenta existente");
    };
    assert_eq!(email, "ana@empresa.com");
    assert_eq!(kdf, KdfParams::RECOMMENDED);
    assert_eq!(salt, B64.encode(SALT));
    let keys = AccountKeys::derive_for_tests("Contraseña-Maestra-1".as_bytes(), SALT);
    let opened = VaultKey::unwrap(&vault_key, &keys).unwrap();
    let probe = tunel_core::sync::RecordKey::new(tunel_core::sync::RecordKind::Host, "x");
    assert_eq!(opened.record_id(&probe), vault.record_id(&probe));
    let (status, _, _) = call(&s.app, "GET", "/v1/records", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_account_follows_the_person_not_the_email() {
    let s = setup(&["empresa.com"], false).await;
    s.sign_up(person("ana-1", "ana@empresa.com"), "Maestra-1")
        .await;
    // Su correo cambió en el proveedor: sigue siendo su cuenta.
    let renamed = s.login(person("ana-1", "ana.lopez@empresa.com")).await;
    let OAuthLogin::Existing { email, .. } = renamed else {
        panic!("se esperaba la cuenta existente");
    };
    assert_eq!(email, "ana@empresa.com");
    // Otra persona a la que el proveedor da ahora el correo de ana no entra en su cuenta.
    let back = s
        .browser(&Client::new(), person("otra-persona", "ana@empresa.com"))
        .await;
    assert!(
        back["error"].contains("ligada a otro inicio de sesión"),
        "{back:?}"
    );
    assert!(!back.contains_key("code"));
}

#[tokio::test]
async fn the_code_needs_the_pkce_verifier_and_works_once() {
    let s = setup(&["empresa.com"], false).await;
    let client = Client::new();
    let back = s.browser(&client, person("ana-1", "ana@empresa.com")).await;
    let (status, _) = s.redeem(&back["code"], &Client::new().verifier).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Un intento fallido gasta el código: quien lo robó no puede probar más.
    let (status, _) = s.redeem(&back["code"], &client.verifier).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unverified_or_foreign_emails_are_sent_back_with_an_error() {
    let s = setup(&["empresa.com"], false).await;
    let unverified = s
        .browser(
            &Client::new(),
            json!({"sub": "a", "email": "ana@empresa.com", "email_verified": false}),
        )
        .await;
    assert!(
        unverified["error"].contains("no ha verificado"),
        "{unverified:?}"
    );
    assert!(!unverified.contains_key("code"));
    let foreign = s
        .browser(&Client::new(), person("eve", "eve@gmail.com"))
        .await;
    assert!(foreign["error"].contains("@empresa.com"), "{foreign:?}");
    let two_ats = s
        .browser(&Client::new(), person("eve", "a@evil.com@empresa.com"))
        .await;
    assert!(two_ats["error"].contains("no válido"), "{two_ats:?}");
}

#[tokio::test]
async fn a_token_for_another_login_is_rejected() {
    let s = setup(&["empresa.com"], false).await;
    let mut claims = person("ana-1", "ana@empresa.com");
    claims["nonce"] = json!("de-otro-inicio");
    let back = s.browser(&Client::new(), claims).await;
    assert!(back["error"].contains("no corresponde"), "{back:?}");
    let mut claims = person("ana-1", "ana@empresa.com");
    claims["aud"] = json!("otra-app");
    let other_app = s.browser(&Client::new(), claims).await;
    assert!(
        other_app["error"].contains("otra aplicación"),
        "{other_app:?}"
    );
}

#[tokio::test]
async fn bad_starts_and_unknown_states_are_refused() {
    let s = setup(&["empresa.com"], false).await;
    let uri = "/v1/auth/google/callback?code=x&state=inventado";
    let (status, location, _) = call(&s.app, "GET", uri, None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(location.is_none());
    let client = Client::new();
    let unknown = format!(
        "/v1/auth/github/start?port=41234&challenge={}&state={}",
        client.challenge, client.state
    );
    assert_eq!(
        call(&s.app, "GET", &unknown, None, None).await.0,
        StatusCode::NOT_FOUND
    );
    for bad in [
        format!(
            "port=80&challenge={}&state={}",
            client.challenge, client.state
        ),
        format!("port=41234&challenge=corto&state={}", client.state),
        format!("port=41234&challenge={}&state=x", client.challenge),
        format!("port=41234&challenge={}", client.challenge),
    ] {
        let uri = format!("/v1/auth/google/start?{bad}");
        assert_eq!(
            call(&s.app, "GET", &uri, None, None).await.0,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
}

#[tokio::test]
async fn an_email_with_a_password_account_cannot_sign_in_through_the_provider() {
    let s = setup(&["empresa.com"], false).await;
    password_account(&s, "ana@empresa.com").await;
    let back = s
        .browser(&Client::new(), person("ana-1", "ana@empresa.com"))
        .await;
    assert!(back["error"].contains("contraseña"), "{back:?}");
}

#[tokio::test]
async fn without_allowed_domains_only_a_trusted_tenant_can_create_accounts() {
    let open_google = setup(&[], false).await;
    let back = open_google
        .browser(&Client::new(), person("x", "ana@gmail.com"))
        .await;
    assert!(
        back["error"].contains("TUNEL_DOMINIOS_PERMITIDOS"),
        "{back:?}"
    );

    let tenant = setup(&[], true).await;
    let claims = json!({"tid": "t1", "oid": "o1", "email": "ana@empresa.com", "xms_edov": true});
    let login = tenant.login(claims).await;
    assert!(matches!(login, OAuthLogin::New { .. }));
}

#[tokio::test]
async fn rewrapping_needs_the_current_key_and_only_works_for_provider_accounts() {
    let s = setup(&["empresa.com"], false).await;
    let (token, wrapped) = s
        .sign_up(person("ana-1", "ana@empresa.com"), "Antigua-1")
        .await;
    let (_, rewrapped) = wrapped_key("Nueva-Maestra-2");
    let update = |previous: &SealedBlob| {
        serde_json::to_value(VaultKeyUpdate {
            previous: previous.clone(),
            kdf: KdfParams::RECOMMENDED,
            salt: B64.encode(SALT),
            vault_key: rewrapped.clone(),
        })
        .unwrap()
    };
    let uri = "/v1/accounts/current/vault-key";
    // Sin la clave actual, una sesión robada no basta para sustituirla.
    let (_, other) = wrapped_key("Otra");
    let (status, _, _) = call(&s.app, "PUT", uri, Some(&token), Some(update(&other))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _, _) = call(&s.app, "PUT", uri, Some(&token), Some(update(&wrapped))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let OAuthLogin::Existing { vault_key, .. } = s.login(person("ana-1", "ana@empresa.com")).await
    else {
        panic!("se esperaba la cuenta existente");
    };
    assert_eq!(vault_key, rewrapped);

    // Una cuenta de contraseña no: su clave de acceso sale de la misma contraseña.
    let bob = password_account(&s, "bob@empresa.com").await;
    let (status, _, _) = call(&s.app, "PUT", uri, Some(&bob), Some(update(&wrapped))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_provider_account_cannot_sign_in_with_a_password() {
    let s = setup(&["empresa.com"], false).await;
    s.sign_up(person("ana-1", "ana@empresa.com"), "Contraseña-Maestra-1")
        .await;
    let keys = AccountKeys::derive_for_tests("Contraseña-Maestra-1".as_bytes(), SALT);
    let login = json!({"email": "ana@empresa.com", "auth": keys.auth_token().as_str()});
    let (status, _, _) = call(&s.app, "POST", "/v1/sessions", None, Some(login)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
