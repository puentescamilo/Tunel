//! Inicio de sesión con proveedores de identidad OpenID Connect: Google, Microsoft 365 o
//! cualquier otro.
//!
//! El proveedor solo confirma quién es la persona: la clave que cifra la bóveda sigue
//! saliendo de una contraseña que el servidor no conoce (la contraseña maestra de Túnel),
//! así que el servidor sigue sin poder leer nada.
//!
//! El servidor es el cliente confidencial ante el proveedor (guarda el ID y el secreto del
//! cliente). Túnel nunca los ve:
//! 1. Túnel escucha en un puerto de `127.0.0.1` y abre en el navegador
//!    `/v1/auth/{proveedor}/start?port=…&challenge=…`, con su propio reto PKCE.
//! 2. El servidor manda al navegador al proveedor; al volver (`/callback`) canjea el código
//!    por el ID token directamente con el proveedor, por TLS, y comprueba emisor,
//!    destinatario, caducidad, `nonce` y correo.
//! 3. El servidor devuelve el navegador a Túnel (`http://127.0.0.1:{puerto}/oauth?code=…`)
//!    con un código de un solo uso y el `state` que mandó Túnel, que Túnel canjea en
//!    `/v1/auth/token` demostrando el reto PKCE. Así, otro programa que vea esa dirección
//!    no puede usar el código.
//!
//! Cada cuenta queda ligada al identificador estable de la persona en su proveedor (`sub`,
//! o `tid` + `oid` en Microsoft), no al correo: un correo reasignado, cambiado o afirmado
//! por otro proveedor no da acceso a la cuenta de otra persona.

use crate::api::{
    ApiError, ApiResult, AppState, MAX_VAULT_KEY_CIPHERTEXT, Session, check_account_kdf,
    check_blob, domain_allowed, normalize_email, now, take_unauthenticated,
};
use crate::auth::{self, StoredHash};
use crate::db::NewOAuthAccount;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tunel_core::sync::SealedBlob;
use tunel_core::sync::protocol::{
    AuthProvider, AuthProviders, OAuthLogin, OAuthRegisterRequest, OAuthRegisterResponse,
    OAuthTokenRequest, VaultKeyUpdate,
};

/// Tiempo para completar el inicio de sesión en el navegador.
const FLOW_TTL: Duration = Duration::from_secs(5 * 60);
/// Tiempo para que Túnel canjee el código que recibe.
const CODE_TTL: Duration = Duration::from_secs(2 * 60);
/// Tiempo para crear la cuenta tras iniciar sesión por primera vez.
const TICKET_TTL: Duration = Duration::from_secs(10 * 60);
/// Inicios de sesión a medias que se guardan como mucho. Con el límite de peticiones sin
/// sesión (10 por segundo), nadie llena tantos en lo que tardan en caducar; si aun así se
/// llena, se descarta el más antiguo en lugar de rechazar el nuevo.
const MAX_PENDING: usize = 10_000;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Tope de los mensajes de error del proveedor que se pasan a Túnel.
const MAX_ERROR_CHARS: usize = 200;
/// Inquilinos de Microsoft que admiten cuentas de cualquier organización: con ellos
/// cualquiera podría poner como correo el de otra persona.
/// El último es el identificador del inquilino de las cuentas personales.
const SHARED_TENANTS: [&str; 4] = [
    "common",
    "organizations",
    "consumers",
    "9188040d-6c67-4c5b-b112-36a304b66dad",
];

/// Un proveedor de identidad configurado.
#[derive(Clone)]
pub struct ProviderConfig {
    /// `google`, `microsoft` u `oidc`; va en las rutas.
    pub id: String,
    pub name: String,
    /// Emisor OpenID Connect; su configuración se lee de `/.well-known/openid-configuration`.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Microsoft con un inquilino concreto: el inquilino ya limita las cuentas a la
    /// organización, la persona se identifica con `tid` + `oid` y el correo se acepta solo
    /// si la organización es dueña de su dominio (`xms_edov`).
    pub trusted_tenant: bool,
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Dirección pública del servidor, sin barra final: de ella sale la dirección de
    /// retorno que hay que registrar en cada proveedor.
    pub public_url: String,
    pub providers: Vec<ProviderConfig>,
    /// Solo para pruebas: admite proveedores por HTTP.
    pub allow_http: bool,
}

impl OAuthConfig {
    /// Lee los proveedores de las variables de entorno; `None` si no hay ninguno.
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let var = |name: &str| {
            var(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let pair = |prefix: &str| -> Result<Option<(String, String)>, String> {
            let id = var(&format!("TUNEL_{prefix}_ID_CLIENTE"));
            let secret = var(&format!("TUNEL_{prefix}_SECRETO"));
            match (id, secret) {
                (Some(id), Some(secret)) => Ok(Some((id, secret))),
                (None, None) => Ok(None),
                _ => Err(format!(
                    "TUNEL_{prefix}_ID_CLIENTE y TUNEL_{prefix}_SECRETO van juntos"
                )),
            }
        };
        let mut providers = Vec::new();
        if let Some((client_id, client_secret)) = pair("GOOGLE")? {
            providers.push(ProviderConfig {
                id: "google".into(),
                name: "Google".into(),
                issuer: "https://accounts.google.com".into(),
                client_id,
                client_secret,
                trusted_tenant: false,
            });
        }
        if let Some((client_id, client_secret)) = pair("MICROSOFT")? {
            let tenant = var("TUNEL_MICROSOFT_INQUILINO").ok_or(
                "falta TUNEL_MICROSOFT_INQUILINO: el ID del directorio (inquilino) de tu \
                 organización en Microsoft Entra",
            )?;
            let well_formed = tenant.split('.').all(|label| {
                !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
            if SHARED_TENANTS.contains(&tenant.to_lowercase().as_str()) || !well_formed {
                return Err(
                    "TUNEL_MICROSOFT_INQUILINO tiene que ser el ID del directorio de tu \
                     organización, no «common», «organizations» ni «consumers»"
                        .into(),
                );
            }
            providers.push(ProviderConfig {
                id: "microsoft".into(),
                name: "Microsoft 365".into(),
                issuer: format!("https://login.microsoftonline.com/{tenant}/v2.0"),
                client_id,
                client_secret,
                trusted_tenant: true,
            });
        }
        if let Some((client_id, client_secret)) = pair("OIDC")? {
            let issuer = var("TUNEL_OIDC_EMISOR")
                .ok_or("falta TUNEL_OIDC_EMISOR, la dirección del emisor OpenID Connect")?;
            if !issuer.starts_with("https://") {
                return Err("TUNEL_OIDC_EMISOR tiene que empezar por https://".into());
            }
            providers.push(ProviderConfig {
                id: "oidc".into(),
                name: var("TUNEL_OIDC_NOMBRE").unwrap_or_else(|| "OpenID Connect".into()),
                issuer: issuer.trim_end_matches('/').to_string(),
                client_id,
                client_secret,
                trusted_tenant: false,
            });
        }
        if providers.is_empty() {
            return Ok(None);
        }
        let public_url = var("TUNEL_URL_PUBLICA").ok_or(
            "falta TUNEL_URL_PUBLICA, la dirección https con la que se llega al servidor; \
             con ella se forma la dirección de retorno de los proveedores",
        )?;
        if !public_url.starts_with("https://") {
            return Err("TUNEL_URL_PUBLICA tiene que empezar por https://".into());
        }
        Ok(Some(Self {
            public_url: public_url.trim_end_matches('/').to_string(),
            providers,
            allow_http: false,
        }))
    }

    fn provider(&self, id: &str) -> ApiResult<&ProviderConfig> {
        self.providers
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| ApiError::not_found("proveedor de identidad"))
    }

    fn redirect_uri(&self, provider: &str) -> String {
        format!("{}/v1/auth/{provider}/callback", self.public_url)
    }
}

/// Lo que publica cada proveedor en `/.well-known/openid-configuration`.
#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

/// Un inicio de sesión a medias, mientras la persona está en el navegador.
struct Flow {
    provider: String,
    /// Reto PKCE de Túnel.
    challenge: String,
    port: u16,
    /// Lo que Túnel mandó como `state`: se le devuelve para que compruebe que la vuelta es
    /// la del inicio de sesión que empezó.
    app_state: String,
    nonce: String,
    /// Verificador PKCE ante el proveedor.
    verifier: String,
    created: Instant,
}

/// Resultado esperando a que Túnel lo canjee.
enum Outcome {
    Existing {
        account: i64,
        email: String,
        kdf: tunel_core::crypto::KdfParams,
        salt: String,
        vault_key: SealedBlob,
    },
    /// La persona y el proveedor con el que creará la cuenta.
    New(Identity, String),
}

struct Pending {
    challenge: String,
    outcome: Outcome,
    created: Instant,
}

/// Permiso para crear la cuenta de quien ya demostró su correo.
struct Ticket {
    identity: Identity,
    provider: String,
    created: Instant,
}

/// Estado del inicio de sesión con proveedores.
pub struct OAuth {
    config: OAuthConfig,
    http: reqwest::Client,
    discovery: Mutex<HashMap<String, Discovery>>,
    flows: Mutex<HashMap<String, Flow>>,
    codes: Mutex<HashMap<String, Pending>>,
    tickets: Mutex<HashMap<String, Ticket>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn random_token() -> String {
    B64_URL.encode(rand::random::<[u8; 32]>())
}

fn pkce_challenge(verifier: &str) -> String {
    B64_URL.encode(Sha256::digest(verifier.as_bytes()))
}

/// Guarda `value`. Si no cabe, quita lo caducado y, si aún no cabe, lo más antiguo.
fn insert_bounded<T>(
    map: &Mutex<HashMap<String, T>>,
    key: String,
    value: T,
    created: impl Fn(&T) -> Instant,
    ttl: Duration,
) {
    let mut map = lock(map);
    if map.len() >= MAX_PENDING {
        map.retain(|_, v| created(v).elapsed() < ttl);
    }
    if map.len() >= MAX_PENDING
        && let Some(oldest) = map
            .iter()
            .min_by_key(|(_, v)| created(v))
            .map(|(k, _)| k.clone())
    {
        map.remove(&oldest);
    }
    map.insert(key, value);
}

impl OAuth {
    pub fn new(config: OAuthConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .https_only(!config.allow_http)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("tunel-server/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            config,
            http,
            discovery: Mutex::default(),
            flows: Mutex::default(),
            codes: Mutex::default(),
            tickets: Mutex::default(),
        })
    }

    pub fn providers(&self) -> &[ProviderConfig] {
        &self.config.providers
    }

    async fn read_json<T: serde::de::DeserializeOwned>(
        mut response: reqwest::Response,
    ) -> Result<T, String> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err("respuesta demasiado grande".into());
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| format!("respuesta no válida: {e}"))
    }

    /// Configuración del proveedor; se pide una vez y se recuerda.
    async fn discovery(&self, provider: &ProviderConfig) -> Result<Discovery, String> {
        if let Some(found) = lock(&self.discovery).get(&provider.id) {
            return Ok(found.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", provider.issuer);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !response.status().is_success() {
            return Err(format!("respondió {}", response.status()));
        }
        let found: Discovery = Self::read_json(response).await?;
        // El emisor tiene que ser el configurado. En Microsoft, si el inquilino se dio por
        // su dominio, el emisor lleva su identificador: basta con que sea de Microsoft.
        let issuer_ok = found.issuer.trim_end_matches('/') == provider.issuer
            || (provider.trusted_tenant
                && found
                    .issuer
                    .starts_with("https://login.microsoftonline.com/")
                && found.issuer.ends_with("/v2.0"));
        if !issuer_ok {
            return Err("su emisor no es el configurado".into());
        }
        let secure = |url: &str| self.config.allow_http || url.starts_with("https://");
        if !secure(&found.authorization_endpoint) || !secure(&found.token_endpoint) {
            return Err("sus direcciones no usan https".into());
        }
        lock(&self.discovery).insert(provider.id.clone(), found.clone());
        Ok(found)
    }

    /// Canjea el código del proveedor por el ID token y devuelve sus datos ya comprobados.
    async fn exchange(
        &self,
        provider: &ProviderConfig,
        discovery: &Discovery,
        code: &str,
        flow: &Flow,
    ) -> Result<Identity, String> {
        let redirect_uri = self.config.redirect_uri(&provider.id);
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
            ("code_verifier", &flow.verifier),
        ];
        let response = self
            .http
            .post(&discovery.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "el proveedor rechazó el código ({})",
                response.status()
            ));
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let tokens: TokenResponse = Self::read_json(response).await?;
        let claims = decode_claims(&tokens.id_token).ok_or("ID token no válido")?;
        verify_claims(
            &claims,
            &discovery.issuer,
            &provider.client_id,
            &flow.nonce,
            now(),
            provider.trusted_tenant,
        )
        .map_err(str::to_string)
    }
}

/// Lo que se usa del ID token.
#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    /// Un destinatario o una lista.
    aud: serde_json::Value,
    exp: i64,
    nonce: Option<String>,
    /// Identificador estable de la persona en el proveedor.
    sub: Option<String>,
    email: Option<String>,
    /// Algunos proveedores lo mandan como texto.
    email_verified: Option<serde_json::Value>,
    /// Microsoft: inquilino y objeto de la persona, que no cambian.
    tid: Option<String>,
    oid: Option<String>,
    /// Microsoft: la organización es dueña del dominio del correo. Hay que pedirlo como
    /// notificación opcional en el registro de la aplicación.
    xms_edov: Option<serde_json::Value>,
}

/// Quién es la persona según el proveedor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    email: String,
    /// Identificador estable: `sub`, o `tid:oid` en Microsoft.
    subject: String,
}

/// Un valor verdadero, como `true` o `"true"`.
fn is_true(value: &Option<serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true" || s == "1",
        Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

/// Datos del ID token, sin comprobar la firma: llega directamente del proveedor por TLS
/// en respuesta al canje del código, y OpenID Connect admite fiarse de ese canal (Core
/// 1.0, apartado 3.1.3.7).
fn decode_claims(id_token: &str) -> Option<Claims> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = B64_URL.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Comprueba el ID token y devuelve quién es la persona.
fn verify_claims(
    claims: &Claims,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
    trusted_tenant: bool,
) -> Result<Identity, &'static str> {
    if claims.iss != issuer {
        return Err("el ID token es de otro emisor");
    }
    let audience_ok = match &claims.aud {
        serde_json::Value::String(aud) => aud == client_id,
        serde_json::Value::Array(list) => list.iter().any(|a| a.as_str() == Some(client_id)),
        _ => false,
    };
    if !audience_ok {
        return Err("el ID token es para otra aplicación");
    }
    if claims.exp <= now {
        return Err("el ID token caducó");
    }
    if claims.nonce.as_deref() != Some(nonce) {
        return Err("el ID token no corresponde a este inicio de sesión");
    }
    let non_empty = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
    let (verified, subject) = if trusted_tenant {
        // En Microsoft el correo no está verificado salvo que la organización sea dueña
        // de su dominio; `preferred_username` puede cambiar y no identifica a nadie.
        let subject = match (non_empty(&claims.tid), non_empty(&claims.oid)) {
            (Some(tid), Some(oid)) => Some(format!("{tid}:{oid}")),
            _ => None,
        };
        (is_true(&claims.xms_edov), subject)
    } else {
        (is_true(&claims.email_verified), non_empty(&claims.sub))
    };
    let subject = subject.ok_or("el proveedor no identificó a la persona")?;
    if !verified {
        return Err("el proveedor no ha verificado ese correo");
    }
    let email = non_empty(&claims.email)
        .filter(|e| e.contains('@'))
        .ok_or("el proveedor no dio un correo")?;
    Ok(Identity { email, subject })
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/auth/providers", get(list_providers))
        .route("/v1/auth/{provider}/start", get(start))
        .route("/v1/auth/{provider}/callback", get(callback))
        .route("/v1/auth/token", post(token))
        .route("/v1/accounts/oauth", post(register))
        .route("/v1/accounts/current/vault-key", put(update_vault_key))
}

fn oauth(state: &AppState) -> ApiResult<&OAuth> {
    state
        .oauth
        .as_ref()
        .ok_or_else(|| ApiError::not_found("proveedor de identidad"))
}

async fn list_providers(State(state): State<Arc<AppState>>) -> Json<AuthProviders> {
    let providers = state
        .oauth
        .as_ref()
        .map(|o| {
            o.providers()
                .iter()
                .map(|p| AuthProvider {
                    id: p.id.clone(),
                    name: p.name.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    Json(AuthProviders { providers })
}

#[derive(Deserialize)]
struct StartQuery {
    port: u16,
    challenge: String,
    /// Valor aleatorio de Túnel que vuelve con la respuesta.
    state: String,
}

/// Valor en base64 apto para URL de entre `min` y `max` caracteres.
fn url_token(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Una página corta para el navegador cuando no se puede volver a Túnel.
fn page(status: StatusCode, message: &str) -> Response {
    let message = escape_html(message);
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>Túnel</title>\
         <body style=\"font-family:system-ui;margin:3em\"><h2>Túnel</h2><p>{message}</p>"
    );
    (status, Html(html)).into_response()
}

async fn start(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(query): Query<StartQuery>,
) -> ApiResult<Response> {
    take_unauthenticated(&state)?;
    let oauth = oauth(&state)?;
    let config = oauth.config.provider(&provider)?.clone();
    if query.port < 1024 {
        return Err(ApiError::bad_request("puerto no válido"));
    }
    if !url_token(&query.challenge, 43, 43) || !url_token(&query.state, 16, 64) {
        return Err(ApiError::bad_request("reto no válido"));
    }
    let discovery = match oauth.discovery(&config).await {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!(provider, error = %e, "no se pudo leer la configuración del proveedor");
            return Ok(page(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "No se pudo contactar con {}. Inténtalo más tarde.",
                    config.name
                ),
            ));
        }
    };
    let flow_state = random_token();
    let flow = Flow {
        provider: provider.clone(),
        challenge: query.challenge,
        port: query.port,
        app_state: query.state,
        nonce: random_token(),
        verifier: random_token(),
        created: Instant::now(),
    };
    let redirect_uri = oauth.config.redirect_uri(&provider);
    let url = reqwest::Url::parse_with_params(
        &discovery.authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", "openid email profile"),
            ("state", flow_state.as_str()),
            ("nonce", flow.nonce.as_str()),
            ("code_challenge", pkce_challenge(&flow.verifier).as_str()),
            ("code_challenge_method", "S256"),
            ("prompt", "select_account"),
        ],
    )
    .map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "el proveedor dio una dirección no válida",
        )
    })?;
    insert_bounded(&oauth.flows, flow_state, flow, |f| f.created, FLOW_TTL);
    Ok(Redirect::to(url.as_str()).into_response())
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Devuelve el navegador a Túnel, con el código o con el motivo del error, y su `state`.
fn back_to_app(flow: &Flow, param: (&str, &str)) -> Response {
    let base = format!("http://127.0.0.1:{}/oauth", flow.port);
    let params = [param, ("state", flow.app_state.as_str())];
    match reqwest::Url::parse_with_params(&base, &params) {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(_) => page(StatusCode::BAD_REQUEST, "No se pudo volver a Túnel."),
    }
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

async fn callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Response> {
    let oauth = oauth(&state)?;
    let flow = query
        .state
        .as_deref()
        .and_then(|s| lock(&oauth.flows).remove(s))
        .filter(|f| f.created.elapsed() < FLOW_TTL && f.provider == provider);
    let Some(flow) = flow else {
        return Ok(page(
            StatusCode::BAD_REQUEST,
            "Este inicio de sesión caducó o ya se usó. Vuelve a empezarlo desde Túnel.",
        ));
    };
    let config = oauth.config.provider(&provider)?.clone();
    if let Some(error) = query.error {
        let detail = query.error_description.unwrap_or(error);
        let message = format!(
            "{} rechazó el inicio de sesión: {}",
            config.name,
            clip(&detail)
        );
        return Ok(back_to_app(&flow, ("error", &message)));
    }
    let Some(code) = query.code else {
        return Ok(back_to_app(
            &flow,
            ("error", "el proveedor no devolvió ningún código"),
        ));
    };
    let result = match oauth.discovery(&config).await {
        Ok(discovery) => oauth.exchange(&config, &discovery, &code, &flow).await,
        Err(e) => Err(e),
    };
    let identity = match result {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!(provider, error = %e, "inicio de sesión con proveedor rechazado");
            let message = format!(
                "no se pudo completar el inicio de sesión con {}: {e}",
                config.name
            );
            return Ok(back_to_app(&flow, ("error", &message)));
        }
    };
    let outcome = match decide(&state, &config, identity).await {
        Ok(outcome) => outcome,
        Err(message) => return Ok(back_to_app(&flow, ("error", &message))),
    };
    let code = random_token();
    let pending = Pending {
        challenge: flow.challenge.clone(),
        outcome,
        created: Instant::now(),
    };
    insert_bounded(&oauth.codes, code.clone(), pending, |p| p.created, CODE_TTL);
    Ok(back_to_app(&flow, ("code", &code)))
}

/// Qué hacer con una persona ya confirmada por el proveedor.
async fn decide(
    state: &AppState,
    provider: &ProviderConfig,
    identity: Identity,
) -> Result<Outcome, String> {
    let internal = |_| "error interno del servidor".to_string();
    // La cuenta ligada a esta persona, aunque su correo haya cambiado desde entonces.
    let linked = state
        .db
        .account_by_oauth(provider.id.clone(), identity.subject.clone())
        .await
        .map_err(internal)?;
    if let Some(account) = linked {
        let email = state.db.account_email(account.id).await.map_err(internal)?;
        return Ok(Outcome::Existing {
            account: account.id,
            email,
            kdf: account.kdf,
            salt: account.salt,
            vault_key: account.vault_key,
        });
    }
    let email = normalize_email(&identity.email)
        .map_err(|_| "el proveedor dio un correo no válido".to_string())?;
    let allowed = &state.config.allowed_domains;
    if !domain_allowed(allowed, &email) {
        let list = allowed
            .iter()
            .map(|d| format!("@{d}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "este servidor solo admite cuentas con correos {list}"
        ));
    }
    match state
        .db
        .account_by_email(email.clone())
        .await
        .map_err(internal)?
    {
        // Otra persona, u otro proveedor, ya tiene una cuenta con este correo.
        Some(account) if account.oauth.is_some() => Err(format!(
            "ya hay una cuenta con {email} ligada a otro inicio de sesión; entra con el \
             proveedor y la cuenta con los que la creaste"
        )),
        Some(_) => Err(format!(
            "ya hay una cuenta con {email} que entra con contraseña; inicia sesión con ella"
        )),
        // Sin dominios permitidos ni registro abierto, Google o un emisor genérico
        // abrirían el servidor a cualquier correo del mundo. Un inquilino de Microsoft
        // concreto ya limita las cuentas a esa organización.
        None if state.config.open_registration
            || !allowed.is_empty()
            || provider.trusted_tenant =>
        {
            Ok(Outcome::New(
                Identity { email, ..identity },
                provider.id.clone(),
            ))
        }
        None => Err(format!(
            "este servidor no admite cuentas nuevas con {}; pide al administrador que \
             configure TUNEL_DOMINIOS_PERMITIDOS",
            provider.name
        )),
    }
}

async fn new_session(state: &AppState, account: i64) -> ApiResult<String> {
    let (token, hash) = auth::new_token();
    let expires = now() + state.config.session_ttl.as_secs() as i64;
    state.db.insert_session(hash, account, expires).await?;
    Ok(token)
}

async fn token(
    State(state): State<Arc<AppState>>,
    Json(request): Json<OAuthTokenRequest>,
) -> ApiResult<Json<OAuthLogin>> {
    take_unauthenticated(&state)?;
    let oauth = oauth(&state)?;
    let invalid = || ApiError::bad_request("código caducado o no válido; vuelve a iniciar sesión");
    let pending = lock(&oauth.codes)
        .remove(&request.code)
        .filter(|p| p.created.elapsed() < CODE_TTL)
        .ok_or_else(invalid)?;
    let proof = pkce_challenge(&request.verifier);
    if !bool::from(proof.as_bytes().ct_eq(pending.challenge.as_bytes())) {
        return Err(invalid());
    }
    Ok(Json(match pending.outcome {
        Outcome::Existing {
            account,
            email,
            kdf,
            salt,
            vault_key,
        } => OAuthLogin::Existing {
            email,
            token: new_session(&state, account).await?,
            kdf,
            salt,
            vault_key,
        },
        Outcome::New(identity, provider) => {
            let ticket = random_token();
            let email = identity.email.clone();
            let entry = Ticket {
                identity,
                provider,
                created: Instant::now(),
            };
            insert_bounded(
                &oauth.tickets,
                ticket.clone(),
                entry,
                |t| t.created,
                TICKET_TTL,
            );
            OAuthLogin::New { email, ticket }
        }
    }))
}

/// Clave de acceso que nadie conoce: la cuenta solo entra a través del proveedor.
fn unusable_auth(kdf: tunel_core::crypto::KdfParams) -> StoredHash {
    StoredHash {
        salt: rand::random::<[u8; 16]>().to_vec(),
        hash: rand::random::<[u8; 32]>().to_vec(),
        kdf,
    }
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<OAuthRegisterRequest>,
) -> ApiResult<(StatusCode, Json<OAuthRegisterResponse>)> {
    take_unauthenticated(&state)?;
    let oauth = oauth(&state)?;
    check_account_kdf(&request.salt, request.kdf)?;
    check_blob(&request.vault_key, MAX_VAULT_KEY_CIPHERTEXT)?;
    let ticket = lock(&oauth.tickets)
        .remove(&request.ticket)
        .filter(|t| t.created.elapsed() < TICKET_TTL)
        .ok_or_else(|| ApiError::bad_request("permiso caducado; vuelve a iniciar sesión"))?;
    let account = state
        .db
        .insert_oauth_account(NewOAuthAccount {
            email: ticket.identity.email,
            subject: ticket.identity.subject,
            provider: ticket.provider,
            kdf: request.kdf,
            salt: request.salt,
            unusable_auth: unusable_auth(state.config.auth_kdf),
            vault_key: request.vault_key,
            created_at: now(),
        })
        .await?;
    let token = new_session(&state, account).await?;
    Ok((StatusCode::CREATED, Json(OAuthRegisterResponse { token })))
}

async fn update_vault_key(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(request): Json<VaultKeyUpdate>,
) -> ApiResult<StatusCode> {
    check_account_kdf(&request.salt, request.kdf)?;
    check_blob(&request.vault_key, MAX_VAULT_KEY_CIPHERTEXT)?;
    match state
        .db
        .set_oauth_vault_key(
            session.account,
            request.previous,
            request.kdf,
            request.salt,
            request.vault_key,
        )
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(crate::db::DbError::Conflict) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "la clave de bóveda cambió desde que iniciaste sesión; vuelve a iniciarla",
        )),
        Err(crate::db::DbError::NotFound) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "solo las cuentas de un proveedor de identidad cambian así su clave",
        )),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://accounts.google.com";
    const CLIENT: &str = "cliente.apps.googleusercontent.com";

    fn claims(extra: serde_json::Value) -> Claims {
        let mut base = json!({
            "iss": ISSUER,
            "aud": CLIENT,
            "exp": 2_000,
            "nonce": "n0",
            "sub": "1234567890",
            "email": "ana@empresa.com",
            "email_verified": true,
        });
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    fn identity(claims: &Claims, trusted: bool) -> Result<Identity, &'static str> {
        verify_claims(claims, ISSUER, CLIENT, "n0", 1_000, trusted)
    }

    fn email(claims: &Claims, trusted: bool) -> Result<String, &'static str> {
        identity(claims, trusted).map(|i| i.email)
    }

    #[test]
    fn a_valid_id_token_gives_the_person() {
        let found = identity(&claims(json!({})), false).unwrap();
        assert_eq!(found.email, "ana@empresa.com");
        assert_eq!(found.subject, "1234567890");
        let listed = claims(json!({"aud": ["otra", CLIENT], "email_verified": "true"}));
        assert_eq!(email(&listed, false).as_deref(), Ok("ana@empresa.com"));
    }

    #[test]
    fn issuer_audience_expiry_and_nonce_are_checked() {
        for bad in [
            json!({"iss": "https://evil.example.com"}),
            json!({"aud": "otra-app"}),
            json!({"aud": ["otra-app"]}),
            json!({"exp": 999}),
            json!({"nonce": "otro"}),
            json!({"nonce": null}),
        ] {
            assert!(identity(&claims(bad.clone()), false).is_err(), "{bad}");
        }
    }

    #[test]
    fn unverified_emails_or_unknown_people_are_rejected() {
        for bad in [
            json!({"email_verified": false}),
            json!({"email_verified": null}),
            json!({"email_verified": "no"}),
            json!({"sub": null}),
            json!({"sub": ""}),
            json!({"email": null}),
            json!({"email": "sin-arroba"}),
        ] {
            assert!(identity(&claims(bad.clone()), false).is_err(), "{bad}");
        }
    }

    fn microsoft(extra: serde_json::Value) -> Claims {
        let mut base = json!({
            "email_verified": null,
            "tid": "t1",
            "oid": "o1",
            "xms_edov": true,
        });
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        claims(base)
    }

    #[test]
    fn microsoft_needs_tenant_object_and_a_domain_owned_email() {
        let found = identity(&microsoft(json!({})), true).unwrap();
        assert_eq!(found.subject, "t1:o1");
        assert_eq!(found.email, "ana@empresa.com");
        // Sin `xms_edov`, el correo puede ser cualquiera que alguien escribió.
        for bad in [
            json!({"xms_edov": false}),
            json!({"xms_edov": null}),
            json!({"oid": null}),
            json!({"tid": null}),
            // `preferred_username` no sirve como correo.
            json!({"email": null, "preferred_username": "ana@empresa.com"}),
        ] {
            assert!(identity(&microsoft(bad.clone()), true).is_err(), "{bad}");
        }
    }

    #[test]
    fn id_tokens_are_decoded_from_their_payload() {
        let payload = B64_URL
            .encode(json!({"iss": ISSUER, "aud": CLIENT, "exp": 5, "email": "x@y.z"}).to_string());
        let token = format!("cabecera.{payload}.firma");
        let claims = decode_claims(&token).unwrap();
        assert_eq!(claims.email.as_deref(), Some("x@y.z"));
        assert!(decode_claims("no-es-un-token").is_none());
        assert!(decode_claims("a.%%%.c").is_none());
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| vars.get(name).cloned()
    }

    #[test]
    fn no_providers_means_no_oauth() {
        assert!(OAuthConfig::from_env(env(&[])).unwrap().is_none());
    }

    #[test]
    fn providers_are_read_from_the_environment() {
        let config = OAuthConfig::from_env(env(&[
            ("TUNEL_URL_PUBLICA", "https://tunel.empresa.com/"),
            ("TUNEL_GOOGLE_ID_CLIENTE", "g-id"),
            ("TUNEL_GOOGLE_SECRETO", "g-secreto"),
            ("TUNEL_MICROSOFT_ID_CLIENTE", "m-id"),
            ("TUNEL_MICROSOFT_SECRETO", "m-secreto"),
            (
                "TUNEL_MICROSOFT_INQUILINO",
                "0a1b2c3d-1111-2222-3333-444455556666",
            ),
            ("TUNEL_OIDC_ID_CLIENTE", "o-id"),
            ("TUNEL_OIDC_SECRETO", "o-secreto"),
            ("TUNEL_OIDC_EMISOR", "https://sso.empresa.com/realms/x/"),
            ("TUNEL_OIDC_NOMBRE", "Keycloak"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(config.public_url, "https://tunel.empresa.com");
        let ids: Vec<_> = config.providers.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["google", "microsoft", "oidc"]);
        assert_eq!(
            config.providers[1].issuer,
            "https://login.microsoftonline.com/0a1b2c3d-1111-2222-3333-444455556666/v2.0"
        );
        assert_eq!(
            config.providers[2].issuer,
            "https://sso.empresa.com/realms/x"
        );
        assert_eq!(config.providers[2].name, "Keycloak");
        assert_eq!(
            config.redirect_uri("google"),
            "https://tunel.empresa.com/v1/auth/google/callback"
        );
        // El secreto no aparece al depurar.
        assert!(!format!("{config:?}").contains("secreto"));
    }

    #[test]
    fn incomplete_or_unsafe_settings_are_rejected() {
        let google = [
            ("TUNEL_GOOGLE_ID_CLIENTE", "g"),
            ("TUNEL_GOOGLE_SECRETO", "s"),
        ];
        // Sin dirección pública.
        assert!(OAuthConfig::from_env(env(&google)).is_err());
        let with_url = |extra: &[(&'static str, &'static str)]| {
            let mut vars = vec![("TUNEL_URL_PUBLICA", "https://t.empresa.com")];
            vars.extend_from_slice(extra);
            OAuthConfig::from_env(env(&vars))
        };
        assert!(with_url(&[("TUNEL_GOOGLE_ID_CLIENTE", "g")]).is_err());
        for tenant in [
            "common",
            "Organizations",
            "consumers",
            "9188040d-6c67-4c5b-b112-36a304b66dad",
            "x/../y",
            "..",
            ".empresa.com",
        ] {
            let microsoft = [
                ("TUNEL_MICROSOFT_ID_CLIENTE", "m"),
                ("TUNEL_MICROSOFT_SECRETO", "s"),
                ("TUNEL_MICROSOFT_INQUILINO", tenant),
            ];
            assert!(with_url(&microsoft).is_err(), "{tenant}");
        }
        let no_tenant = [
            ("TUNEL_MICROSOFT_ID_CLIENTE", "m"),
            ("TUNEL_MICROSOFT_SECRETO", "s"),
        ];
        assert!(with_url(&no_tenant).is_err());
        let http_issuer = [
            ("TUNEL_OIDC_ID_CLIENTE", "o"),
            ("TUNEL_OIDC_SECRETO", "s"),
            ("TUNEL_OIDC_EMISOR", "http://sso.empresa.com"),
        ];
        assert!(with_url(&http_issuer).is_err());
        let http_url = [
            ("TUNEL_URL_PUBLICA", "http://t.empresa.com"),
            ("TUNEL_GOOGLE_ID_CLIENTE", "g"),
            ("TUNEL_GOOGLE_SECRETO", "s"),
        ];
        assert!(OAuthConfig::from_env(env(&http_url)).is_err());
    }

    #[test]
    fn pages_escape_html() {
        assert_eq!(
            escape_html("<b>\"x\" & y</b>"),
            "&lt;b&gt;&quot;x&quot; &amp; y&lt;/b&gt;"
        );
    }

    #[test]
    fn a_full_map_drops_the_oldest_entry() {
        let map = Mutex::new(HashMap::new());
        let start = Instant::now();
        for i in 0..MAX_PENDING {
            let created = start + Duration::from_millis(i as u64);
            insert_bounded(&map, format!("k{i}"), created, |t| *t, FLOW_TTL);
        }
        let newest = start + Duration::from_secs(60);
        insert_bounded(&map, "nuevo".into(), newest, |t| *t, FLOW_TTL);
        let map = map.into_inner().unwrap();
        assert_eq!(map.len(), MAX_PENDING);
        assert!(map.contains_key("nuevo"));
        assert!(!map.contains_key("k0"));
    }

    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        // Ejemplo del apéndice B de la RFC 7636.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
