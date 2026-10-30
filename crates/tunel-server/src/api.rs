//! Rutas HTTP del servidor de sincronización.

use crate::auth::{self, AuthHasher, HashError, LoginLimiter, RateBucket};
use crate::db::{Db, DbError, NewAccount, Quota, Rotation, Space};
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tunel_core::crypto::{KdfParams, NONCE_LEN};
use tunel_core::sync::keys::{MAX_RECORD_CIPHERTEXT, MIN_SALT_LEN, RECORD_ID_LEN, kdf_is_strong};
use tunel_core::sync::protocol::*;
use tunel_core::sync::{SealedBlob, SealedRecord};

/// Ajustes del servidor.
#[derive(Debug, Clone)]
pub struct Config {
    /// Cualquiera puede crear una cuenta. Si es `false`, solo se puede crear la primera.
    pub open_registration: bool,
    /// Dominios de correo con los que se pueden crear cuentas, en minúsculas. Vacío admite
    /// cualquiera. Si hay alguno, el registro queda abierto para esos dominios aunque
    /// `open_registration` sea `false`.
    pub allowed_domains: Vec<String>,
    /// Argon2id con el que el servidor guarda el hash de las claves de acceso nuevas.
    pub auth_kdf: KdfParams,
    /// Hashes de Argon2id que se calculan a la vez como mucho.
    pub concurrent_hashes: usize,
    /// Cuánto espera turno un hash antes de responder que el servidor está ocupado.
    pub hash_queue_wait: Duration,
    /// Peticiones por segundo, y ráfaga, en las rutas sin sesión (todas las cuentas juntas).
    pub unauthenticated_per_second: u32,
    pub unauthenticated_burst: u32,
    pub session_ttl: Duration,
    pub quota: Quota,
    pub login_attempts: u32,
    pub login_window: Duration,
    /// Cuentas con intentos fallidos que se vigilan a la vez como mucho.
    pub max_tracked_logins: usize,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    /// Equipos de los que puede ser miembro una cuenta.
    pub max_teams_per_account: u64,
    pub max_team_members: u64,
    /// Invitaciones sin responder que puede acumular una cuenta.
    pub max_pending_invitations: u64,
    /// Límites de cada equipo. Más pequeños que los de una cuenta: al renovar la clave
    /// todo el equipo se sube en una sola petición de como mucho `MAX_ROTATE_BODY`.
    pub team_quota: Quota,
    /// Renovaciones de clave que se procesan a la vez como mucho.
    pub concurrent_rotations: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            open_registration: false,
            allowed_domains: Vec::new(),
            auth_kdf: KdfParams {
                memory_kib: 19 * 1024,
                iterations: 2,
                parallelism: 1,
            },
            concurrent_hashes: 4,
            hash_queue_wait: Duration::from_secs(5),
            unauthenticated_per_second: 10,
            unauthenticated_burst: 30,
            session_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            quota: Quota {
                records: 20_000,
                bytes: 256 * 1024 * 1024,
            },
            login_attempts: 5,
            login_window: Duration::from_secs(15 * 60),
            max_tracked_logins: 10_000,
            request_timeout: Duration::from_secs(30),
            max_concurrent_requests: 256,
            max_teams_per_account: 20,
            max_team_members: 200,
            max_pending_invitations: 20,
            team_quota: Quota {
                records: 5_000,
                bytes: 32 * 1024 * 1024,
            },
            concurrent_rotations: 2,
        }
    }
}

/// Parámetros de Argon2id de todas las cuentas. Son los mismos que se inventan para un
/// correo sin cuenta, así el prelogin no distingue unas de otras.
pub const ACCOUNT_KDF: KdfParams = KdfParams::RECOMMENDED;
/// Tamaño máximo del cuerpo en las rutas de cuentas y sesiones.
const MAX_AUTH_BODY: usize = 8 * 1024;
/// Tamaño máximo del cuerpo al subir registros.
const MAX_PUSH_BODY: usize = 16 * 1024 * 1024;
/// Al renovar la clave de un equipo se sube todo su contenido de una vez: cabe la cuota
/// de un equipo con el JSON alrededor.
const MAX_ROTATE_BODY: usize = 48 * 1024 * 1024;
/// El nombre de un equipo cifrado, con relleno de sobra.
const MAX_TEAM_NAME_CIPHERTEXT: usize = 512;
/// Tamaño máximo del manifiesto cifrado en base64.
const MAX_MANIFEST_CIPHERTEXT: usize = 8 * 1024 * 1024;
/// La clave de bóveda envuelta ocupa unos 64 bytes en base64; se deja margen.
const MAX_VAULT_KEY_CIPHERTEXT: usize = 256;
const MAX_EMAIL_LEN: usize = 254;
/// Cada cuánto se borran las sesiones caducadas.
const SESSION_SWEEP: Duration = Duration::from_secs(60 * 60);

pub struct AppState {
    pub db: Db,
    pub config: Config,
    hasher: AuthHasher,
    limiter: LoginLimiter,
    unauthenticated: RateBucket,
    rotations: tokio::sync::Semaphore,
    secret: [u8; 32],
}

impl AppState {
    pub async fn new(db: Db, config: Config) -> anyhow::Result<Arc<Self>> {
        let secret = db.server_secret().await?;
        Ok(Arc::new(Self {
            hasher: AuthHasher::new(
                config.auth_kdf,
                config.concurrent_hashes,
                config.hash_queue_wait,
            )?,
            limiter: LoginLimiter::new(
                config.login_attempts,
                config.login_window,
                config.max_tracked_logins,
            ),
            unauthenticated: RateBucket::new(
                config.unauthenticated_per_second,
                config.unauthenticated_burst,
            ),
            rotations: tokio::sync::Semaphore::new(config.concurrent_rotations),
            db,
            config,
            secret,
        }))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let auth_routes = Router::new()
        .route("/v1/prelogin", post(prelogin))
        .route("/v1/accounts", post(register))
        .route("/v1/sessions", post(login))
        .route("/v1/sessions/current", delete(logout))
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY));
    let record_routes = Router::new()
        .route("/v1/records", get(pull).post(push))
        .route("/v1/teams/{team}/records", get(team_pull).post(team_push))
        .layer(DefaultBodyLimit::max(MAX_PUSH_BODY));
    let team_routes = Router::new()
        .route("/v1/keys", get(own_keys).put(upload_keys))
        .route("/v1/users/{email}/key", get(user_key))
        .route("/v1/teams", get(list_teams).post(create_team))
        .route("/v1/teams/{team}", delete(delete_team))
        .route("/v1/teams/{team}/accept", post(accept_invitation))
        .route(
            "/v1/teams/{team}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/v1/teams/{team}/members/{email}",
            patch(update_member).delete(remove_member),
        )
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY));
    let rotate_routes = Router::new()
        .route("/v1/teams/{team}/rotate", post(rotate_team))
        .layer(DefaultBodyLimit::max(MAX_ROTATE_BODY));
    let config = &state.config;
    Router::new()
        .merge(auth_routes)
        .merge(record_routes)
        .merge(team_routes)
        .merge(rotate_routes)
        .route("/health", get(|| async { "ok" }))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ))
        .layer(GlobalConcurrencyLimitLayer::new(
            config.max_concurrent_requests,
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

/// Borra de vez en cuando las sesiones caducadas.
pub fn spawn_session_sweeper(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(SESSION_SWEEP);
        loop {
            ticks.tick().await;
            if let Err(e) = state.db.purge_sessions(now()).await {
                tracing::warn!(error = %e, "no se pudieron borrar las sesiones caducadas");
            }
        }
    })
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "credenciales no válidas")
    }

    fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, format!("{what} no encontrado"))
    }

    fn too_many() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "demasiados intentos; espera unos minutos",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::AccountExists
            | DbError::Conflict
            | DbError::KeysExist
            | DbError::NoKeys
            | DbError::TeamExists
            | DbError::AlreadyMember => Self::new(StatusCode::CONFLICT, e.to_string()),
            // Distinto de 409: no se arregla volviendo a descargar.
            DbError::RekeyNeeded => Self::new(StatusCode::LOCKED, e.to_string()),
            DbError::RegistrationClosed | DbError::Limit(_) => {
                Self::new(StatusCode::FORBIDDEN, e.to_string())
            }
            DbError::NotFound => Self::new(StatusCode::NOT_FOUND, e.to_string()),
            DbError::LastAdmin | DbError::MembersMismatch => Self::bad_request(e.to_string()),
            DbError::QuotaExceeded => Self::new(StatusCode::INSUFFICIENT_STORAGE, e.to_string()),
            DbError::BadVersion => Self::bad_request(e.to_string()),
            other => {
                tracing::error!(error = %other, "error de base de datos");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "error interno")
            }
        }
    }
}

impl From<HashError> for ApiError {
    fn from(e: HashError) -> Self {
        match e {
            HashError::Busy => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "servidor ocupado; inténtalo en un momento",
            ),
            HashError::Internal(e) => e.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "error interno");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "error interno")
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn normalize_email(email: &str) -> ApiResult<String> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= MAX_EMAIL_LEN
        && email
            .split_once('@')
            .is_some_and(|(user, domain)| !user.is_empty() && !domain.is_empty())
        && !email.chars().any(char::is_whitespace);
    if valid {
        Ok(email)
    } else {
        Err(ApiError::bad_request("correo no válido"))
    }
}

/// Lee la lista de dominios permitidos, separados por comas o espacios, como
/// `gammaingenieros.com, @otro.com`. Falla con el primero que no parezca un dominio.
pub fn parse_allowed_domains(text: &str) -> Result<Vec<String>, String> {
    let mut domains = Vec::new();
    for item in text.split(|c: char| c == ',' || c.is_whitespace()) {
        let domain = item.trim().trim_start_matches('@').to_lowercase();
        if domain.is_empty() {
            continue;
        }
        let valid = domain.len() <= 253
            && domain.contains('.')
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        if !valid {
            return Err(format!(
                "«{}» no es un dominio de correo válido",
                item.trim()
            ));
        }
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    Ok(domains)
}

/// El correo, ya normalizado, es de un dominio permitido (o no hay restricción). Se
/// compara el dominio entero: `ejemplo.com` no admite `dev.ejemplo.com`.
fn domain_allowed(allowed: &[String], email: &str) -> bool {
    allowed.is_empty()
        || email
            .rsplit_once('@')
            .is_some_and(|(_, domain)| allowed.iter().any(|a| a == domain))
}

fn check_blob(blob: &SealedBlob, max_ciphertext: usize) -> ApiResult<()> {
    let nonce_ok = B64.decode(&blob.nonce).is_ok_and(|n| n.len() == NONCE_LEN);
    if !nonce_ok || blob.ciphertext.len() > max_ciphertext || B64.decode(&blob.ciphertext).is_err()
    {
        return Err(ApiError::bad_request("datos cifrados no válidos"));
    }
    Ok(())
}

fn check_record(record: &SealedRecord) -> ApiResult<()> {
    let id_ok = record.id.len() == RECORD_ID_LEN
        && record
            .id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !id_ok {
        return Err(ApiError::bad_request("identificador de registro no válido"));
    }
    check_blob(&record.blob, MAX_RECORD_CIPHERTEXT)
}

/// Sal y parámetros de una cuenta. Para un correo sin cuenta devuelve unos inventados
/// pero estables, así no se puede averiguar qué correos tienen cuenta.
async fn prelogin(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    take_unauthenticated(&state)?;
    let email = normalize_email(&request.email)?;
    if let Some(account) = state.db.account_by_email(email.clone()).await? {
        return Ok(Json(PreloginResponse {
            kdf: account.kdf,
            salt: account.salt,
        }));
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&state.secret)
        .expect("HMAC acepta claves de cualquier longitud");
    mac.update(email.as_bytes());
    let fake_salt = &mac.finalize().into_bytes()[..MIN_SALT_LEN];
    Ok(Json(PreloginResponse {
        kdf: ACCOUNT_KDF,
        salt: B64.encode(fake_salt),
    }))
}

/// Gasta una ficha de las rutas sin sesión, o responde 429.
fn take_unauthenticated(state: &AppState) -> ApiResult<()> {
    if state.unauthenticated.try_take() {
        Ok(())
    } else {
        Err(ApiError::too_many())
    }
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<StatusCode> {
    take_unauthenticated(&state)?;
    let email = normalize_email(&request.email)?;
    let allowed = &state.config.allowed_domains;
    if !domain_allowed(allowed, &email) {
        let list = allowed
            .iter()
            .map(|d| format!("@{d}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            format!("este servidor solo admite cuentas con correos {list}"),
        ));
    }
    let salt = B64
        .decode(&request.salt)
        .map_err(|_| ApiError::bad_request("sal no válida"))?;
    // Todas las cuentas usan los mismos parámetros y una sal del mismo tamaño que las
    // inventadas, para que el prelogin no permita distinguirlas.
    if salt.len() != MIN_SALT_LEN
        || request.kdf != ACCOUNT_KDF
        || !kdf_is_strong(&salt, request.kdf)
    {
        return Err(ApiError::bad_request(
            "parámetros de cifrado de la cuenta no admitidos",
        ));
    }
    let auth =
        auth::decode_auth(&request.auth).ok_or_else(|| ApiError::bad_request("clave no válida"))?;
    check_blob(&request.vault_key, MAX_VAULT_KEY_CIPHERTEXT)?;
    let auth = state.hasher.hash_new(&auth).await?;
    state
        .db
        .insert_account(
            NewAccount {
                email,
                kdf: request.kdf,
                salt: request.salt,
                auth,
                vault_key: request.vault_key,
                created_at: now(),
            },
            !state.config.open_registration && allowed.is_empty(),
        )
        .await?;
    Ok(StatusCode::CREATED)
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    take_unauthenticated(&state)?;
    let email = normalize_email(&request.email)?;
    // El intento se cuenta antes de comprobar la clave: lanzar muchas peticiones a la vez
    // no permite probar más claves de las permitidas.
    if !state.limiter.try_begin(&email) {
        return Err(ApiError::too_many());
    }
    let auth = auth::decode_auth(&request.auth).ok_or_else(ApiError::unauthorized)?;
    let Some(account) = state.db.account_by_email(email.clone()).await? else {
        state.hasher.burn(&auth).await?;
        return Err(ApiError::unauthorized());
    };
    if !state.hasher.verify(&auth, &account.auth).await? {
        return Err(ApiError::unauthorized());
    }
    state.limiter.succeeded(&email);
    let (token, hash) = auth::new_token();
    let expires = now() + state.config.session_ttl.as_secs() as i64;
    state.db.insert_session(hash, account.id, expires).await?;
    Ok(Json(LoginResponse {
        token,
        vault_key: account.vault_key,
    }))
}

/// Cuenta de la sesión indicada en `Authorization: Bearer <token>`.
pub struct Session {
    account: i64,
    token_hash: [u8; 32],
}

impl FromRequestParts<Arc<AppState>> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| auth::token_looks_valid(t))
            .ok_or_else(ApiError::unauthorized)?;
        let token_hash = auth::token_hash(token);
        let account = state
            .db
            .session_account(token_hash, now())
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        Ok(Self {
            account,
            token_hash,
        })
    }
}

async fn logout(State(state): State<Arc<AppState>>, session: Session) -> ApiResult<StatusCode> {
    state.db.delete_session(session.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: u64,
}

async fn pull_space(state: &AppState, space: Space, since: u64) -> ApiResult<Json<PullResponse>> {
    let page = state.db.pull(space, since, PULL_PAGE_SIZE).await?;
    Ok(Json(PullResponse {
        records: page.records,
        cursor: page.cursor,
        more: page.more,
        manifest: page.manifest,
        epoch: page.epoch,
    }))
}

async fn pull(
    State(state): State<Arc<AppState>>,
    session: Session,
    Query(query): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    pull_space(&state, Space::Account(session.account), query.since).await
}

/// Comprueba los registros de una subida: identificadores válidos y sin repetir.
fn check_records(records: &[SealedRecord]) -> ApiResult<()> {
    let mut ids = std::collections::HashSet::new();
    for record in records {
        check_record(record)?;
        if !ids.insert(&record.id) {
            return Err(ApiError::bad_request("registro repetido en la petición"));
        }
    }
    Ok(())
}

async fn push_space(
    state: &AppState,
    space: Space,
    request: PushRequest,
) -> ApiResult<Json<PushResponse>> {
    if request.records.len() > MAX_PUSH_RECORDS {
        return Err(ApiError::bad_request(
            "demasiados registros en una petición",
        ));
    }
    if request.base_version.checked_add(1) != Some(request.manifest.version) {
        return Err(ApiError::bad_request("versión de manifiesto no válida"));
    }
    check_blob(&request.manifest.blob, MAX_MANIFEST_CIPHERTEXT)?;
    check_records(&request.records)?;
    let quota = match space {
        Space::Account(_) => state.config.quota,
        Space::Team(_) => state.config.team_quota,
    };
    let cursor = state
        .db
        .push(
            space,
            request.base_version,
            request.epoch,
            request.manifest,
            request.records,
            quota,
        )
        .await?;
    Ok(Json(PushResponse { cursor }))
}

async fn push(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(request): Json<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    push_space(&state, Space::Account(session.account), request).await
}

async fn own_keys(
    State(state): State<Arc<AppState>>,
    session: Session,
) -> ApiResult<Json<AccountKeysBlob>> {
    state
        .db
        .account_keys(session.account)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("par de claves"))
}

/// Guarda el par de claves de la cuenta, una sola vez.
async fn upload_keys(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(request): Json<AccountKeysBlob>,
) -> ApiResult<StatusCode> {
    check_blob(&request.private_key, MAX_VAULT_KEY_CIPHERTEXT)?;
    state.db.set_account_keys(session.account, request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Clave pública de otra cuenta. Solo con sesión: revela qué correos tienen cuenta en
/// este servidor, algo que ya sabe quien comparte equipos en él.
async fn user_key(
    State(state): State<Arc<AppState>>,
    _session: Session,
    Path(email): Path<String>,
) -> ApiResult<Json<UserKeyResponse>> {
    let email = normalize_email(&email)?;
    let public_key = state
        .db
        .public_key_by_email(email.clone())
        .await?
        .ok_or_else(|| ApiError::not_found("usuario con claves"))?;
    Ok(Json(UserKeyResponse { email, public_key }))
}

/// El identificador de un equipo es un UUID en su forma canónica.
fn check_team_id(id: &str) -> ApiResult<()> {
    match uuid::Uuid::parse_str(id) {
        Ok(uuid) if uuid.hyphenated().to_string() == id => Ok(()),
        _ => Err(ApiError::bad_request("identificador de equipo no válido")),
    }
}

/// Rol de la sesión en el equipo y si ya aceptó. A quien no es miembro ni está
/// invitado se le responde lo mismo que si el equipo no existiera.
async fn membership(
    state: &AppState,
    session: &Session,
    team: &str,
) -> ApiResult<(TeamRole, bool)> {
    check_team_id(team)?;
    state
        .db
        .membership(team.to_string(), session.account)
        .await?
        .ok_or_else(|| ApiError::not_found("equipo"))
}

/// Rol de la sesión en el equipo; una invitación pendiente todavía no da acceso.
async fn team_role(state: &AppState, session: &Session, team: &str) -> ApiResult<TeamRole> {
    match membership(state, session, team).await? {
        (role, true) => Ok(role),
        (_, false) => Err(ApiError::not_found("equipo")),
    }
}

async fn require_admin(state: &AppState, session: &Session, team: &str) -> ApiResult<()> {
    match team_role(state, session, team).await? {
        TeamRole::Admin => Ok(()),
        TeamRole::Member => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "solo un administrador del equipo puede hacerlo",
        )),
    }
}

async fn list_teams(
    State(state): State<Arc<AppState>>,
    session: Session,
) -> ApiResult<Json<Vec<TeamSummary>>> {
    Ok(Json(state.db.teams_of(session.account).await?))
}

async fn create_team(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(request): Json<CreateTeamRequest>,
) -> ApiResult<StatusCode> {
    check_team_id(&request.id)?;
    check_blob(&request.name, MAX_TEAM_NAME_CIPHERTEXT)?;
    check_blob(&request.key, MAX_VAULT_KEY_CIPHERTEXT)?;
    state
        .db
        .create_team(
            session.account,
            request.id,
            request.name,
            request.key,
            now(),
            state.config.max_teams_per_account,
        )
        .await?;
    Ok(StatusCode::CREATED)
}

async fn delete_team(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &session, &team).await?;
    state.db.delete_team(team).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn accept_invitation(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
) -> ApiResult<StatusCode> {
    check_team_id(&team)?;
    state
        .db
        .accept_invitation(team, session.account, state.config.max_teams_per_account)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_members(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
) -> ApiResult<Json<Vec<TeamMember>>> {
    team_role(&state, &session, &team).await?;
    Ok(Json(state.db.team_members(team).await?))
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Json(request): Json<AddMemberRequest>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &session, &team).await?;
    let email = normalize_email(&request.email)?;
    check_blob(&request.key, MAX_VAULT_KEY_CIPHERTEXT)?;
    state
        .db
        .add_member(
            team,
            email,
            request.role,
            request.epoch,
            request.key,
            session.account,
            state.config.max_team_members,
            state.config.max_pending_invitations,
        )
        .await?;
    Ok(StatusCode::CREATED)
}

async fn update_member(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, email)): Path<(String, String)>,
    Json(request): Json<UpdateMemberRequest>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &session, &team).await?;
    let email = normalize_email(&email)?;
    state.db.set_member_role(team, email, request.role).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Un administrador saca a un miembro o retira una invitación, o un miembro se sale del
/// equipo o rechaza su invitación.
async fn remove_member(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, email)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (role, accepted) = membership(&state, &session, &team).await?;
    let role = if accepted { role } else { TeamRole::Member };
    let email = normalize_email(&email)?;
    let leaving = state.db.account_email(session.account).await? == email;
    if role != TeamRole::Admin && !leaving {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "solo un administrador del equipo puede sacar a otros",
        ));
    }
    state.db.remove_member(team, email).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn team_pull(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Query(query): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    team_role(&state, &session, &team).await?;
    pull_space(&state, Space::Team(team), query.since).await
}

async fn team_push(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Json(request): Json<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    team_role(&state, &session, &team).await?;
    if request.epoch.is_none() {
        return Err(ApiError::bad_request(
            "falta la época de la clave del equipo",
        ));
    }
    push_space(&state, Space::Team(team), request).await
}

async fn rotate_team(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Json(request): Json<RotateTeamRequest>,
) -> ApiResult<Json<PushResponse>> {
    require_admin(&state, &session, &team).await?;
    let _permit = state.rotations.try_acquire().map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "servidor ocupado; inténtalo en un momento",
        )
    })?;
    if request.records.len() as u64 > state.config.team_quota.records
        || request.keys.len() as u64 > state.config.max_team_members
    {
        return Err(ApiError::bad_request("demasiados registros o miembros"));
    }
    check_blob(&request.name, MAX_TEAM_NAME_CIPHERTEXT)?;
    check_blob(&request.manifest.blob, MAX_MANIFEST_CIPHERTEXT)?;
    check_records(&request.records)?;
    let mut keys = Vec::with_capacity(request.keys.len());
    for member in request.keys {
        check_blob(&member.key, MAX_VAULT_KEY_CIPHERTEXT)?;
        keys.push(MemberKey {
            email: normalize_email(&member.email)?,
            key: member.key,
        });
    }
    let rotation = Rotation {
        epoch: request.epoch,
        base_version: request.base_version,
        name: request.name,
        keys,
        manifest: request.manifest,
        records: request.records,
    };
    let cursor = state
        .db
        .rotate_team(team, rotation, session.account, state.config.team_quota)
        .await?;
    Ok(Json(PushResponse { cursor }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_domains_are_normalized_and_deduplicated() {
        assert_eq!(
            parse_allowed_domains(" GammaIngenieros.com, @otro.org\nOTRO.org ").unwrap(),
            ["gammaingenieros.com", "otro.org"]
        );
        assert!(parse_allowed_domains("").unwrap().is_empty());
        assert!(parse_allowed_domains(" , ").unwrap().is_empty());
    }

    #[test]
    fn invalid_domains_are_rejected() {
        for bad in [
            "localhost",
            "ana@ejemplo.com",
            "ejemplo..com",
            "-x.com",
            "ej mplo.com/x",
        ] {
            assert!(parse_allowed_domains(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_exact_domain_is_allowed() {
        let allowed = vec!["ejemplo.com".to_string()];
        assert!(domain_allowed(&allowed, "ana@ejemplo.com"));
        assert!(!domain_allowed(&allowed, "ana@dev.ejemplo.com"));
        assert!(!domain_allowed(&allowed, "ana@ejemplo.com.evil"));
        assert!(domain_allowed(&[], "ana@cualquiera.net"));
    }
}
