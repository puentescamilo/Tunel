//! Sesiones compartidas: el servidor reenvía por WebSocket, sin poder leerlos, los
//! fotogramas entre quien comparte una terminal y los miembros de su Team que la miran.
//!
//! Las sesiones solo viven en memoria. Una sesión termina cuando quien comparte se
//! desconecta, o si no llega a conectarse poco después de anunciarla. Al sacar a alguien
//! del Team, borrar el Team o cerrar la sesión de la cuenta, sus conexiones se cierran en
//! el acto; además, cada conexión vuelve a comprobar su acceso de vez en cuando.

use crate::api::{ApiError, ApiResult, AppState, Session, check_blob, now, team_role};
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tunel_core::sync::live::JoinNonce;
use tunel_core::sync::protocol::{
    ConnId, CreateLiveRequest, HostEvent, HostMessage, LiveAnnouncement, LiveSummary, ViewerEvent,
    ViewerMessage,
};

/// Tamaño máximo de un mensaje de quien comparte: un fotograma de
/// [`tunel_core::sync::live::MAX_FRAME`] bytes, cifrado, en base64 y dentro del JSON.
const MAX_HOST_MESSAGE: usize = 1024 * 1024;
/// Quien mira solo escribe trozos de [`tunel_core::sync::live::MAX_INPUT`] bytes.
const MAX_VIEWER_MESSAGE: usize = 16 * 1024;
/// El anuncio cifrado: título, clave de sesión y clave pública, con relleno.
const MAX_META_CIPHERTEXT: usize = 2048;
/// Tiempo para escribir un mensaje antes de dar la conexión por perdida.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);
/// Latidos sin recibir nada (ni la respuesta a un ping) tras los que se da la conexión
/// por perdida.
const IDLE_HEARTBEATS: u32 = 3;
/// Mensajes en cola hacia cada conexión.
const QUEUE: usize = 4096;
/// Tiempo mínimo entre dos peticiones de control de la misma persona.
const REQUEST_INTERVAL: Duration = Duration::from_secs(5);

const CLOSE_ENDED: (u16, &str) = (1000, "la sesión terminó");
const CLOSE_KICKED: (u16, &str) = (4001, "quien comparte te sacó de la sesión");
const CLOSE_NO_ACCESS: (u16, &str) = (4003, "ya no tienes acceso a esta sesión");
const CLOSE_TOO_SLOW: (u16, &str) = (4008, "la conexión va demasiado lenta");
const CLOSE_IDLE: (u16, &str) = (4009, "la conexión dejó de responder");
const CLOSE_BAD_MESSAGE: (u16, &str) = (4400, "mensaje no válido");

/// Límites de las sesiones compartidas.
#[derive(Debug, Clone)]
pub struct LiveLimits {
    /// Sesiones a la vez en todo el servidor.
    pub sessions: usize,
    /// Sesiones a la vez de una misma cuenta.
    pub per_account: usize,
    /// Personas mirando una misma sesión (cada cuenta, una sola vez).
    pub viewers: usize,
    /// Bytes pendientes de enviar a una conexión; si los supera, va demasiado lenta.
    pub buffer: usize,
    /// Tiempo para que quien anuncia una sesión se conecte a ella.
    pub host_wait: Duration,
    /// Cada cuánto se manda un ping (los proxies cortan las conexiones calladas, nginx a
    /// los 60 s) y se comprueba que la cuenta sigue teniendo acceso.
    pub heartbeat: Duration,
}

impl Default for LiveLimits {
    fn default() -> Self {
        Self {
            sessions: 200,
            per_account: 5,
            viewers: 20,
            buffer: 8 * 1024 * 1024,
            host_wait: Duration::from_secs(60),
            heartbeat: Duration::from_secs(25),
        }
    }
}

/// Las sesiones compartidas en curso.
#[derive(Default)]
pub struct LiveRegistry {
    sessions: Mutex<HashMap<String, Arc<LiveSession>>>,
}

impl LiveRegistry {
    fn sessions(&self) -> MutexGuard<'_, HashMap<String, Arc<LiveSession>>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, team: &str, id: &str) -> ApiResult<Arc<LiveSession>> {
        self.sessions()
            .get(id)
            .filter(|s| s.team == team)
            .cloned()
            .ok_or_else(|| ApiError::not_found("sesión"))
    }

    /// Quita y cierra la sesión, si sigue siendo esa: con el mismo identificador puede
    /// haber ya otra.
    fn remove(&self, session: &Arc<LiveSession>) {
        {
            let mut sessions = self.sessions();
            if sessions
                .get(&session.id)
                .is_some_and(|s| Arc::ptr_eq(s, session))
            {
                sessions.remove(&session.id);
            }
        }
        session.end();
    }

    /// Sesiones que cumplen `filter`, sin dejar el registro bloqueado.
    fn matching(&self, filter: impl Fn(&LiveSession) -> bool) -> Vec<Arc<LiveSession>> {
        self.sessions()
            .values()
            .filter(|s| filter(s))
            .cloned()
            .collect()
    }

    /// `email` dejó el Team: termina sus sesiones y deja de ver las de los demás.
    pub fn revoke_member(&self, team: &str, email: &str) {
        for session in self.matching(|s| s.team == team) {
            if session.owner_email == email {
                self.remove(&session);
            } else {
                session.drop_viewers(|_, v| v.email == email, CLOSE_NO_ACCESS);
            }
        }
    }

    /// Se borró el Team.
    pub fn end_team(&self, team: &str) {
        for session in self.matching(|s| s.team == team) {
            self.remove(&session);
        }
    }

    /// Se cerró la sesión de la cuenta con ese token.
    pub fn revoke_token(&self, token_hash: &[u8; 32]) {
        for session in self.matching(|_| true) {
            if session.state().host_token.as_ref() == Some(token_hash) {
                self.remove(&session);
            } else {
                session.drop_viewers(|_, v| &v.token_hash == token_hash, CLOSE_NO_ACCESS);
            }
        }
    }
}

/// Lo que se manda a una conexión.
enum Outbound {
    Text(Utf8Bytes),
    Close(u16, &'static str),
}

/// Cola hacia una conexión, con los bytes pendientes contados.
#[derive(Clone)]
struct Queue {
    tx: mpsc::Sender<Outbound>,
    pending: Arc<AtomicUsize>,
}

impl Queue {
    fn new() -> (Self, mpsc::Receiver<Outbound>) {
        let (tx, rx) = mpsc::channel(QUEUE);
        let queue = Self {
            tx,
            pending: Arc::new(AtomicUsize::new(0)),
        };
        (queue, rx)
    }

    /// Encola un mensaje; `false` si la conexión va tan retrasada que hay que cerrarla.
    fn push(&self, text: Utf8Bytes, budget: usize) -> bool {
        let len = text.len();
        if self.pending.load(Ordering::Relaxed) + len > budget {
            return false;
        }
        self.pending.fetch_add(len, Ordering::Relaxed);
        self.tx.try_send(Outbound::Text(text)).is_ok()
    }

    fn sent(&self, len: usize) {
        self.pending.fetch_sub(len, Ordering::Relaxed);
    }

    fn close(&self, (code, reason): (u16, &'static str)) {
        let _ = self.tx.try_send(Outbound::Close(code, reason));
    }
}

struct Viewer {
    account: i64,
    email: String,
    token_hash: [u8; 32],
    queue: Queue,
    control: bool,
}

struct SessionState {
    announcement: LiveAnnouncement,
    /// Cola hacia quien comparte, mientras está conectado.
    host: Option<Queue>,
    host_token: Option<[u8; 32]>,
    /// Quien comparte ya se conectó una vez; si se va, la sesión termina.
    host_seen: bool,
    viewers: HashMap<ConnId, Viewer>,
    /// Última petición de control de cada cuenta.
    requests: HashMap<i64, Instant>,
    next_conn: ConnId,
    ended: bool,
}

struct LiveSession {
    id: String,
    team: String,
    owner: i64,
    owner_email: String,
    budget: usize,
    state: Mutex<SessionState>,
}

/// Qué hacer con quien mira tras encolarle algo.
#[must_use]
enum Delivery {
    Delivered,
    /// No da abasto: hay que echarlo.
    TooSlow,
}

impl SessionState {
    fn deliver(&self, conn: ConnId, event: &ViewerEvent, budget: usize) -> Delivery {
        match self.viewers.get(&conn) {
            Some(viewer) if !viewer.queue.push(to_text(event), budget) => Delivery::TooSlow,
            _ => Delivery::Delivered,
        }
    }

    /// Avisa a quien comparte. Si no da abasto, la sesión no puede seguir: se perdería la
    /// llegada o la salida de alguien.
    fn notify_host(&self, event: &HostEvent, budget: usize) -> bool {
        self.host
            .as_ref()
            .is_some_and(|host| host.push(to_text(event), budget))
    }
}

impl LiveSession {
    fn state(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn summary(&self) -> Option<LiveSummary> {
        let state = self.state();
        state.host.as_ref().map(|_| LiveSummary {
            id: self.id.clone(),
            owner: self.owner_email.clone(),
            epoch: state.announcement.epoch,
            meta: state.announcement.meta.clone(),
            viewers: state.viewers.len() as u32,
        })
    }

    /// Cierra la sesión y todas sus conexiones.
    fn end(&self) {
        let mut state = self.state();
        state.ended = true;
        if let Some(host) = state.host.take() {
            host.close(CLOSE_ENDED);
        }
        for viewer in std::mem::take(&mut state.viewers).into_values() {
            viewer.queue.close(CLOSE_ENDED);
        }
    }

    /// Echa a quienes cumplen `filter` y se lo dice a quien comparte. Si quien comparte
    /// no da abasto, termina la sesión.
    fn drop_viewers(&self, filter: impl Fn(ConnId, &Viewer) -> bool, reason: (u16, &'static str)) {
        let healthy = {
            let mut state = self.state();
            let gone: Vec<ConnId> = state
                .viewers
                .iter()
                .filter(|(conn, v)| filter(**conn, v))
                .map(|(conn, _)| *conn)
                .collect();
            gone.into_iter().all(|conn| {
                if let Some(viewer) = state.viewers.remove(&conn) {
                    viewer.queue.close(reason);
                }
                state.notify_host(&HostEvent::Left { conn }, self.budget)
            })
        };
        if !healthy {
            self.end();
        }
    }

    /// Quien mira se fue por su cuenta.
    fn left(&self, conn: ConnId) {
        let healthy = {
            let mut state = self.state();
            state.viewers.remove(&conn).is_none()
                || state.notify_host(&HostEvent::Left { conn }, self.budget)
        };
        if !healthy {
            self.end();
        }
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/teams/{team}/live", get(list).post(create))
        .route(
            "/v1/teams/{team}/live/{id}",
            put(update).delete(delete_session),
        )
        .route("/v1/teams/{team}/live/{id}/host", get(host))
        .route("/v1/teams/{team}/live/{id}/watch", get(watch))
}

async fn list(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
) -> ApiResult<Json<Vec<LiveSummary>>> {
    team_role(&state, &session, &team).await?;
    let sessions = state.live.matching(|s| s.team == team);
    Ok(Json(sessions.iter().filter_map(|s| s.summary()).collect()))
}

fn valid_session_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
}

async fn create(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Json(CreateLiveRequest { id, announcement }): Json<CreateLiveRequest>,
) -> ApiResult<StatusCode> {
    team_role(&state, &session, &team).await?;
    check_blob(&announcement.meta, MAX_META_CIPHERTEXT)?;
    if !valid_session_id(&id) {
        return Err(ApiError::bad_request("identificador de sesión no válido"));
    }
    let owner_email = state.db.account_email(session.account).await?;
    let limits = &state.config.live;
    let live = Arc::new(LiveSession {
        id: id.clone(),
        team,
        owner: session.account,
        owner_email,
        budget: limits.buffer,
        state: Mutex::new(SessionState {
            announcement,
            host: None,
            host_token: None,
            host_seen: false,
            viewers: HashMap::new(),
            requests: HashMap::new(),
            next_conn: 1,
            ended: false,
        }),
    });
    {
        let mut sessions = state.live.sessions();
        let mine = sessions
            .values()
            .filter(|s| s.owner == session.account)
            .count();
        if sessions.len() >= limits.sessions || mine >= limits.per_account {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "se alcanzó el límite de sesiones compartidas",
            ));
        }
        if sessions.contains_key(&id) {
            return Err(ApiError::new(StatusCode::CONFLICT, "la sesión ya existe"));
        }
        sessions.insert(id, live.clone());
    }
    // Si quien la anuncia no llega a conectarse, la sesión no ocupa sitio para siempre.
    let wait = limits.host_wait;
    let registry = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(wait).await;
        if !live.state().host_seen {
            registry.live.remove(&live);
        }
    });
    Ok(StatusCode::CREATED)
}

/// La sesión `id` del Team, si la sesión de la cuenta es de quien la comparte.
async fn owned(
    state: &AppState,
    session: &Session,
    team: &str,
    id: &str,
) -> ApiResult<Arc<LiveSession>> {
    team_role(state, session, team).await?;
    let live = state.live.get(team, id)?;
    if live.owner != session.account {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "solo quien comparte la sesión puede hacerlo",
        ));
    }
    Ok(live)
}

/// Cambia el anuncio; quien comparte lo vuelve a cifrar cuando cambia la clave del Team.
async fn update(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
    Json(announcement): Json<LiveAnnouncement>,
) -> ApiResult<StatusCode> {
    check_blob(&announcement.meta, MAX_META_CIPHERTEXT)?;
    let live = owned(&state, &session, &team, &id).await?;
    live.state().announcement = announcement;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_session(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let live = owned(&state, &session, &team, &id).await?;
    state.live.remove(&live);
    Ok(StatusCode::NO_CONTENT)
}

fn host_taken() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "la sesión ya tiene a quien la comparte conectado",
    )
}

/// Quien comparte se conecta a su sesión.
async fn host(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let live = owned(&state, &session, &team, &id).await?;
    if live.state().host_seen {
        return Err(host_taken());
    }
    let token_hash = session.token_hash;
    Ok(ws
        .max_message_size(MAX_HOST_MESSAGE)
        .max_frame_size(MAX_HOST_MESSAGE)
        .on_upgrade(move |mut socket| async move {
            let (queue, rx) = Queue::new();
            let connected = {
                let mut live_state = live.state();
                let free = !live_state.host_seen && !live_state.ended;
                if free {
                    live_state.host_seen = true;
                    live_state.host = Some(queue.clone());
                    live_state.host_token = Some(token_hash);
                }
                free
            };
            if !connected {
                close(&mut socket, CLOSE_ENDED).await;
                return;
            }
            let connection = Connection {
                state: &state,
                live: &live,
                account: live.owner,
                token_hash,
                queue,
            };
            connection.run(socket, rx, Role::Host).await;
            state.live.remove(&live);
        }))
}

#[derive(Deserialize)]
struct WatchQuery {
    /// Número aleatorio de llegada, en base64 (ver [`JoinNonce`]).
    nonce: String,
}

fn already_watching() -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "ya estás mirando esta sesión")
}

fn full() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "la sesión ya tiene el máximo de personas mirando",
    )
}

/// Por qué no se puede empezar a mirar una sesión ahora mismo.
fn watch_refusal(state: &SessionState, account: i64, limit: usize) -> Option<ApiError> {
    if state.host.is_none() {
        Some(ApiError::not_found("sesión"))
    } else if state.viewers.values().any(|v| v.account == account) {
        Some(already_watching())
    } else if state.viewers.len() >= limit {
        Some(full())
    } else {
        None
    }
}

/// Un miembro del Team empieza a mirar la sesión.
async fn watch(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
    Query(query): Query<WatchQuery>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    team_role(&state, &session, &team).await?;
    let live = state.live.get(&team, &id)?;
    let nonce = JoinNonce::from_base64(&query.nonce)
        .ok_or_else(|| ApiError::bad_request("número de llegada no válido"))?
        .to_base64();
    let email = state.db.account_email(session.account).await?;
    let limit = state.config.live.viewers;
    let account = session.account;
    if let Some(refusal) = watch_refusal(&live.state(), account, limit) {
        return Err(refusal);
    }
    let token_hash = session.token_hash;
    Ok(ws
        .max_message_size(MAX_VIEWER_MESSAGE)
        .max_frame_size(MAX_VIEWER_MESSAGE)
        .on_upgrade(move |mut socket| async move {
            let (queue, rx) = Queue::new();
            let joined = {
                let mut live_state = live.state();
                if watch_refusal(&live_state, account, limit).is_some() {
                    None
                } else {
                    let conn = live_state.next_conn;
                    live_state.next_conn += 1;
                    live_state.viewers.insert(
                        conn,
                        Viewer {
                            account,
                            email: email.clone(),
                            token_hash,
                            queue: queue.clone(),
                            control: false,
                        },
                    );
                    let event = HostEvent::Joined { conn, email, nonce };
                    Some((conn, live_state.notify_host(&event, live.budget)))
                }
            };
            let conn = match joined {
                None => {
                    close(&mut socket, CLOSE_ENDED).await;
                    return;
                }
                Some((_, false)) => {
                    live.end();
                    close(&mut socket, CLOSE_ENDED).await;
                    return;
                }
                Some((conn, true)) => conn,
            };
            let connection = Connection {
                state: &state,
                live: &live,
                account,
                token_hash,
                queue,
            };
            connection.run(socket, rx, Role::Viewer(conn)).await;
            live.left(conn);
        }))
}

fn to_text<T: serde::Serialize>(message: &T) -> Utf8Bytes {
    Utf8Bytes::from(serde_json::to_string(message).expect("los mensajes siempre se serializan"))
}

async fn send(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(message)).await,
        Ok(Ok(()))
    )
}

async fn close(socket: &mut WebSocket, (code, reason): (u16, &'static str)) {
    let frame = CloseFrame {
        code,
        reason: Utf8Bytes::from_static(reason),
    };
    let _ = send(socket, Message::Close(Some(frame))).await;
}

#[derive(Debug, Clone, Copy)]
enum Role {
    Host,
    Viewer(ConnId),
}

/// Una conexión WebSocket abierta, de quien comparte o de quien mira.
struct Connection<'a> {
    state: &'a AppState,
    live: &'a LiveSession,
    account: i64,
    token_hash: [u8; 32],
    queue: Queue,
}

impl Connection<'_> {
    /// La cuenta sigue con su sesión abierta y en el Team.
    async fn still_allowed(&self) -> bool {
        let db = &self.state.db;
        let session = db.session_account(self.token_hash, now()).await;
        if !matches!(session, Ok(Some(account)) if account == self.account) {
            return false;
        }
        matches!(
            db.membership(self.live.team.clone(), self.account).await,
            Ok(Some((_, true)))
        )
    }

    /// Reenvía en los dos sentidos hasta que una de las partes cierra.
    async fn run(&self, mut socket: WebSocket, mut outbound: mpsc::Receiver<Outbound>, role: Role) {
        let heartbeat = self.state.config.live.heartbeat;
        let mut ticks = tokio::time::interval(heartbeat);
        ticks.tick().await;
        let mut last_seen = Instant::now();
        loop {
            tokio::select! {
                message = socket.recv() => {
                    last_seen = Instant::now();
                    match message {
                        Some(Ok(Message::Text(text))) => {
                            if !self.received(role, &text) {
                                close(&mut socket, CLOSE_BAD_MESSAGE).await;
                                return;
                            }
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                        Some(Ok(Message::Binary(_))) => {
                            close(&mut socket, CLOSE_BAD_MESSAGE).await;
                            return;
                        }
                        Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                    }
                }
                next = outbound.recv() => match next {
                    Some(Outbound::Text(text)) => {
                        let len = text.len();
                        let sent = send(&mut socket, Message::Text(text)).await;
                        self.queue.sent(len);
                        if !sent {
                            return;
                        }
                    }
                    Some(Outbound::Close(code, reason)) => {
                        close(&mut socket, (code, reason)).await;
                        return;
                    }
                    None => {
                        close(&mut socket, CLOSE_ENDED).await;
                        return;
                    }
                },
                _ = ticks.tick() => {
                    if last_seen.elapsed() > heartbeat * IDLE_HEARTBEATS {
                        close(&mut socket, CLOSE_IDLE).await;
                        return;
                    }
                    if !self.still_allowed().await {
                        close(&mut socket, CLOSE_NO_ACCESS).await;
                        return;
                    }
                    if !send(&mut socket, Message::Ping(Default::default())).await {
                        return;
                    }
                }
            }
        }
    }

    /// Atiende un mensaje; `false` si no es válido.
    fn received(&self, role: Role, text: &str) -> bool {
        match role {
            Role::Host => match serde_json::from_str::<HostMessage>(text) {
                Ok(message) => {
                    self.handle_host(message);
                    true
                }
                Err(_) => false,
            },
            Role::Viewer(conn) => match serde_json::from_str::<ViewerMessage>(text) {
                Ok(message) => {
                    self.handle_viewer(conn, message);
                    true
                }
                Err(_) => false,
            },
        }
    }

    fn handle_host(&self, message: HostMessage) {
        let budget = self.live.budget;
        let slow: Vec<ConnId> = {
            let mut state = self.live.state();
            match message {
                HostMessage::Output { frame } => {
                    let text = to_text(&ViewerEvent::Output { frame });
                    state
                        .viewers
                        .iter()
                        .filter(|(_, viewer)| !viewer.queue.push(text.clone(), budget))
                        .map(|(conn, _)| *conn)
                        .collect()
                }
                HostMessage::Join { to, frame } => {
                    match state.deliver(to, &ViewerEvent::Join { frame }, budget) {
                        Delivery::TooSlow => vec![to],
                        Delivery::Delivered => Vec::new(),
                    }
                }
                HostMessage::Grant { to, grant, key } => {
                    if let Some(viewer) = state.viewers.get_mut(&to) {
                        viewer.control = true;
                    }
                    match state.deliver(to, &ViewerEvent::Grant { grant, key }, budget) {
                        Delivery::TooSlow => vec![to],
                        Delivery::Delivered => Vec::new(),
                    }
                }
                HostMessage::Revoke { to } => {
                    if let Some(viewer) = state.viewers.get_mut(&to) {
                        viewer.control = false;
                    }
                    match state.deliver(to, &ViewerEvent::Revoke, budget) {
                        Delivery::TooSlow => vec![to],
                        Delivery::Delivered => Vec::new(),
                    }
                }
                HostMessage::Kick { to } => {
                    if let Some(viewer) = state.viewers.remove(&to) {
                        viewer.queue.close(CLOSE_KICKED);
                    }
                    Vec::new()
                }
            }
        };
        if !slow.is_empty() {
            self.live
                .drop_viewers(|conn, _| slow.contains(&conn), CLOSE_TOO_SLOW);
        }
    }

    fn handle_viewer(&self, conn: ConnId, message: ViewerMessage) {
        let budget = self.live.budget;
        let delivered = {
            let mut state = self.live.state();
            let Some(control) = state.viewers.get(&conn).map(|v| v.control) else {
                return;
            };
            let event = match message {
                ViewerMessage::Request => {
                    let now = Instant::now();
                    let recent = state
                        .requests
                        .get(&self.account)
                        .is_some_and(|last| now.duration_since(*last) < REQUEST_INTERVAL);
                    if recent {
                        return;
                    }
                    state.requests.insert(self.account, now);
                    HostEvent::Request { conn }
                }
                // Sin el control, lo que escriba no llega: quien comparte tampoco lo
                // aceptaría, porque no tiene una clave de control con la que abrirlo.
                ViewerMessage::Input { .. } if !control => return,
                ViewerMessage::Input { frame } => HostEvent::Input { conn, frame },
            };
            state.notify_host(&event, budget)
        };
        // Si quien comparte no da abasto, lo escrito se perdería y quien comparte lo
        // notaría; mejor terminar ya.
        if !delivered {
            self.live.end();
        }
    }
}
