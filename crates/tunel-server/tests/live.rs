//! Pruebas de las sesiones compartidas con un servidor real escuchando en TCP y el cifrado
//! de verdad: el servidor reenvía los fotogramas y solo deja escribir a quien tiene el
//! control.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tower::ServiceExt;
use tunel_core::crypto::KdfParams;
use tunel_core::sync::live::{
    ControlContext, ControlKey, InputOpener, InputSealer, JoinNonce, LiveFrame, LiveKey, LiveMeta,
    MetaContext, OutputOpener, OutputSealer, open_meta, seal_meta, unwrap_control_key,
    wrap_control_key,
};
use tunel_core::sync::protocol::*;
use tunel_core::sync::team::{seal_team_name, wrap_team_key};
use tunel_core::sync::{AccountKeypair, AccountKeys, TeamKeyContext, VaultKey};
use tunel_server::{AppState, Config, Db, LiveLimits, router};
use uuid::Uuid;

const SALT: &[u8; 16] = b"sal-de-la-cuenta";
const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";
const WAIT: Duration = Duration::from_secs(5);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn at(session: &str) -> MetaContext<'_> {
    MetaContext {
        team: TEAM,
        epoch: 0,
        session,
    }
}

/// Servidor escuchando en un puerto libre; las peticiones HTTP van directas al router.
struct Server {
    app: Router,
    address: std::net::SocketAddr,
}

async fn server_with(live: LiveLimits) -> Server {
    let config = Config {
        open_registration: true,
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        unauthenticated_burst: 1000,
        live,
        ..Config::default()
    };
    let state = AppState::new(Db::open_in_memory().unwrap(), config)
        .await
        .unwrap();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = app.clone();
    tokio::spawn(async move { axum::serve(listener, served).await.unwrap() });
    Server { app, address }
}

struct User {
    email: String,
    token: String,
    keys: AccountKeypair,
}

impl Server {
    async fn send(
        &self,
        method: &str,
        uri: &str,
        user: Option<&User>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(user) = user {
            request = request.header("authorization", format!("Bearer {}", user.token));
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn user(&self, email: &str) -> User {
        let account = AccountKeys::derive_for_tests(email.as_bytes(), SALT);
        let body = serde_json::to_value(RegisterRequest {
            email: email.into(),
            kdf: KdfParams::RECOMMENDED,
            salt: B64.encode(SALT),
            auth: account.auth_token().to_string(),
            vault_key: VaultKey::generate().wrap(&account).unwrap(),
        })
        .unwrap();
        let (status, body) = self.send("POST", "/v1/accounts", None, Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let login = json!({"email": email, "auth": account.auth_token().as_str()});
        let (status, body) = self.send("POST", "/v1/sessions", None, Some(login)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = serde_json::from_value::<LoginResponse>(body).unwrap().token;
        let keys = AccountKeypair::generate();
        let user = User {
            email: email.into(),
            token,
            keys,
        };
        let blob = serde_json::to_value(AccountKeysBlob {
            public_key: user.keys.public(),
            private_key: user.keys.seal(&VaultKey::generate()).unwrap(),
        })
        .unwrap();
        let (status, _) = self.send("PUT", "/v1/keys", Some(&user), Some(blob)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        user
    }

    /// Crea el Team con `admin` y mete a `members`; devuelve su clave.
    async fn team(&self, admin: &User, members: &[&User]) -> VaultKey {
        let key = VaultKey::generate();
        let context = TeamKeyContext {
            team: TEAM,
            epoch: 0,
        };
        let body = serde_json::to_value(CreateTeamRequest {
            id: TEAM.into(),
            name: seal_team_name(&key, TEAM, "Ops").unwrap(),
            key: wrap_team_key(&key, context, &admin.keys, &admin.keys.public()).unwrap(),
        })
        .unwrap();
        let (status, _) = self
            .send("POST", "/v1/teams", Some(admin), Some(body))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        for member in members {
            let body = serde_json::to_value(AddMemberRequest {
                email: member.email.clone(),
                role: TeamRole::Member,
                epoch: 0,
                key: wrap_team_key(&key, context, &admin.keys, &member.keys.public()).unwrap(),
            })
            .unwrap();
            let uri = format!("/v1/teams/{TEAM}/members");
            let (status, _) = self.send("POST", &uri, Some(admin), Some(body)).await;
            assert_eq!(status, StatusCode::CREATED);
            let uri = format!("/v1/teams/{TEAM}/accept");
            let (status, _) = self.send("POST", &uri, Some(member), None).await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        key
    }

    /// Anuncia una sesión; devuelve su identificador.
    async fn announce(&self, host: &User, meta: &LiveMeta, team_key: &VaultKey) -> String {
        let id = Uuid::new_v4().to_string();
        let (status, body) = self.create(host, &id, meta, team_key).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        id
    }

    async fn create(
        &self,
        host: &User,
        id: &str,
        meta: &LiveMeta,
        team_key: &VaultKey,
    ) -> (StatusCode, Value) {
        let body = serde_json::to_value(CreateLiveRequest {
            id: id.into(),
            announcement: LiveAnnouncement {
                epoch: 0,
                meta: seal_meta(team_key, at(id), meta).unwrap(),
            },
        })
        .unwrap();
        let uri = format!("/v1/teams/{TEAM}/live");
        self.send("POST", &uri, Some(host), Some(body)).await
    }

    async fn list(&self, user: &User) -> (StatusCode, Vec<LiveSummary>) {
        let uri = format!("/v1/teams/{TEAM}/live");
        let (status, body) = self.send("GET", &uri, Some(user), None).await;
        (status, serde_json::from_value(body).unwrap_or_default())
    }

    async fn connect(&self, user: &User, id: &str, role: &str) -> Result<Socket, StatusCode> {
        let role = match role {
            "watch" => format!("watch?nonce={}", JoinNonce::generate().to_base64()),
            other => other.to_string(),
        };
        let url = format!("ws://{}/v1/teams/{TEAM}/live/{id}/{role}", self.address);
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {}", user.token).parse().unwrap(),
        );
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => Ok(socket),
            Err(tungstenite::Error::Http(response)) => Err(response.status()),
            Err(e) => panic!("{e}"),
        }
    }
}

async fn put<T: serde::Serialize>(socket: &mut Socket, message: &T) {
    let text = serde_json::to_string(message).unwrap();
    socket.send(Message::text(text)).await.unwrap();
}

/// Siguiente mensaje de texto; `Err` con el código si el servidor cierra.
async fn next<T: serde::de::DeserializeOwned>(socket: &mut Socket) -> Result<T, Option<u16>> {
    loop {
        let message = tokio::time::timeout(WAIT, socket.next())
            .await
            .expect("el servidor no respondió a tiempo");
        match message {
            Some(Ok(Message::Text(text))) => return Ok(serde_json::from_str(&text).unwrap()),
            Some(Ok(Message::Close(frame))) => return Err(frame.map(|f| u16::from(f.code))),
            Some(Ok(_)) => continue,
            Some(Err(_)) | None => return Err(None),
        }
    }
}

/// No llega nada en un rato.
async fn quiet(socket: &mut Socket) {
    let waited = tokio::time::timeout(Duration::from_millis(200), socket.next()).await;
    assert!(waited.is_err(), "llegó algo inesperado: {waited:?}");
}

fn meta(host: &User) -> LiveMeta {
    LiveMeta {
        title: "web-01".into(),
        key: LiveKey::generate(),
        host: host.keys.public(),
    }
}

/// Un Team con `ana` (admin, comparte) y `bob` (miembro, mira), con la sesión anunciada
/// y `ana` conectada.
struct Scene {
    server: Server,
    ana: User,
    bob: User,
    team_key: VaultKey,
    id: String,
    meta: LiveMeta,
    host: Socket,
}

async fn scene() -> Scene {
    scene_with(LiveLimits::default()).await
}

async fn scene_with(live: LiveLimits) -> Scene {
    let server = server_with(live).await;
    let ana = server.user("ana@ejemplo.com").await;
    let bob = server.user("bob@ejemplo.com").await;
    let team_key = server.team(&ana, &[&bob]).await;
    let meta = meta(&ana);
    let id = server.announce(&ana, &meta, &team_key).await;
    let host = server.connect(&ana, &id, "host").await.unwrap();
    Scene {
        server,
        ana,
        bob,
        team_key,
        id,
        meta,
        host,
    }
}

impl Scene {
    /// `bob` empieza a mirar; `ana` recibe el aviso con su número de llegada.
    async fn watch(&mut self) -> (Socket, ConnId, JoinNonce) {
        let nonce = JoinNonce::generate();
        let role = format!("watch?nonce={}", nonce.to_base64());
        let viewer = self
            .server
            .connect(&self.bob, &self.id, &role)
            .await
            .unwrap();
        match next(&mut self.host).await.unwrap() {
            HostEvent::Joined {
                conn,
                email,
                nonce: relayed,
            } => {
                assert_eq!(email, "bob@ejemplo.com");
                assert_eq!(JoinNonce::from_base64(&relayed), Some(nonce));
                (viewer, conn, nonce)
            }
            other => panic!("se esperaba la llegada de bob: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_member_sees_the_session_and_receives_its_frames() {
    let mut s = scene().await;
    let (status, sessions) = s.server.list(&s.bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].owner, "ana@ejemplo.com");
    let opened = open_meta(&s.team_key, at(&s.id), &sessions[0].meta).unwrap();
    assert_eq!(opened.title, "web-01");

    let mut sealer = OutputSealer::new(&s.meta.key, &s.id);
    let before = sealer.seal(&LiveFrame::Output(b"antes".to_vec())).unwrap();
    let (mut viewer, conn, nonce) = s.watch().await;
    put(&mut s.host, &HostMessage::Output { frame: before }).await;
    let frame = sealer.seal_join(&nonce, 80, 24, b"$ ").unwrap();
    put(&mut s.host, &HostMessage::Join { to: conn, frame }).await;
    let output = LiveFrame::Output(b"ls\r\n".to_vec());
    let frame = sealer.seal(&output).unwrap();
    put(&mut s.host, &HostMessage::Output { frame }).await;

    let mut opener = OutputOpener::new(&opened.key, &s.id, &nonce);
    let ViewerEvent::Output { frame } = next(&mut viewer).await.unwrap() else {
        panic!("se esperaba la salida de antes de llegar");
    };
    assert_eq!(opener.open(&frame).unwrap(), None);
    let ViewerEvent::Join { frame } = next(&mut viewer).await.unwrap() else {
        panic!("se esperaba la pantalla de llegada");
    };
    assert!(matches!(
        opener.open_join(&frame).unwrap(),
        LiveFrame::Snapshot {
            cols: 80,
            rows: 24,
            ..
        }
    ));
    let ViewerEvent::Output { frame } = next(&mut viewer).await.unwrap() else {
        panic!("se esperaba un fotograma");
    };
    assert_eq!(opener.open(&frame).unwrap(), Some(output));
    let (_, sessions) = s.server.list(&s.bob).await;
    assert_eq!(sessions[0].viewers, 1);
}

#[tokio::test]
async fn only_a_viewer_with_control_reaches_the_host() {
    let mut s = scene().await;
    let (mut viewer, conn, _) = s.watch().await;
    let grant = ControlContext {
        session: &s.id,
        grant: 1,
    };

    // Sin el control, lo que escribe no llega.
    let early = InputSealer::new(&ControlKey::generate(), grant)
        .seal(b"x")
        .unwrap();
    put(&mut viewer, &ViewerMessage::Input { frame: early }).await;
    put(&mut viewer, &ViewerMessage::Request).await;
    assert_eq!(
        next::<HostEvent>(&mut s.host).await.unwrap(),
        HostEvent::Request { conn }
    );

    let control = ControlKey::generate();
    let key = wrap_control_key(&control, grant, &s.ana.keys, &s.bob.keys.public()).unwrap();
    put(
        &mut s.host,
        &HostMessage::Grant {
            to: conn,
            grant: 1,
            key,
        },
    )
    .await;
    let ViewerEvent::Grant { grant: number, key } = next(&mut viewer).await.unwrap() else {
        panic!("se esperaba el control");
    };
    let context = ControlContext {
        session: &s.id,
        grant: number,
    };
    let opened = unwrap_control_key(&key, context, &s.bob.keys, &s.meta.host).unwrap();
    let frame = InputSealer::new(&opened, context).seal(b"ls\r").unwrap();
    put(&mut viewer, &ViewerMessage::Input { frame }).await;
    let HostEvent::Input { conn: from, frame } = next(&mut s.host).await.unwrap() else {
        panic!("se esperaba entrada");
    };
    assert_eq!(from, conn);
    let typed = InputOpener::new(&control, grant).open(&frame).unwrap();
    assert_eq!(typed, b"ls\r");

    put(&mut s.host, &HostMessage::Revoke { to: conn }).await;
    assert_eq!(
        next::<ViewerEvent>(&mut viewer).await.unwrap(),
        ViewerEvent::Revoke
    );
    let frame = InputSealer::new(&opened, context).seal(b"y").unwrap();
    put(&mut viewer, &ViewerMessage::Input { frame }).await;
    quiet(&mut s.host).await;
}

#[tokio::test]
async fn control_requests_are_rate_limited() {
    let mut s = scene().await;
    let (mut viewer, conn, _) = s.watch().await;
    for _ in 0..3 {
        put(&mut viewer, &ViewerMessage::Request).await;
    }
    assert_eq!(
        next::<HostEvent>(&mut s.host).await.unwrap(),
        HostEvent::Request { conn }
    );
    quiet(&mut s.host).await;
}

#[tokio::test]
async fn the_host_can_kick_a_viewer() {
    let mut s = scene().await;
    let (mut viewer, conn, _) = s.watch().await;
    put(&mut s.host, &HostMessage::Kick { to: conn }).await;
    assert_eq!(next::<ViewerEvent>(&mut viewer).await, Err(Some(4001)));
}

#[tokio::test]
async fn the_session_ends_when_the_host_leaves() {
    let mut s = scene().await;
    let (mut viewer, conn, _) = s.watch().await;
    put(&mut viewer, &ViewerMessage::Request).await;
    assert_eq!(
        next::<HostEvent>(&mut s.host).await.unwrap(),
        HostEvent::Request { conn }
    );
    s.host.close(None).await.unwrap();
    assert_eq!(
        next::<ViewerEvent>(&mut viewer).await,
        Err(Some(u16::from(CloseCode::Normal)))
    );
    let (_, sessions) = s.server.list(&s.bob).await;
    assert!(sessions.is_empty());
    let again = s.server.connect(&s.ana, &s.id, "host").await;
    assert_eq!(again.err(), Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn only_the_owner_hosts_and_only_once() {
    let mut s = scene().await;
    let second = s.server.connect(&s.ana, &s.id, "host").await;
    assert_eq!(second.err(), Some(StatusCode::CONFLICT));
    let stolen = s.server.connect(&s.bob, &s.id, "host").await;
    assert_eq!(stolen.err(), Some(StatusCode::FORBIDDEN));
    let uri = format!("/v1/teams/{TEAM}/live/{}", s.id);
    let (status, _) = s.server.send("DELETE", &uri, Some(&s.bob), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = s.server.send("DELETE", &uri, Some(&s.ana), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        next::<HostEvent>(&mut s.host).await,
        Err(Some(u16::from(CloseCode::Normal)))
    );
}

#[tokio::test]
async fn outsiders_cannot_list_or_watch() {
    let s = scene().await;
    let eve = s.server.user("eve@ejemplo.com").await;
    assert_eq!(s.server.list(&eve).await.0, StatusCode::NOT_FOUND);
    let watched = s.server.connect(&eve, &s.id, "watch").await;
    assert_eq!(watched.err(), Some(StatusCode::NOT_FOUND));
    let id = Uuid::new_v4().to_string();
    let (status, _) = s.server.create(&eve, &id, &meta(&eve), &s.team_key).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_removed_member_is_disconnected_at_once() {
    let mut s = scene().await;
    let (mut viewer, conn, _) = s.watch().await;
    let uri = format!("/v1/teams/{TEAM}/members/bob@ejemplo.com");
    let (status, _) = s.server.send("DELETE", &uri, Some(&s.ana), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(next::<ViewerEvent>(&mut viewer).await, Err(Some(4003)));
    assert_eq!(
        next::<HostEvent>(&mut s.host).await.unwrap(),
        HostEvent::Left { conn }
    );
}

#[tokio::test]
async fn sessions_without_a_host_are_dropped_and_limits_apply() {
    let server = server_with(LiveLimits {
        per_account: 2,
        viewers: 1,
        host_wait: Duration::from_millis(200),
        ..LiveLimits::default()
    })
    .await;
    let ana = server.user("ana@ejemplo.com").await;
    let bob = server.user("bob@ejemplo.com").await;
    let carla = server.user("carla@ejemplo.com").await;
    let team_key = server.team(&ana, &[&bob, &carla]).await;
    let meta = meta(&ana);

    let live = server.announce(&ana, &meta, &team_key).await;
    let _host = server.connect(&ana, &live, "host").await.unwrap();
    let _abandoned = server.announce(&ana, &meta, &team_key).await;
    let third = Uuid::new_v4().to_string();
    let (status, _) = server.create(&ana, &third, &meta, &team_key).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = server.create(&ana, &live, &meta, &team_key).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // La que nunca tuvo a nadie conectado desaparece y deja sitio.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (status, _) = server.create(&ana, &live, &meta, &team_key).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = server.create(&ana, &third, &meta, &team_key).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = server.create(&ana, "no-es-un-uuid", &meta, &team_key).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let _watching = server.connect(&bob, &live, "watch").await.unwrap();
    let full = server.connect(&carla, &live, "watch").await;
    assert_eq!(full.err(), Some(StatusCode::FORBIDDEN));
}

#[tokio::test]
async fn a_slow_viewer_is_dropped_without_stopping_the_others() {
    let mut s = scene_with(LiveLimits {
        buffer: 64 * 1024,
        ..LiveLimits::default()
    })
    .await;
    let (_stalled, conn, _) = s.watch().await;
    let mut sealer = OutputSealer::new(&s.meta.key, &s.id);
    // Nadie lee del lado de quien mira: al llenarse la cola, el servidor lo echa.
    let mut left = false;
    for _ in 0..400 {
        let frame = sealer
            .seal(&LiveFrame::Output(vec![b'x'; 16 * 1024]))
            .unwrap();
        put(&mut s.host, &HostMessage::Output { frame }).await;
        if let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(1), s.host.next()).await
        {
            assert_eq!(
                serde_json::from_str::<HostEvent>(&text).unwrap(),
                HostEvent::Left { conn }
            );
            left = true;
            break;
        }
    }
    assert!(left, "el servidor no echó a quien no lee");
}

#[tokio::test]
async fn malformed_messages_close_the_connection() {
    let mut s = scene().await;
    s.host
        .send(Message::text("{\"t\":\"nada\"}"))
        .await
        .unwrap();
    assert_eq!(next::<HostEvent>(&mut s.host).await, Err(Some(4400)));
}

#[tokio::test]
async fn each_account_watches_a_session_once() {
    let mut s = scene().await;
    let (_viewer, _, _) = s.watch().await;
    let again = s.server.connect(&s.bob, &s.id, "watch").await;
    assert_eq!(again.err(), Some(StatusCode::CONFLICT));
}

#[tokio::test]
async fn a_bad_join_nonce_is_refused() {
    let s = scene().await;
    let bad = s.server.connect(&s.bob, &s.id, "watch?nonce=AAAA").await;
    assert_eq!(bad.err(), Some(StatusCode::BAD_REQUEST));
    let missing = s.server.connect(&s.bob, &s.id, "watch?x=1").await;
    assert_eq!(missing.err(), Some(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn signing_out_closes_the_connections_of_that_session() {
    let mut s = scene().await;
    let (mut viewer, conn, _) = s.watch().await;
    let (status, _) = s
        .server
        .send("DELETE", "/v1/sessions/current", Some(&s.bob), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(next::<ViewerEvent>(&mut viewer).await, Err(Some(4003)));
    assert_eq!(
        next::<HostEvent>(&mut s.host).await.unwrap(),
        HostEvent::Left { conn }
    );
    let (status, _) = s
        .server
        .send("DELETE", "/v1/sessions/current", Some(&s.ana), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        next::<HostEvent>(&mut s.host).await,
        Err(Some(u16::from(CloseCode::Normal)))
    );
}

#[tokio::test]
async fn deleting_the_team_ends_its_sessions() {
    let mut s = scene().await;
    let (mut viewer, _, _) = s.watch().await;
    let uri = format!("/v1/teams/{TEAM}");
    let (status, _) = s.server.send("DELETE", &uri, Some(&s.ana), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        next::<ViewerEvent>(&mut viewer).await,
        Err(Some(u16::from(CloseCode::Normal)))
    );
    assert_eq!(
        next::<HostEvent>(&mut s.host).await,
        Err(Some(u16::from(CloseCode::Normal)))
    );
}

#[tokio::test]
async fn a_connection_that_stops_answering_is_closed() {
    let mut s = scene_with(LiveLimits {
        heartbeat: Duration::from_millis(100),
        ..LiveLimits::default()
    })
    .await;
    // Sin leer, el cliente no contesta a los pings.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(next::<HostEvent>(&mut s.host).await, Err(Some(4009)));
    let (_, sessions) = s.server.list(&s.bob).await;
    assert!(sessions.is_empty());
}
