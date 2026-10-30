//! Sesiones compartidas de punta a punta contra un `tunel-server` real: quien comparte
//! envía su pantalla, quien mira la recibe y solo escribe cuando le dan el control.

use std::time::Duration;
use tunel_core::crypto::KdfParams;
use tunel_core::io::{SessionInput, SessionIo, SessionOutput};
use tunel_core::sync::protocol::{ConnId, TeamRole};
use tunel_core::sync::{KeyProblem, SyncLocal};
use tunel_core::vault::VaultData;
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::live::{self, HostUpdate, LiveHost, LiveListing, LiveViewer, ViewerUpdate};
use tunel_sync::teams::{self, KeyStatus};
use tunel_sync::{ServerUrl, SyncError, check_server_url, create_account, sync_once};
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(5);

async fn start_server() -> ServerUrl {
    let config = Config {
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        open_registration: true,
        unauthenticated_burst: 1000,
        ..Config::default()
    };
    let state = AppState::new(Db::open_in_memory().unwrap(), config)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    check_server_url(&format!("http://{address}")).unwrap()
}

async fn account(server: &ServerUrl, email: &str) -> SyncLocal {
    let password = Zeroizing::new(format!("contraseña de {email}"));
    let local = create_account(server, email, password, &VaultData::default())
        .await
        .unwrap();
    sync_once(&local, &VaultData::default())
        .await
        .unwrap()
        .local
}

/// `ana` crea un Team e invita a los demás, que aceptan.
async fn team(server: &ServerUrl, others: &[&str]) -> (SyncLocal, Vec<SyncLocal>, String) {
    let ana = account(server, "ana@ejemplo.com").await;
    let (mut ana, team) = teams::create_team(&ana, "Ops").await.unwrap();
    let mut members = Vec::new();
    for email in others {
        let member = account(server, email).await;
        let (local, key) = teams::lookup_key(&ana, email).await.unwrap();
        ana = teams::invite(&local, &team, email, TeamRole::Member, key)
            .await
            .unwrap();
        let member = sync_once(&member, &VaultData::default())
            .await
            .unwrap()
            .local;
        let member = teams::accept_invitation(&member, &team).await.unwrap();
        let member = sync_once(&member, &VaultData::default())
            .await
            .unwrap()
            .local;
        members.push(member);
    }
    (ana, members, team)
}

async fn host_update(host: &mut LiveHost) -> HostUpdate {
    tokio::time::timeout(WAIT, host.next_update())
        .await
        .expect("quien comparte no recibió nada")
        .expect("la sesión terminó")
}

async fn viewer_update(viewer: &mut LiveViewer) -> ViewerUpdate {
    tokio::time::timeout(WAIT, viewer.next_update())
        .await
        .expect("quien mira no recibió nada")
        .expect("la sesión terminó")
}

async fn screen(io: &mut SessionIo) -> SessionOutput {
    tokio::time::timeout(WAIT, io.output.recv())
        .await
        .expect("la terminal no recibió nada")
        .expect("la terminal se cerró")
}

async fn joined(host: &mut LiveHost) -> (ConnId, String) {
    match host_update(host).await {
        HostUpdate::Joined { conn, email } => (conn, email),
        other => panic!("se esperaba una llegada: {other:?}"),
    }
}

/// Ana comparte y bob empieza a mirar; ana le manda la pantalla.
struct Scene {
    ana: SyncLocal,
    host: LiveHost,
    viewer: LiveViewer,
    io: SessionIo,
    conn: ConnId,
}

async fn scene() -> Scene {
    let server = start_server().await;
    let (ana, members, team) = team(&server, &["bob@ejemplo.com"]).await;
    let bob = members.into_iter().next().unwrap();
    let (ana, mut host) = live::share(&ana, &team, "web-01").await.unwrap();

    let (bob, listings) = live::live_sessions(&bob, &team).await.unwrap();
    let listing: &LiveListing = &listings[0];
    assert_eq!(listing.title.as_deref(), Some("web-01"));
    assert_eq!(listing.owner, "ana@ejemplo.com");
    assert_eq!(listing.owner_key, Some(KeyStatus::Pinned));
    let (_bob, viewer, mut io) = live::watch(&bob, listing).await.unwrap();

    let (conn, email) = joined(&mut host).await;
    assert_eq!(email, "bob@ejemplo.com");
    host.welcome(conn, 80, 24, b"$ ".to_vec());
    assert_eq!(
        screen(&mut io).await,
        SessionOutput::Resize { cols: 80, rows: 24 }
    );
    assert_eq!(
        screen(&mut io).await,
        SessionOutput::Data(b"\x1bc$ ".to_vec())
    );
    Scene {
        ana,
        host,
        viewer,
        io,
        conn,
    }
}

#[tokio::test]
async fn a_member_sees_the_shared_terminal() {
    let mut s = scene().await;
    s.host.output(b"ls\r\n");
    s.host.resize(100, 30);
    assert_eq!(
        screen(&mut s.io).await,
        SessionOutput::Data(b"ls\r\n".to_vec())
    );
    assert_eq!(
        screen(&mut s.io).await,
        SessionOutput::Resize {
            cols: 100,
            rows: 30
        }
    );
    // Lo grande llega troceado pero entero.
    let big = vec![b'x'; 100 * 1024];
    s.host.output(&big);
    let mut received = Vec::new();
    while received.len() < big.len() {
        match screen(&mut s.io).await {
            SessionOutput::Data(data) => received.extend(data),
            other => panic!("se esperaba salida: {other:?}"),
        }
    }
    assert_eq!(received, big);
}

#[tokio::test]
async fn only_a_viewer_with_control_can_type() {
    let mut s = scene().await;
    s.io.input
        .send(SessionInput::Data(b"sin permiso".to_vec()))
        .unwrap();

    s.viewer.request_control();
    assert_eq!(
        host_update(&mut s.host).await,
        HostUpdate::ControlRequested { conn: s.conn }
    );
    let (_, key) = live::viewer_key(&s.ana, "bob@ejemplo.com").await.unwrap();
    s.host.grant(s.conn, key);
    assert_eq!(
        viewer_update(&mut s.viewer).await,
        ViewerUpdate::Control(true)
    );

    s.io.input
        .send(SessionInput::Data(b"uptime\r".to_vec()))
        .unwrap();
    // Lo escrito antes de tener el control nunca llegó.
    assert_eq!(
        host_update(&mut s.host).await,
        HostUpdate::Input {
            conn: s.conn,
            data: b"uptime\r".to_vec()
        }
    );
    let pasted = vec![b'p'; 10 * 1024];
    s.io.input.send(SessionInput::Data(pasted.clone())).unwrap();
    let mut received = Vec::new();
    while received.len() < pasted.len() {
        match host_update(&mut s.host).await {
            HostUpdate::Input { data, .. } => received.extend(data),
            other => panic!("se esperaba entrada: {other:?}"),
        }
    }
    assert_eq!(received, pasted);

    s.host.revoke(s.conn);
    assert_eq!(
        viewer_update(&mut s.viewer).await,
        ViewerUpdate::Control(false)
    );
}

#[tokio::test]
async fn the_viewer_sees_the_end_of_the_session() {
    let mut s = scene().await;
    drop(s.host);
    assert_eq!(
        screen(&mut s.io).await,
        SessionOutput::Closed { exit_status: None }
    );
}

#[tokio::test]
async fn the_host_sees_viewers_leave() {
    let mut s = scene().await;
    s.io.input.send(SessionInput::Close).unwrap();
    assert_eq!(
        host_update(&mut s.host).await,
        HostUpdate::Left { conn: s.conn }
    );
}

#[tokio::test]
async fn a_kicked_viewer_is_told_why() {
    let mut s = scene().await;
    s.host.kick(s.conn);
    match screen(&mut s.io).await {
        SessionOutput::Error(reason) => assert!(reason.contains("te sacó"), "{reason}"),
        other => panic!("se esperaba un error: {other:?}"),
    }
}

#[tokio::test]
async fn control_needs_a_confirmed_key() {
    let server = start_server().await;
    let (_ana, members, team) = team(&server, &["bob@ejemplo.com", "carla@ejemplo.com"]).await;
    let (bob, carla) = (&members[0], &members[1]);
    // Bob comparte; nunca comparó la huella de carla, a la que invitó ana.
    let (bob, mut host) = live::share(bob, &team, "db").await.unwrap();
    let (carla, listings) = live::live_sessions(carla, &team).await.unwrap();
    assert_eq!(listings[0].owner_key, Some(KeyStatus::New));
    let (_carla, _viewer, _io) = live::watch(&carla, &listings[0]).await.unwrap();
    let (_, email) = joined(&mut host).await;
    let refused = live::viewer_key(&bob, &email).await;
    assert!(matches!(
        refused,
        Err(SyncError::Key(KeyProblem::Unconfirmed(_)))
    ));
}
