//! Grabación de sesiones de punta a punta contra un `tunel-server` real: un admin la
//! enciende, un miembro graba y el admin abre la grabación comprobada.

use tunel_core::crypto::KdfParams;
use tunel_core::sync::SyncLocal;
use tunel_core::sync::protocol::TeamRole;
use tunel_core::sync::recording::RecordingEvent;
use tunel_core::vault::VaultData;
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::audit::Trust;
use tunel_sync::recording::{self, Uploader};
use tunel_sync::{ServerUrl, SyncError, check_server_url, create_account, sync_once, teams};
use zeroize::Zeroizing;

const REC: &str = "0f8b2c1e-1111-4222-8333-944455556666";

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
    sync(local).await
}

async fn sync(local: SyncLocal) -> SyncLocal {
    sync_once(&local, &VaultData::default())
        .await
        .unwrap()
        .local
}

/// Ana crea un Team con Bob dentro.
async fn team(server: &ServerUrl) -> (SyncLocal, SyncLocal, String) {
    let ana = account(server, "ana@ejemplo.com").await;
    let bob = account(server, "bob@ejemplo.com").await;
    let (ana, team) = teams::create_team(&ana, "Infra").await.unwrap();
    let (ana, key) = teams::lookup_key(&ana, "bob@ejemplo.com").await.unwrap();
    let ana = teams::invite(&ana, &team, "bob@ejemplo.com", TeamRole::Member, key)
        .await
        .unwrap();
    let bob = sync(bob).await;
    let bob = teams::accept_invitation(&bob, &team).await.unwrap();
    (sync(ana).await, sync(bob).await, team)
}

fn output(at_ms: u64, text: &str) -> RecordingEvent {
    RecordingEvent::Output {
        at_ms,
        data: text.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn a_member_records_and_the_admin_opens_it_verified() {
    let server = start_server().await;
    let (ana, bob, team) = team(&server).await;
    assert!(!recording::team_records(&bob, &team));
    assert!(matches!(
        teams::set_recording(&bob, &team, true).await,
        Err(SyncError::Forbidden(_)) | Err(SyncError::NotFound(_))
    ));
    let ana = teams::set_recording(&ana, &team, true).await.unwrap();
    assert!(recording::team_records(&ana, &team));
    let bob = sync(bob).await;
    assert!(
        recording::team_records(&bob, &team),
        "le llega con la lista firmada"
    );

    let mut uploader =
        Uploader::start(&bob, &team, REC, "web", 1_700_000_000_000, (80, 24)).unwrap();
    uploader
        .send(&[output(0, "$ ls\r\n")], false)
        .await
        .unwrap();
    uploader
        .send(&[output(900, "a b c\r\n")], true)
        .await
        .unwrap();

    let listed = recording::list(&ana, &team).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].finished);
    assert_eq!(listed[0].author, "bob@ejemplo.com");
    let opened = recording::open(&ana, &team, REC, &listed[0].author)
        .await
        .unwrap();
    assert_eq!(opened.trust, Trust::Verified);
    assert!(opened.complete);
    assert_eq!(opened.header.unwrap().host, "web");
    assert_eq!(
        opened.events,
        vec![output(0, "$ ls\r\n"), output(900, "a b c\r\n")]
    );

    // Solo los admins las ven y las borran.
    assert!(matches!(
        recording::list(&bob, &team).await,
        Err(SyncError::Forbidden(_))
    ));
    recording::delete(&ana, &team, REC).await.unwrap();
    assert!(recording::list(&ana, &team).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_recording_left_halfway_opens_as_incomplete() {
    let server = start_server().await;
    let (ana, bob, team) = team(&server).await;
    let mut uploader = Uploader::start(&bob, &team, REC, "web", 0, (80, 24)).unwrap();
    uploader.send(&[output(0, "hola")], false).await.unwrap();
    drop(uploader);
    let opened = recording::open(&ana, &team, REC, "bob@ejemplo.com")
        .await
        .unwrap();
    assert!(!opened.complete);
    assert_eq!(opened.problem, None);
    assert_eq!(opened.events, vec![output(0, "hola")]);
}
