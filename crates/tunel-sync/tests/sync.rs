//! Sincronización de punta a punta contra un `tunel-server` real que escucha en un puerto
//! local: varios equipos, trabajo sin conexión, sesiones caducadas y un servidor que
//! intenta ocultar datos.

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use std::collections::BTreeSet;
use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::vault::VaultData;
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::{
    ServerUrl, SyncError, check_server_url, create_account, sign_in, sign_out, sync_once,
};
use zeroize::Zeroizing;

const EMAIL: &str = "ana@ejemplo.com";
const PASSWORD: &str = "una contraseña larga";

async fn serve(app: Router) -> ServerUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    check_server_url(&format!("http://{address}")).unwrap()
}

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
    serve(router(state)).await
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.into())
}

fn hosts(labels: &[&str]) -> VaultData {
    labels.iter().fold(VaultData::default(), |d, l| {
        d.with_host(Host::new(*l, "10.0.0.1"))
    })
}

fn labels(data: &VaultData) -> BTreeSet<String> {
    data.hosts.iter().map(|h| h.label.clone()).collect()
}

/// Un equipo: su bóveda local y su configuración de sincronización.
struct Device {
    data: VaultData,
    local: tunel_core::sync::SyncLocal,
}

impl Device {
    async fn sync(&mut self) -> tunel_sync::SyncOutcome {
        let outcome = sync_once(&self.local, &self.data).await.unwrap();
        self.data = outcome.data.clone();
        self.local = outcome.local.clone();
        outcome
    }

    fn edit(&mut self, new: VaultData) {
        self.local.state = self
            .local
            .state
            .record_local(&self.data, &new, now())
            .unwrap();
        self.data = new;
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn first_device(server: &ServerUrl, data: VaultData) -> Device {
    let local = create_account(server, EMAIL, password(), &data)
        .await
        .unwrap();
    Device { data, local }
}

async fn another_device(server: &ServerUrl, data: VaultData) -> Device {
    let local = sign_in(server, EMAIL, password(), &data).await.unwrap();
    Device { data, local }
}

#[tokio::test]
async fn two_devices_combine_their_vaults() {
    let server = start_server().await;
    let mut laptop = first_device(&server, hosts(&["web", "db"])).await;
    let first = laptop.sync().await;
    assert_eq!((first.uploaded, first.downloaded), (2, 0));

    let mut desktop = another_device(&server, hosts(&["solo-escritorio"])).await;
    desktop.sync().await;
    assert_eq!(
        labels(&desktop.data),
        labels(&hosts(&["web", "db", "solo-escritorio"]))
    );

    laptop.sync().await;
    assert_eq!(labels(&laptop.data), labels(&desktop.data));
    assert!(laptop.local.state.pending.is_empty());
    assert!(desktop.local.state.pending.is_empty());
}

#[tokio::test]
async fn offline_edits_and_deletions_reach_the_other_device() {
    let server = start_server().await;
    let mut laptop = first_device(&server, hosts(&["web", "db"])).await;
    laptop.sync().await;
    let mut desktop = another_device(&server, VaultData::default()).await;
    desktop.sync().await;

    // Sin conexión: el portátil renombra un host y el escritorio borra otro.
    let web = laptop
        .data
        .hosts
        .iter()
        .find(|h| h.label == "web")
        .unwrap()
        .clone();
    laptop.edit(laptop.data.with_host(Host {
        label: "web-renombrado".into(),
        ..web
    }));
    let db = desktop
        .data
        .hosts
        .iter()
        .find(|h| h.label == "db")
        .unwrap()
        .id;
    desktop.edit(desktop.data.without_host(db));
    assert_eq!(laptop.local.state.pending.len(), 1);

    laptop.sync().await;
    desktop.sync().await;
    laptop.sync().await;
    let expected = labels(&hosts(&["web-renombrado"]));
    assert_eq!(labels(&laptop.data), expected);
    assert_eq!(labels(&desktop.data), expected);
}

#[tokio::test]
async fn an_expired_session_is_renewed_with_the_stored_key() {
    let server = start_server().await;
    let mut laptop = first_device(&server, hosts(&["web"])).await;
    laptop.sync().await;
    // Cerrar la sesión en el servidor deja inválido el token guardado.
    sign_out(&laptop.local).await.unwrap();

    laptop.edit(laptop.data.with_host(Host::new("nuevo", "1.1.1.1")));
    let outcome = laptop.sync().await;
    assert_eq!(outcome.uploaded, 1);
}

#[tokio::test]
async fn wrong_password_and_duplicate_accounts_are_reported() {
    let server = start_server().await;
    first_device(&server, VaultData::default()).await;
    let wrong = sign_in(
        &server,
        EMAIL,
        Zeroizing::new("otra contraseña".into()),
        &VaultData::default(),
    )
    .await;
    assert!(matches!(wrong, Err(SyncError::Unauthorized)), "{wrong:?}");
    let duplicate = create_account(&server, EMAIL, password(), &VaultData::default()).await;
    assert!(
        matches!(duplicate, Err(SyncError::AccountExists)),
        "{duplicate:?}"
    );
}

#[tokio::test]
async fn an_unreachable_server_leaves_the_vault_untouched() {
    let server = start_server().await;
    let mut laptop = first_device(&server, hosts(&["web"])).await;
    laptop.local.server = "http://127.0.0.1:9".into();
    let error = sync_once(&laptop.local, &laptop.data).await.unwrap_err();
    assert!(error.is_transient(), "{error:?}");
    assert_eq!(laptop.local.state.pending.len(), 1);
}

/// Proxy que reenvía al servidor real pero quita el primer registro de cada descarga.
async fn withholding_proxy(upstream: ServerUrl) -> ServerUrl {
    async fn forward(State(upstream): State<String>, request: Request) -> Response {
        let client = reqwest::Client::new();
        let (parts, body) = request.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let url = format!("{upstream}{}", parts.uri);
        let mut outgoing = client.request(parts.method.clone(), url).body(body);
        for (name, value) in &parts.headers {
            if name != "host" {
                outgoing = outgoing.header(name, value);
            }
        }
        let response = outgoing.send().await.unwrap();
        let status = response.status();
        let mut bytes = response.bytes().await.unwrap().to_vec();
        if parts.method == "GET" && parts.uri.path() == "/v1/records" {
            let mut page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if let Some(records) = page["records"].as_array_mut()
                && !records.is_empty()
            {
                records.remove(0);
            }
            bytes = serde_json::to_vec(&page).unwrap();
        }
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap()
    }
    serve(Router::new().fallback(forward).with_state(upstream.base)).await
}

#[tokio::test]
async fn a_server_that_hides_records_is_detected() {
    let server = start_server().await;
    let mut laptop = first_device(&server, hosts(&["web", "db"])).await;
    laptop.sync().await;

    let proxy = withholding_proxy(server).await;
    let local = sign_in(&proxy, EMAIL, password(), &VaultData::default())
        .await
        .unwrap();
    let error = sync_once(&local, &VaultData::default()).await.unwrap_err();
    assert!(matches!(error, SyncError::Integrity(_)), "{error:?}");
}

#[tokio::test]
async fn every_device_of_the_account_shares_one_key_pair() {
    let server = start_server().await;
    let laptop = first_device(&server, hosts(&["web"])).await;
    let desktop = another_device(&server, VaultData::default()).await;
    let laptop_key = laptop.local.keypair.as_ref().unwrap().public();
    assert_eq!(desktop.local.keypair.unwrap().public(), laptop_key);
}

#[tokio::test]
async fn a_device_linked_before_teams_gets_the_key_pair_on_its_next_sync() {
    let server = start_server().await;
    let mut laptop = first_device(&server, hosts(&["web"])).await;
    let public = laptop.local.keypair.take().unwrap().public();
    let outcome = laptop.sync().await;
    assert_eq!(outcome.local.keypair.unwrap().public(), public);
}
