//! El móvil se une a una cuenta y recibe lo que subió el escritorio, contra un
//! `tunel-server` real en memoria.

use std::sync::Arc;
use tokio::runtime::Runtime;
use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::vault::VaultData;
use tunel_mobile::{TunelError, Vault, sign_in_options};
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::{ServerUrl, check_server_url, create_account, sync_once};
use zeroize::Zeroizing;

const ACCOUNT_PASSWORD: &str = "contraseña-de-la-cuenta";
const VAULT_PASSWORD: &str = "contraseña-del-movil";
const EMAIL: &str = "ana@ejemplo.com";

/// El servidor corre en su propio entorno de tokio: las funciones del móvil bloquean y no
/// pueden llamarse desde dentro de uno.
struct World {
    runtime: Runtime,
    server: ServerUrl,
    _dir: tempfile::TempDir,
    phone_path: String,
}

impl World {
    fn new() -> Self {
        let runtime = Runtime::new().unwrap();
        let server = runtime.block_on(async {
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
        });
        let dir = tempfile::tempdir().unwrap();
        let phone_path = dir.path().join("vault.json").to_string_lossy().into_owned();
        Self {
            runtime,
            server,
            _dir: dir,
            phone_path,
        }
    }

    /// El escritorio crea la cuenta y sube estos hosts.
    fn desktop_uploads(&self, labels: &[&str]) {
        let data = labels.iter().fold(VaultData::default(), |d, l| {
            d.with_host(Host::new(*l, "10.0.0.1"))
        });
        self.runtime.block_on(async {
            let local = create_account(
                &self.server,
                EMAIL,
                Zeroizing::new(ACCOUNT_PASSWORD.into()),
                &data,
            )
            .await
            .unwrap();
            sync_once(&local, &data).await.unwrap();
        });
    }

    fn phone(&self) -> Arc<Vault> {
        Vault::create(self.phone_path.clone(), VAULT_PASSWORD.into()).unwrap()
    }

    fn url(&self) -> String {
        self.server.base.to_string()
    }
}

fn labels(vault: &Vault) -> Vec<String> {
    vault.hosts().into_iter().map(|h| h.label).collect()
}

#[test]
fn the_phone_receives_the_hosts_of_the_account() {
    let w = World::new();
    w.desktop_uploads(&["web-01", "db-01"]);
    let phone = w.phone();

    phone
        .sign_in_with_password(w.url(), EMAIL.into(), ACCOUNT_PASSWORD.into())
        .unwrap();
    let report = phone.sync().unwrap();

    assert_eq!(labels(&phone), ["db-01", "web-01"]);
    assert!(report.team_problems.is_empty());
    let account = phone.account().unwrap().unwrap();
    assert_eq!(account.email, EMAIL);
    assert_eq!(account.provider_name, None);
}

#[test]
fn what_was_received_is_still_there_after_reopening_the_vault() {
    let w = World::new();
    w.desktop_uploads(&["web-01"]);
    {
        let phone = w.phone();
        phone
            .sign_in_with_password(w.url(), EMAIL.into(), ACCOUNT_PASSWORD.into())
            .unwrap();
        phone.sync().unwrap();
    }

    let reopened = Vault::unlock(w.phone_path.clone(), VAULT_PASSWORD.into()).unwrap();

    assert_eq!(labels(&reopened), ["web-01"]);
    assert!(reopened.account().unwrap().is_some());
}

#[test]
fn a_wrong_account_password_is_explained_and_nothing_is_saved() {
    let w = World::new();
    w.desktop_uploads(&["web-01"]);
    let phone = w.phone();

    let error = phone
        .sign_in_with_password(w.url(), EMAIL.into(), "otra-contraseña".into())
        .unwrap_err();

    let TunelError::Sync { message } = error else {
        panic!("{error:?}");
    };
    assert!(
        message.starts_with("Correo o contraseña incorrectos"),
        "{message}"
    );
    assert_eq!(phone.account().unwrap(), None);
}

#[test]
fn syncing_without_an_account_says_so() {
    let w = World::new();
    let phone = w.phone();

    assert!(matches!(phone.sync(), Err(TunelError::NotSignedIn)));
}

#[test]
fn signing_out_forgets_the_account_and_what_it_brought() {
    let w = World::new();
    w.desktop_uploads(&["web-01"]);
    let phone = w.phone();
    phone
        .sign_in_with_password(w.url(), EMAIL.into(), ACCOUNT_PASSWORD.into())
        .unwrap();
    phone.sync().unwrap();

    phone.sign_out().unwrap();

    assert_eq!(phone.account().unwrap(), None);
    assert!(phone.hosts().is_empty());
}

#[test]
fn the_server_says_how_to_sign_in() {
    let w = World::new();

    let options = sign_in_options(w.url()).unwrap();

    assert!(options.password_login);
    assert!(options.providers.is_empty());
}

#[test]
fn a_plain_http_server_on_the_internet_is_rejected() {
    let error = sign_in_options("http://tunel.example.com".into()).unwrap_err();

    assert!(matches!(error, TunelError::Sync { .. }), "{error:?}");
}
