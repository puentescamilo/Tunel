//! La terminal del móvil contra un servidor SSH `russh` en el mismo proceso: la pregunta por
//! la clave del servidor, la autenticación y el ida y vuelta de la shell.

use russh::keys::decode_secret_key;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;
use tunel_core::crypto::KdfParams;
use tunel_core::{Host, Identity, KnownHost, Protocol, UnlockedVault, VaultData};
use tunel_mobile::{
    HostKeyQuestion, LoginQuestion, TerminalListener, TerminalSession, TunelError, Vault,
};

const USER: &str = "ana";
const PASSWORD: &str = "contraseña-correcta";
const OTP: &str = "123456";
const VAULT_PASSWORD: &str = "contraseña-del-movil";
const HOST_KEY: &str = include_str!("../../tunel-ssh/tests/fixtures/host_ed25519");
const TIMEOUT: Duration = Duration::from_secs(15);

/// Shell de prueba: saluda, devuelve en mayúsculas lo que recibe y con "exit" termina.
#[derive(Clone, Default)]
struct TestServer {
    sizes: Arc<Mutex<Vec<(u32, u32)>>>,
}

impl server::Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        match response {
            None => Ok(Auth::Partial {
                name: "otp".into(),
                instructions: "Código de un solo uso".into(),
                prompts: vec![("Código: ".into(), true)].into(),
            }),
            Some(mut answers) => {
                let ok = user == USER && answers.next().as_deref() == Some(OTP.as_bytes());
                Ok(if ok { Auth::Accept } else { Auth::reject() })
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.sizes.lock().unwrap().push((cols, rows));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.sizes.lock().unwrap().push((cols, rows));
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"bienvenida\r\n".to_vec())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let text = String::from_utf8_lossy(data);
        if text.contains("exit") {
            session.eof(channel)?;
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
        } else {
            session.data(channel, text.to_uppercase().into_bytes())?;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum Event {
    Connected,
    Output(Vec<u8>),
    HostKey(HostKeyQuestion),
    Login(LoginQuestion),
    Closed(Option<String>),
}

struct Recorder(Mutex<Sender<Event>>);

impl Recorder {
    fn record(&self, event: Event) {
        let _ = self.0.lock().unwrap().send(event);
    }
}

impl TerminalListener for Recorder {
    fn connected(&self) {
        self.record(Event::Connected);
    }
    fn output(&self, data: Vec<u8>) {
        self.record(Event::Output(data));
    }
    fn host_key(&self, question: HostKeyQuestion) {
        self.record(Event::HostKey(question));
    }
    fn login(&self, question: LoginQuestion) {
        self.record(Event::Login(question));
    }
    fn closed(&self, error: Option<String>) {
        self.record(Event::Closed(error));
    }
}

struct World {
    /// Mantiene vivo el servidor SSH.
    _runtime: Runtime,
    port: u16,
    server: TestServer,
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl World {
    fn new() -> Self {
        let runtime = Runtime::new().unwrap();
        let server = TestServer::default();
        let state = server.clone();
        let port = runtime.block_on(async move {
            let config = Arc::new(server::Config {
                keys: vec![decode_secret_key(HOST_KEY, None).unwrap()],
                auth_rejection_time: Duration::from_millis(10),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut state = state;
            tokio::spawn(async move { state.run_on_socket(config, &listener).await });
            port
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        Self {
            _runtime: runtime,
            port,
            server,
            _dir: dir,
            path,
        }
    }

    /// Guarda `data` en la bóveda del móvil y la abre como lo hace la app.
    fn vault(&self, data: VaultData) -> Arc<Vault> {
        let mut vault =
            UnlockedVault::create(&self.path, VAULT_PASSWORD, KdfParams::FAST_FOR_TESTS).unwrap();
        vault.commit(data).unwrap();
        drop(vault);
        self.reopen()
    }

    fn reopen(&self) -> Arc<Vault> {
        Vault::unlock(self.path.to_string_lossy().into(), VAULT_PASSWORD.into()).unwrap()
    }

    /// Un host del servidor de prueba; con `password`, la identidad la lleva.
    fn host(&self, password: Option<&str>) -> (Host, Identity) {
        let identity = Identity::new("ana", USER);
        let identity = match password {
            Some(p) => identity.with_password(p),
            None => identity,
        };
        let host = Host {
            port: Some(self.port),
            identity: Some(identity.id),
            ..Host::new("prueba", "127.0.0.1")
        };
        (host, identity)
    }
}

fn data_with(host: &Host, identity: &Identity) -> VaultData {
    VaultData::default()
        .with_identity(identity.clone())
        .with_host(host.clone())
}

fn open(vault: &Arc<Vault>, host: &Host) -> (Arc<TerminalSession>, Receiver<Event>) {
    let (tx, rx) = channel();
    let session = vault
        .clone()
        .open_terminal(
            host.id.0.to_string(),
            80,
            24,
            Arc::new(Recorder(Mutex::new(tx))),
        )
        .unwrap();
    (session, rx)
}

fn next(events: &Receiver<Event>) -> Event {
    events
        .recv_timeout(TIMEOUT)
        .expect("no llegó nada a tiempo")
}

/// Espera a que la salida acumulada contenga `needle` y la devuelve.
fn output_until(events: &Receiver<Event>, needle: &str) -> String {
    let mut seen = String::new();
    while !seen.contains(needle) {
        match next(events) {
            Event::Output(data) => seen.push_str(&String::from_utf8_lossy(&data)),
            other => panic!("esperaba salida con «{needle}» y llegó {other:?} tras «{seen}»"),
        }
    }
    seen
}

fn accept_key(session: &TerminalSession, events: &Receiver<Event>) -> HostKeyQuestion {
    let Event::HostKey(question) = next(events) else {
        panic!("esperaba la pregunta por la clave del servidor");
    };
    session.answer_host_key(true).unwrap();
    question
}

fn expect_connected(events: &Receiver<Event>) {
    match next(events) {
        Event::Connected => {}
        other => panic!("esperaba la conexión y llegó {other:?}"),
    }
}

#[test]
fn the_shell_answers_what_is_typed_and_closes_on_exit() {
    let w = World::new();
    let (host, identity) = w.host(Some(PASSWORD));
    let vault = w.vault(data_with(&host, &identity));
    let (session, events) = open(&vault, &host);

    let question = accept_key(&session, &events);
    expect_connected(&events);
    output_until(&events, "bienvenida");
    session.send(b"hola".to_vec());
    output_until(&events, "HOLA");
    session.send(b"exit\n".to_vec());

    assert_eq!(question.port, w.port);
    assert!(question.fingerprint.starts_with("SHA256:"));
    assert_eq!(question.expected, None);
    assert!(matches!(next(&events), Event::Closed(None)));
}

#[test]
fn an_accepted_key_is_remembered_and_not_asked_again() {
    let w = World::new();
    let (host, identity) = w.host(Some(PASSWORD));
    let vault = w.vault(data_with(&host, &identity));
    let (first, events) = open(&vault, &host);
    accept_key(&first, &events);
    expect_connected(&events);
    first.close();

    let (_second, events) = open(&vault, &host);

    expect_connected(&events);
    drop(vault);
    let saved = UnlockedVault::unlock(&w.path, VAULT_PASSWORD).unwrap();
    assert_eq!(saved.data.known_hosts.len(), 1);
    assert_eq!(saved.data.known_hosts[0].port, w.port);
}

#[test]
fn a_changed_key_is_reported_and_rejecting_it_does_not_connect() {
    let w = World::new();
    let (host, identity) = w.host(Some(PASSWORD));
    let known = KnownHost {
        host: "127.0.0.1".into(),
        port: w.port,
        algorithm: "ssh-ed25519".into(),
        fingerprint: "SHA256:otra-clave".into(),
    };
    let vault = w.vault(data_with(&host, &identity).trust_host_key(known));
    let (session, events) = open(&vault, &host);

    let Event::HostKey(question) = next(&events) else {
        panic!("esperaba la pregunta por la clave del servidor");
    };
    session.answer_host_key(false).unwrap();

    assert_eq!(
        question.expected.as_deref(),
        Some("ssh-ed25519 SHA256:otra-clave")
    );
    let Event::Closed(Some(error)) = next(&events) else {
        panic!("la sesión debía cerrarse con el motivo");
    };
    assert!(error.contains("rechazaste la clave"), "{error}");
}

#[test]
fn the_server_can_ask_for_a_code_to_sign_in() {
    let w = World::new();
    let (host, identity) = w.host(None);
    let vault = w.vault(data_with(&host, &identity));
    let (session, events) = open(&vault, &host);
    accept_key(&session, &events);

    let Event::Login(question) = next(&events) else {
        panic!("esperaba que el servidor pidiera el código");
    };
    session.answer_login(Some(vec![OTP.into()]));

    assert_eq!(question.instructions, "Código de un solo uso");
    assert_eq!(question.prompts.len(), 1);
    assert!(question.prompts[0].echo);
    expect_connected(&events);
}

#[test]
fn cancelling_the_login_closes_with_the_reason() {
    let w = World::new();
    let (host, identity) = w.host(None);
    let vault = w.vault(data_with(&host, &identity));
    let (session, events) = open(&vault, &host);
    accept_key(&session, &events);
    assert!(matches!(next(&events), Event::Login(_)));

    session.answer_login(None);

    let Event::Closed(Some(error)) = next(&events) else {
        panic!("la sesión debía cerrarse con el motivo");
    };
    assert!(error.starts_with("Autenticación fallida"), "{error}");
}

#[test]
fn the_terminal_size_reaches_the_server() {
    let w = World::new();
    let (host, identity) = w.host(Some(PASSWORD));
    let vault = w.vault(data_with(&host, &identity));
    let (session, events) = open(&vault, &host);
    accept_key(&session, &events);
    expect_connected(&events);
    output_until(&events, "bienvenida");

    session.resize(120, 40);
    // El eco confirma que el servidor ya procesó lo enviado antes.
    session.send(b"listo".to_vec());
    output_until(&events, "LISTO");

    assert_eq!(*w.server.sizes.lock().unwrap(), [(80, 24), (120, 40)]);
}

#[test]
fn hosts_that_are_not_ssh_cannot_be_opened() {
    let w = World::new();
    let (host, identity) = w.host(Some(PASSWORD));
    let host = Host {
        protocol: Some(Protocol::Telnet),
        ..host
    };
    let vault = w.vault(data_with(&host, &identity));
    let (tx, _rx) = channel();

    let result = vault.clone().open_terminal(
        host.id.0.to_string(),
        80,
        24,
        Arc::new(Recorder(Mutex::new(tx))),
    );

    assert!(
        matches!(result, Err(TunelError::UnsupportedProtocol { ref name }) if name == "Telnet")
    );
}

#[test]
fn an_unknown_host_is_reported() {
    let w = World::new();
    let vault = w.vault(VaultData::default());
    let (tx, _rx) = channel();

    let result = vault.open_terminal(
        "no-es-un-id".into(),
        80,
        24,
        Arc::new(Recorder(Mutex::new(tx))),
    );

    assert!(matches!(result, Err(TunelError::HostNotFound)));
}
