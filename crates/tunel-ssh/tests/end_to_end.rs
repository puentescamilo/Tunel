//! Pruebas de punta a punta contra un servidor SSH `russh` que corre en el mismo proceso.
//!
//! Las claves de `tests/fixtures` son exclusivas de estas pruebas.

use russh::keys::{PublicKey, decode_secret_key};
use russh::server::{self, Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tunel_core::io::{SessionInput, SessionOutput, session_pair};
use tunel_core::*;
use tunel_ssh::shell::{ShellOptions, run_shell};
use tunel_ssh::{ConnectContext, Interaction, SshConnection, forward};

const USER: &str = "ana";
const PASSWORD: &str = "contraseña-correcta";
const OTP: &str = "123456";
const HOST_KEY: &str = include_str!("fixtures/host_ed25519");
const CLIENT_KEY: &str = include_str!("fixtures/client_ed25519");
const CLIENT_PUB: &str = include_str!("fixtures/client_ed25519.pub");
const CLIENT_PASSPHRASE: &str = "frase-de-paso";
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct TestServer {
    client_key: PublicKey,
    /// Canales con shell abierta: solo ellos usan la "shell" de prueba.
    shells: Arc<std::sync::Mutex<std::collections::HashSet<ChannelId>>>,
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

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if user == USER && key.public_key.key_data() == self.client_key.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
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
        _cols: u32,
        _rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shells.lock().unwrap().insert(channel);
        session.channel_success(channel)?;
        session.data(channel, b"bienvenida\r\n".to_vec())?;
        Ok(())
    }

    /// La "shell" de prueba devuelve en mayúsculas lo que recibe y termina con "exit".
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.shells.lock().unwrap().contains(&channel) {
            return Ok(());
        }
        let text = String::from_utf8_lossy(data);
        if text.contains("exit") {
            session.exit_status_request(channel, 7)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else {
            session.data(channel, text.to_uppercase().into_bytes())?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, [b"eco:", command].concat())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(mut tcp) = tokio::net::TcpStream::connect((host, port as u16)).await else {
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
        });
        Ok(())
    }
}

async fn start_server() -> u16 {
    let key = decode_secret_key(HOST_KEY, None).unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let client_key = PublicKey::from_openssh(CLIENT_PUB.trim()).unwrap();
    tokio::spawn(async move {
        let mut server = TestServer {
            client_key,
            shells: Arc::default(),
        };
        let _ = server.run_on_socket(config, &listener).await;
    });
    port
}

struct Fixture {
    vault: VaultData,
    target: HostId,
}

fn fixture(port: u16, identity: Identity) -> Fixture {
    let host = Host {
        port: Some(port),
        identity: Some(identity.id),
        ..Host::new("prueba", "127.0.0.1")
    };
    let target = host.id;
    Fixture {
        vault: VaultData::default().with_identity(identity).with_host(host),
        target,
    }
}

/// Acepta automáticamente las claves de host y responde a keyboard-interactive con `otp`.
fn auto_answer(
    otp: Option<&'static str>,
) -> (
    mpsc::UnboundedSender<Interaction>,
    tokio::task::JoinHandle<Vec<String>>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Some(interaction) = rx.recv().await {
            match interaction {
                Interaction::HostKey {
                    fingerprint,
                    status,
                    reply,
                    ..
                } => {
                    assert_eq!(status, HostKeyStatus::Unknown);
                    seen.push(fingerprint);
                    let _ = reply.send(true);
                }
                Interaction::KeyboardInteractive { prompts, reply, .. } => {
                    seen.push(format!("prompt:{}", prompts[0].0));
                    let _ = reply.send(otp.map(|o| vec![o.to_string()]));
                }
            }
        }
        seen
    });
    (tx, task)
}

fn context(vault: &VaultData, interactions: mpsc::UnboundedSender<Interaction>) -> ConnectContext {
    let snapshot = vault.clone();
    ConnectContext {
        lookup: Arc::new(move |h, p, a, f| snapshot.check_host_key(h, p, a, f)),
        interactions,
        keepalive: None,
    }
}

async fn connect(
    f: &Fixture,
    interactions: mpsc::UnboundedSender<Interaction>,
) -> Result<SshConnection, tunel_ssh::SshError> {
    let target = f.vault.resolve(f.target).unwrap();
    let jumps = f.vault.resolve_jump_chain(f.target).unwrap();
    tokio::time::timeout(
        TIMEOUT,
        SshConnection::connect(&context(&f.vault, interactions), &jumps, &target),
    )
    .await
    .expect("la conexión no terminó a tiempo")
}

fn password_identity() -> Identity {
    Identity {
        password: Some(PASSWORD.into()),
        ..Identity::new("ana", USER)
    }
}

#[tokio::test]
async fn password_auth_then_exec_returns_output_and_status() {
    let port = start_server().await;
    let f = fixture(port, password_identity());
    let (tx, answers) = auto_answer(None);
    let conn = connect(&f, tx).await.unwrap();
    let (output, status) = conn.exec("uptime").await.unwrap();
    assert_eq!(output, b"eco:uptime");
    assert_eq!(status, Some(0));
    drop(conn);
    let seen = answers.await.unwrap();
    assert!(
        seen[0].starts_with("SHA256:"),
        "se pidió confirmar la huella: {seen:?}"
    );
}

#[tokio::test]
async fn trusted_host_key_connects_without_prompt() {
    let port = start_server().await;
    let host_key = decode_secret_key(HOST_KEY, None).unwrap();
    let fingerprint = host_key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    let f = fixture(port, password_identity());
    let vault = f.vault.trust_host_key(KnownHost {
        host: "127.0.0.1".into(),
        port,
        algorithm: "ssh-ed25519".into(),
        fingerprint,
    });
    let f = Fixture { vault, ..f };
    let (tx, answers) = auto_answer(None);
    connect(&f, tx).await.unwrap();
    assert!(answers.await.unwrap().is_empty());
}

#[tokio::test]
async fn changed_host_key_is_reported_as_mismatch_and_can_be_rejected() {
    let port = start_server().await;
    let f = fixture(port, password_identity());
    let vault = f.vault.trust_host_key(KnownHost {
        host: "127.0.0.1".into(),
        port,
        algorithm: "ssh-ed25519".into(),
        fingerprint: "SHA256:otra-huella".into(),
    });
    let f = Fixture { vault, ..f };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let reject = tokio::spawn(async move {
        if let Some(Interaction::HostKey { status, reply, .. }) = rx.recv().await {
            let _ = reply.send(false);
            return Some(status);
        }
        None
    });
    assert!(connect(&f, tx).await.is_err());
    assert_eq!(
        reject.await.unwrap(),
        Some(HostKeyStatus::Mismatch {
            expected: "ssh-ed25519 SHA256:otra-huella".into()
        })
    );
}

#[tokio::test]
async fn encrypted_private_key_authenticates() {
    let port = start_server().await;
    let key = SshKey {
        passphrase: Some(CLIENT_PASSPHRASE.into()),
        ..SshKey::new("cliente", CLIENT_KEY)
    };
    let identity = Identity {
        key: Some(key.id),
        ..Identity::new("ana", USER)
    };
    let f = fixture(port, identity);
    let f = Fixture {
        vault: f.vault.with_key(key),
        ..f
    };
    let (tx, _answers) = auto_answer(None);
    let conn = connect(&f, tx).await.unwrap();
    assert_eq!(conn.exec("id").await.unwrap().0, b"eco:id");
}

#[tokio::test]
async fn keyboard_interactive_prompts_the_user() {
    let port = start_server().await;
    let f = fixture(port, Identity::new("ana", USER));
    let (tx, answers) = auto_answer(Some(OTP));
    let conn = connect(&f, tx).await.unwrap();
    drop(conn);
    let seen = answers.await.unwrap();
    assert!(seen.iter().any(|s| s == "prompt:Código: "), "{seen:?}");
}

#[tokio::test]
async fn wrong_password_fails_authentication() {
    let port = start_server().await;
    let identity = Identity {
        password: Some("mala".into()),
        ..Identity::new("ana", USER)
    };
    let f = fixture(port, identity);
    let (tx, _answers) = auto_answer(None);
    let err = connect(&f, tx).await.err().expect("debía fallar");
    assert!(matches!(err, tunel_ssh::SshError::AuthFailed(_)), "{err}");
}

#[tokio::test]
async fn interactive_shell_round_trip_and_exit_status() {
    let port = start_server().await;
    let f = fixture(port, password_identity());
    let (tx, _answers) = auto_answer(None);
    let conn = connect(&f, tx).await.unwrap();
    let (mut session, backend) = session_pair();
    let options = ShellOptions {
        cols: 80,
        rows: 24,
        env: Default::default(),
        agent_forwarding: false,
        startup_script: None,
    };
    let shell = tokio::spawn(async move { run_shell(&conn, options, backend).await });

    let mut received = Vec::new();
    let mut sent = false;
    let exit = tokio::time::timeout(TIMEOUT, async {
        loop {
            match session.output.recv().await {
                Some(SessionOutput::Data(d)) => {
                    received.extend(d);
                    let text = String::from_utf8_lossy(&received).to_string();
                    if text.contains("bienvenida") && !sent {
                        session
                            .input
                            .send(SessionInput::Resize {
                                cols: 100,
                                rows: 30,
                            })
                            .unwrap();
                        session
                            .input
                            .send(SessionInput::Data(b"hola".to_vec()))
                            .unwrap();
                        sent = true;
                    }
                    if text.contains("HOLA") {
                        session
                            .input
                            .send(SessionInput::Data(b"exit".to_vec()))
                            .unwrap();
                    }
                }
                Some(SessionOutput::Closed { exit_status }) => return exit_status,
                Some(SessionOutput::Error(e)) => panic!("{e}"),
                None => return None,
            }
        }
    })
    .await
    .expect("la shell no terminó");
    assert_eq!(exit, Some(7));
    shell.await.unwrap().unwrap();
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn local_port_forward_tunnels_tcp() {
    let port = start_server().await;
    let echo = echo_server().await;
    let f = fixture(port, password_identity());
    let (tx, _answers) = auto_answer(None);
    let conn = Arc::new(connect(&f, tx).await.unwrap());
    let rule = PortForward {
        bind_port: 0,
        ..PortForward::local(f.target, 0, "127.0.0.1", echo)
    };
    let active = forward::start(conn, rule).await.unwrap();
    let bound = active.bound.unwrap();

    let mut client = tokio::net::TcpStream::connect(bound).await.unwrap();
    client.write_all(b"por el tunel").await.unwrap();
    let mut buf = [0u8; 12];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"por el tunel");
    active.stop().await;
}

#[tokio::test]
async fn dynamic_forward_acts_as_socks5_proxy() {
    let port = start_server().await;
    let echo = echo_server().await;
    let f = fixture(port, password_identity());
    let (tx, _answers) = auto_answer(None);
    let conn = Arc::new(connect(&f, tx).await.unwrap());
    let rule = PortForward {
        kind: ForwardKind::Dynamic,
        ..PortForward::local(f.target, 0, "", 0)
    };
    let active = forward::start(conn, rule).await.unwrap();

    let socket = tokio::net::TcpStream::connect(active.bound.unwrap())
        .await
        .unwrap();
    let mut stream = tunel_ssh::proxy::socks5_handshake(socket, "127.0.0.1", echo, None)
        .await
        .unwrap();
    stream.write_all(b"socks").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"socks");
}

#[tokio::test]
async fn jump_host_chain_reaches_target() {
    // El mismo servidor hace de bastión y de destino: el segundo salto viaja dentro del primero.
    let port = start_server().await;
    let identity = password_identity();
    let bastion = Host {
        port: Some(port),
        identity: Some(identity.id),
        ..Host::new("bastion", "127.0.0.1")
    };
    let target = Host {
        port: Some(port),
        identity: Some(identity.id),
        jump_hosts: vec![bastion.id],
        ..Host::new("interno", "127.0.0.1")
    };
    let target_id = target.id;
    let vault = VaultData::default()
        .with_identity(identity)
        .with_host(bastion)
        .with_host(target);
    let f = Fixture {
        vault,
        target: target_id,
    };
    let (tx, answers) = auto_answer(None);
    let conn = connect(&f, tx).await.unwrap();
    assert_eq!(conn.exec("hostname").await.unwrap().0, b"eco:hostname");
    drop(conn);
    // Una confirmación de clave por salto.
    assert_eq!(answers.await.unwrap().len(), 2);
}
