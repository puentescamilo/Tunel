//! La terminal SSH del móvil. La conexión, la autenticación y la verificación de la clave
//! del servidor son las del escritorio (`tunel-ssh`); la app solo pinta lo que llega y manda
//! lo que se teclea.
//!
//! Lo que la app tiene que decidir llega por [`TerminalListener`] y se responde con los
//! métodos de [`TerminalSession`].

use crate::runtime::{capitalize, runtime};
use crate::{TunelError, Vault};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tunel_core::io::{SessionInput, SessionOutput, session_pair};
use tunel_core::{HostId, HostKeyStatus, KnownHost, Protocol, ResolveError, ResolvedHost};
use tunel_ssh::shell::{ShellOptions, run_shell};
use tunel_ssh::{ConnectContext, Interaction, SshConnection, SshError};
use uuid::Uuid;

/// Cada cuánto se comprueba que el servidor sigue ahí: en el móvil la red cambia a menudo.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// El servidor presenta una clave que la bóveda no conoce.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostKeyQuestion {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// Huella SHA-256 en formato OpenSSH (`SHA256:…`).
    pub fingerprint: String,
    /// La clave que se conocía, si la del servidor cambió: alguien podría estar
    /// interceptando la conexión.
    pub expected: Option<String>,
}

/// El servidor pide datos para entrar (keyboard-interactive): contraseña, código, PIN…
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginQuestion {
    pub host: String,
    pub instructions: String,
    pub prompts: Vec<LoginPrompt>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginPrompt {
    pub text: String,
    /// `false` para lo que no debe verse al escribirlo, como una contraseña.
    pub echo: bool,
}

/// Lo que la sesión cuenta a la app. Se llama desde hilos del núcleo, nunca desde el
/// principal: la app pasa al suyo lo que toque la interfaz.
#[uniffi::export(with_foreign)]
pub trait TerminalListener: Send + Sync {
    /// La conexión está autenticada y la shell, abierta.
    fn connected(&self);
    /// Bytes para la terminal, tal como llegan del servidor.
    fn output(&self, data: Vec<u8>);
    /// Hay que preguntar si se confía en la clave; responder con
    /// [`TerminalSession::answer_host_key`].
    fn host_key(&self, question: HostKeyQuestion);
    /// Hay que pedir datos para entrar; responder con [`TerminalSession::answer_login`].
    fn login(&self, question: LoginQuestion);
    /// La sesión terminó: `error` es `None` si se cerró con normalidad.
    fn closed(&self, error: Option<String>);
}

/// Pregunta en espera de respuesta. La conexión espera a cada una antes de seguir, así que
/// hay como mucho una.
enum Pending {
    HostKey {
        entry: KnownHost,
        reply: oneshot::Sender<bool>,
    },
    Login(oneshot::Sender<Option<Vec<String>>>),
}

/// Lo que comparten la sesión y las tareas que la atienden.
#[derive(Default)]
struct Shared {
    pending: Mutex<Option<Pending>>,
    /// La persona rechazó la clave del servidor: no es un error que haya que explicar.
    rejected: AtomicBool,
}

impl Shared {
    fn take(&self) -> Option<Pending> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    fn put(&self, pending: Pending) {
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending);
    }
}

/// Una sesión de terminal abierta. Al soltarla se cierra.
#[derive(uniffi::Object)]
pub struct TerminalSession {
    input: mpsc::UnboundedSender<SessionInput>,
    shared: Arc<Shared>,
    /// Sin retener la bóveda: si la app la cierra, la sesión no impide volver a abrirla.
    vault: Weak<Vault>,
}

#[uniffi::export]
impl TerminalSession {
    /// Lo tecleado, en bytes.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.input.send(SessionInput::Data(data));
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.input.send(SessionInput::Resize { cols, rows });
    }

    /// Responde a [`TerminalListener::host_key`]. Si se acepta, la clave se guarda en la
    /// bóveda y la próxima vez no se pregunta.
    pub fn answer_host_key(&self, accept: bool) -> Result<(), TunelError> {
        let Some(Pending::HostKey { entry, reply }) = self.shared.take() else {
            return Ok(());
        };
        if accept && let Some(vault) = self.vault.upgrade() {
            let mut vault = vault.lock();
            let data = vault.data.trust_host_key(entry);
            // Como en el escritorio, la clave aceptada llega a los demás equipos de la cuenta.
            if let Err(error) = crate::vault::commit_local(&mut vault, data) {
                // Sin guardarla, la conexión no sigue: la próxima vez preguntaría otra vez.
                drop(reply);
                return Err(error);
            }
        }
        self.shared.rejected.store(!accept, Ordering::Release);
        let _ = reply.send(accept);
        Ok(())
    }

    /// Responde a [`TerminalListener::login`], una respuesta por pregunta y en orden;
    /// `None` cancela.
    pub fn answer_login(&self, answers: Option<Vec<String>>) {
        if let Some(Pending::Login(reply)) = self.shared.take() {
            let _ = reply.send(answers);
        }
    }

    /// Cierra la sesión; [`TerminalListener::closed`] llega después.
    pub fn disconnect(&self) {
        // Una pregunta sin responder se da por cancelada.
        drop(self.shared.take());
        let _ = self.input.send(SessionInput::Close);
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        self.disconnect();
    }
}

#[uniffi::export]
impl Vault {
    /// Abre una terminal en el host `host_id` con el tamaño de la pantalla. Vuelve enseguida:
    /// la conexión sigue en segundo plano y avisa por `listener`.
    pub fn open_terminal(
        self: Arc<Self>,
        host_id: String,
        cols: u16,
        rows: u16,
        listener: Arc<dyn TerminalListener>,
    ) -> Result<Arc<TerminalSession>, TunelError> {
        let id = Uuid::from_str(&host_id)
            .map(HostId)
            .map_err(|_| TunelError::HostNotFound)?;
        let (target, jumps) = {
            let vault = self.lock();
            (vault.data.resolve(id)?, vault.data.resolve_jump_chain(id)?)
        };
        let notice = protocol_notice(target.host.protocol.as_ref())?;

        let (io, backend) = session_pair();
        let (interactions, questions) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        let vault = Arc::downgrade(&self);
        let lookup_vault = vault.clone();
        let ctx = ConnectContext {
            lookup: Arc::new(move |host, port, algorithm, fingerprint| {
                lookup_vault.upgrade().map_or(HostKeyStatus::Unknown, |v| {
                    v.lock()
                        .data
                        .check_host_key(host, port, algorithm, fingerprint)
                })
            }),
            interactions,
            keepalive: Some(KEEPALIVE),
            security_key: None,
        };
        let options = ShellOptions {
            cols,
            rows,
            env: Default::default(),
            agent_forwarding: false,
            x11_display: None,
            startup_script: None,
            command: None,
        };
        if let Some(notice) = notice {
            listener.output(notice.into_bytes());
        }
        let runtime = runtime();
        runtime.spawn(ask(questions, shared.clone(), listener.clone()));
        runtime.spawn(run(
            Connection {
                ctx,
                jumps,
                target,
                options,
            },
            backend,
            io.output,
            shared.clone(),
            listener,
        ));
        Ok(Arc::new(TerminalSession {
            input: io.input,
            shared,
            vault,
        }))
    }
}

/// Lo que dice la terminal antes de conectar, o por qué no se puede abrir el host aquí.
fn protocol_notice(protocol: Option<&Protocol>) -> Result<Option<String>, TunelError> {
    match protocol {
        None | Some(Protocol::Ssh) => Ok(None),
        Some(Protocol::Mosh { .. }) => Ok(Some(
            "\x1b[33mTúnel: Mosh no está disponible en este dispositivo; se abre por SSH.\x1b[0m\r\n"
                .into(),
        )),
        Some(other @ (Protocol::Telnet | Protocol::Serial { .. })) => {
            Err(TunelError::UnsupportedProtocol {
                name: other.label().into(),
            })
        }
    }
}

/// Pasa a la app cada pregunta de la conexión y guarda cómo responderla.
async fn ask(
    mut questions: mpsc::UnboundedReceiver<Interaction>,
    shared: Arc<Shared>,
    listener: Arc<dyn TerminalListener>,
) {
    while let Some(interaction) = questions.recv().await {
        match interaction {
            Interaction::HostKey {
                host,
                port,
                algorithm,
                fingerprint,
                status,
                reply,
            } => {
                let expected = match status {
                    HostKeyStatus::Mismatch { expected } => Some(expected),
                    HostKeyStatus::Trusted | HostKeyStatus::Unknown => None,
                };
                let question = HostKeyQuestion {
                    host: host.clone(),
                    port,
                    algorithm: algorithm.clone(),
                    fingerprint: fingerprint.clone(),
                    expected,
                };
                shared.put(Pending::HostKey {
                    entry: KnownHost {
                        host,
                        port,
                        algorithm,
                        fingerprint,
                    },
                    reply,
                });
                listener.host_key(question);
            }
            Interaction::KeyboardInteractive {
                host,
                instructions,
                prompts,
                reply,
            } => {
                shared.put(Pending::Login(reply));
                listener.login(LoginQuestion {
                    host,
                    instructions,
                    prompts: prompts
                        .into_iter()
                        .map(|(text, echo)| LoginPrompt { text, echo })
                        .collect(),
                });
            }
            // En el móvil no hay llaves de seguridad: la firma falla antes de pedir tocarla.
            Interaction::TouchSecurityKey { .. } => {}
        }
    }
}

struct Connection {
    ctx: ConnectContext,
    jumps: Vec<ResolvedHost>,
    target: ResolvedHost,
    options: ShellOptions,
}

/// Conecta, abre la shell y pasa su salida a la app hasta que se cierre.
async fn run(
    connection: Connection,
    backend: tunel_core::io::BackendIo,
    mut output: mpsc::UnboundedReceiver<SessionOutput>,
    shared: Arc<Shared>,
    listener: Arc<dyn TerminalListener>,
) {
    let Connection {
        ctx,
        jumps,
        target,
        options,
    } = connection;
    let conn = match SshConnection::connect(&ctx, &jumps, &target).await {
        Ok(conn) => conn,
        Err(error) => {
            let rejected = shared.rejected.load(Ordering::Acquire);
            listener.closed(Some(connect_error(&error, rejected)));
            return;
        }
    };
    // Sin `ctx`, la tarea de preguntas termina.
    drop(ctx);
    listener.connected();
    let shell = tokio::spawn(async move {
        let result = run_shell(&conn, options, backend).await;
        conn.disconnect().await;
        result
    });
    while let Some(message) = output.recv().await {
        match message {
            SessionOutput::Data(data) => listener.output(data),
            SessionOutput::Closed { .. } => break,
            SessionOutput::Error(message) => {
                listener.closed(Some(message));
                return;
            }
            SessionOutput::Resize { .. } => {}
        }
    }
    let error = match shell.await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(capitalize(&error.to_string())),
        Err(_) => Some("La sesión terminó de forma inesperada".into()),
    };
    listener.closed(error);
}

fn connect_error(error: &SshError, rejected: bool) -> String {
    if rejected {
        return "No se conectó: rechazaste la clave del servidor".into();
    }
    match error {
        SshError::SecurityKey(_) => {
            "Esta identidad usa una llave de seguridad, que no está disponible en este \
             dispositivo"
                .into()
        }
        other => capitalize(&other.to_string()),
    }
}

impl From<ResolveError> for TunelError {
    fn from(error: ResolveError) -> Self {
        match error {
            ResolveError::HostNotFound => Self::HostNotFound,
            other => Self::Connection {
                detail: capitalize(&other.to_string()),
            },
        }
    }
}
