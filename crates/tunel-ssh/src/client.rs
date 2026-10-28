//! Conexión SSH: verificación de clave de host, autenticación y cadenas de jump hosts.

use crate::fido::{self, SkKey, SkSigner};
use crate::proxy;
use crate::x11::X11Forwarding;
use russh::client::{self, ChannelOpenHandle, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{
    Certificate, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key,
};
use russh::{Channel, Disconnect};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tunel_core::{HostKeyStatus, ResolvedHost};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 10;
/// Tope de salida de `exec` para que un servidor hostil no agote la memoria.
pub const MAX_EXEC_OUTPUT: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("SSH: {0}")]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Proxy(#[from] proxy::ProxyError),
    #[error("clave privada no válida: {0}")]
    Key(String),
    #[error("certificado no válido: {0}")]
    Certificate(String),
    #[error("autenticación fallida para {0}")]
    AuthFailed(String),
    #[error("el host no tiene usuario configurado")]
    MissingUsername,
    #[error("clave de host rechazada")]
    HostKeyRejected,
    #[error("tiempo de conexión agotado")]
    Timeout,
    #[error("la interfaz cerró la conversación")]
    InteractionClosed,
    #[error("agente SSH: {0}")]
    Agent(String),
    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("X11: {0}")]
    X11(#[from] crate::x11::X11Error),
    #[error(transparent)]
    SecurityKey(#[from] fido::FidoError),
}

impl From<fido::SkSignError> for SshError {
    fn from(error: fido::SkSignError) -> Self {
        match error {
            fido::SkSignError::Fido(e) => Self::SecurityKey(e),
            fido::SkSignError::Send(_) => Self::InteractionClosed,
        }
    }
}

/// Pregunta que la conexión necesita que responda el usuario.
#[derive(Debug)]
pub enum Interaction {
    HostKey {
        host: String,
        port: u16,
        algorithm: String,
        fingerprint: String,
        status: HostKeyStatus,
        reply: oneshot::Sender<bool>,
    },
    KeyboardInteractive {
        host: String,
        instructions: String,
        prompts: Vec<(String, bool)>,
        reply: oneshot::Sender<Option<Vec<String>>>,
    },
    /// Hay que tocar la llave de seguridad; `finished` pasa a `true` al terminar la firma.
    TouchSecurityKey {
        host: String,
        finished: Arc<AtomicBool>,
    },
}

/// Consulta la bóveda para saber si una clave ya es de confianza.
pub type HostKeyLookup = Arc<dyn Fn(&str, u16, &str, &str) -> HostKeyStatus + Send + Sync>;

/// Destinos locales de los reenvíos remotos (`-R`), por (dirección, puerto) del servidor.
pub type RemoteForwardTargets = Arc<Mutex<HashMap<(String, u32), (String, u16)>>>;

/// Reenvío X11 activo en la conexión; vacío mientras ninguna shell lo haya pedido.
pub type X11Slot = Arc<Mutex<Option<Arc<X11Forwarding>>>>;

pub struct ClientHandler {
    host: String,
    port: u16,
    lookup: HostKeyLookup,
    interactions: mpsc::UnboundedSender<Interaction>,
    remote_targets: RemoteForwardTargets,
    x11: X11Slot,
}

fn describe_key(key: &PublicKeyOrCertificate) -> (String, String) {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => (
            key.algorithm().as_str().to_string(),
            key.fingerprint(HashAlg::Sha256).to_string(),
        ),
        PublicKeyOrCertificate::Certificate(cert) => (
            cert.algorithm().as_str().to_string(),
            cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
        ),
    }
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let (algorithm, fingerprint) = describe_key(server_public_key);
        let status = (self.lookup)(&self.host, self.port, &algorithm, &fingerprint);
        if status == HostKeyStatus::Trusted {
            return Ok(true);
        }
        let (reply, answer) = oneshot::channel();
        self.interactions
            .send(Interaction::HostKey {
                host: self.host.clone(),
                port: self.port,
                algorithm,
                fingerprint,
                status,
                reply,
            })
            .map_err(|_| SshError::InteractionClosed)?;
        answer.await.map_err(|_| SshError::InteractionClosed)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self.remote_targets.lock().ok().and_then(|m| {
            m.get(&(connected_address.to_string(), connected_port))
                .cloned()
        });
        let Some((host, port)) = target else {
            tracing::warn!(
                connected_address,
                connected_port,
                "reenvío remoto sin destino registrado"
            );
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                Ok(mut tcp) => {
                    let mut stream = channel.into_stream();
                    if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await {
                        tracing::debug!(error = %e, "reenvío remoto terminado");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, host, port, "no se pudo conectar el destino del reenvío remoto")
                }
            }
        });
        Ok(())
    }

    /// Solo se aceptan canales X11 si una shell de esta conexión pidió el reenvío; la cookie
    /// de cada conexión X11 se comprueba después, en [`X11Forwarding::serve`].
    async fn server_channel_open_x11(
        &mut self,
        channel: Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let forwarding = self.x11.lock().ok().and_then(|slot| slot.clone());
        let Some(forwarding) = forwarding else {
            tracing::warn!(host = self.host, "canal X11 no solicitado; rechazado");
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(forwarding.serve(channel));
        Ok(())
    }
}

/// Sesión SSH autenticada, con los saltos intermedios que la mantienen viva.
pub struct SshConnection {
    handle: Arc<Handle<ClientHandler>>,
    _hops: Vec<Arc<Handle<ClientHandler>>>,
    remote_targets: RemoteForwardTargets,
    x11: X11Slot,
    pub label: String,
}

pub struct ConnectContext {
    pub lookup: HostKeyLookup,
    pub interactions: mpsc::UnboundedSender<Interaction>,
    pub keepalive: Option<Duration>,
    /// Llave de seguridad para las claves `sk-*`; `None` usa la del sistema.
    pub security_key: Option<Arc<dyn fido::Authenticator>>,
}

fn config(keepalive: Option<Duration>) -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: keepalive,
        nodelay: true,
        ..Default::default()
    })
}

impl SshConnection {
    /// Conecta a `target` atravesando `jumps` en orden.
    pub async fn connect(
        ctx: &ConnectContext,
        jumps: &[ResolvedHost],
        target: &ResolvedHost,
    ) -> Result<Self, SshError> {
        tokio::time::timeout(
            CONNECT_TIMEOUT * (jumps.len() as u32 + 1),
            Self::connect_inner(ctx, jumps, target),
        )
        .await
        .map_err(|_| SshError::Timeout)?
    }

    async fn connect_inner(
        ctx: &ConnectContext,
        jumps: &[ResolvedHost],
        target: &ResolvedHost,
    ) -> Result<Self, SshError> {
        let remote_targets: RemoteForwardTargets = Arc::default();
        let x11: X11Slot = Arc::default();
        let hops: Vec<&ResolvedHost> = jumps.iter().chain(std::iter::once(target)).collect();
        // Solo el destino final recibe canales X11; los saltos intermedios nunca los aceptan.
        let handler = |h: &ResolvedHost| ClientHandler {
            host: h.host.address.clone(),
            port: h.port,
            lookup: ctx.lookup.clone(),
            interactions: ctx.interactions.clone(),
            remote_targets: remote_targets.clone(),
            x11: if std::ptr::eq(h, target) {
                x11.clone()
            } else {
                Arc::default()
            },
        };
        let first = hops[0];
        let stream =
            proxy::connect(first.host.proxy.as_ref(), &first.host.address, first.port).await?;
        let mut handle =
            client::connect_stream(config(ctx.keepalive), stream, handler(first)).await?;
        authenticate(&mut handle, first, ctx).await?;

        let mut previous = Vec::new();
        for hop in &hops[1..] {
            let channel = handle
                .channel_open_direct_tcpip(
                    hop.host.address.clone(),
                    u32::from(hop.port),
                    "127.0.0.1",
                    0,
                )
                .await?;
            let mut next =
                client::connect_stream(config(ctx.keepalive), channel.into_stream(), handler(hop))
                    .await?;
            authenticate(&mut next, hop, ctx).await?;
            previous.push(Arc::new(std::mem::replace(&mut handle, next)));
        }
        Ok(Self {
            handle: Arc::new(handle),
            _hops: previous,
            remote_targets,
            x11,
            label: target.host.display_name().to_string(),
        })
    }

    pub fn handle(&self) -> &Handle<ClientHandler> {
        &self.handle
    }

    pub(crate) fn remote_targets(&self) -> &RemoteForwardTargets {
        &self.remote_targets
    }

    /// Activa el reenvío X11 de la conexión; sustituye al anterior si lo había.
    pub(crate) fn set_x11(&self, forwarding: Arc<X11Forwarding>) {
        if let Ok(mut slot) = self.x11.lock() {
            *slot = Some(forwarding);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub async fn disconnect(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "es")
            .await;
    }

    /// Ejecuta un comando sin PTY y devuelve (salida, código de salida).
    pub async fn exec(&self, command: &str) -> Result<(Vec<u8>, Option<u32>), SshError> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        let mut output = Vec::new();
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    let room = MAX_EXEC_OUTPUT.saturating_sub(output.len());
                    output.extend_from_slice(&data[..data.len().min(room)]);
                    if room <= data.len() {
                        let _ = channel.close().await;
                        break;
                    }
                }
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok((output, status))
    }
}

/// Clave privada en el equipo, con certificado OpenSSH si lo hay.
async fn authenticate_with_key(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    private: russh::keys::PrivateKey,
    certificate: Option<Certificate>,
) -> Result<bool, SshError> {
    let private = Arc::new(private);
    let result = match certificate {
        Some(cert) => {
            handle
                .authenticate_openssh_cert(user.to_string(), private, cert)
                .await?
        }
        None => {
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            handle
                .authenticate_publickey(user.to_string(), PrivateKeyWithHashAlg::new(private, hash))
                .await?
        }
    };
    Ok(result.success())
}

/// Clave `sk-*`: firma la llave de seguridad. Pide el PIN si la clave lo exige y avisa de
/// que hay que tocarla mientras espera.
async fn authenticate_with_security_key(
    handle: &mut Handle<ClientHandler>,
    target: &ResolvedHost,
    ctx: &ConnectContext,
    key: SkKey,
    certificate: Option<Certificate>,
) -> Result<bool, SshError> {
    let identity = target.identity.as_ref().ok_or(SshError::MissingUsername)?;
    let user = identity.username.clone();
    let authenticator = match &ctx.security_key {
        Some(authenticator) => authenticator.clone(),
        None => fido::system_authenticator()?,
    };
    let host = target.host.address.clone();
    let pin = if key.needs_pin() {
        Some(ask_security_key_pin(&ctx.interactions, &host).await?)
    } else {
        None
    };
    let finished = Arc::new(AtomicBool::new(false));
    if key.needs_touch() {
        ctx.interactions
            .send(Interaction::TouchSecurityKey {
                host,
                finished: finished.clone(),
            })
            .map_err(|_| SshError::InteractionClosed)?;
    }
    let public = key.public.clone();
    let mut signer = SkSigner {
        key,
        authenticator,
        pin,
    };
    let result = match certificate {
        Some(cert) => {
            handle
                .authenticate_certificate_with(user, cert, None, &mut signer)
                .await
        }
        None => {
            handle
                .authenticate_publickey_with(user, public, None, &mut signer)
                .await
        }
    };
    finished.store(true, Ordering::Release);
    Ok(result?.success())
}

async fn ask_security_key_pin(
    interactions: &mpsc::UnboundedSender<Interaction>,
    host: &str,
) -> Result<String, SshError> {
    let (reply, answer) = oneshot::channel();
    interactions
        .send(Interaction::KeyboardInteractive {
            host: host.to_string(),
            instructions: "Esta clave necesita el PIN de tu llave de seguridad.".into(),
            prompts: vec![("PIN de la llave".into(), false)],
            reply,
        })
        .map_err(|_| SshError::InteractionClosed)?;
    answer
        .await
        .map_err(|_| SshError::InteractionClosed)?
        .and_then(|answers| answers.into_iter().next())
        .filter(|pin| !pin.is_empty())
        .ok_or(fido::FidoError::PinRequired.into())
}

/// Prueba, en orden: clave (con certificado si lo hay), agente, contraseña y keyboard-interactive.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    target: &ResolvedHost,
    ctx: &ConnectContext,
) -> Result<(), SshError> {
    let interactions = &ctx.interactions;
    let identity = target.identity.as_ref().ok_or(SshError::MissingUsername)?;
    let user = identity.username.clone();
    if user.trim().is_empty() {
        return Err(SshError::MissingUsername);
    }

    if let Some(key) = &target.key {
        let private = decode_secret_key(&key.private_key, key.passphrase.as_deref())
            .map_err(|e| SshError::Key(e.to_string()))?;
        let certificate = key
            .certificate
            .as_deref()
            .map(|text| Certificate::from_openssh(text.trim()))
            .transpose()
            .map_err(|e| SshError::Certificate(e.to_string()))?;
        if let Some(sk) = SkKey::from_private(&private) {
            if authenticate_with_security_key(handle, target, ctx, sk, certificate).await? {
                return Ok(());
            }
        } else if authenticate_with_key(handle, &user, private, certificate).await? {
            return Ok(());
        }
    }

    if identity.use_agent && authenticate_with_agent(handle, &user).await? {
        return Ok(());
    }

    if let Some(password) = &identity.password
        && handle
            .authenticate_password(user.clone(), password.clone())
            .await?
            .success()
    {
        return Ok(());
    }

    if keyboard_interactive(
        handle,
        target,
        &user,
        identity.password.as_deref(),
        interactions,
    )
    .await?
    {
        return Ok(());
    }
    Err(SshError::AuthFailed(format!(
        "{user}@{}",
        target.host.address
    )))
}

#[cfg(unix)]
async fn authenticate_with_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
) -> Result<bool, SshError> {
    let mut agent = match russh::keys::agent::client::AgentClient::connect_env().await {
        Ok(agent) => agent,
        Err(e) => {
            tracing::info!(error = %e, "agente SSH no disponible");
            return Ok(false);
        }
    };
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| SshError::Agent(e.to_string()))?;
    for identity in identities {
        let key = identity.public_key().into_owned();
        let hash = handle.best_supported_rsa_hash().await?.flatten();
        match handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
        {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "el agente no pudo firmar"),
        }
    }
    Ok(false)
}

#[cfg(windows)]
async fn authenticate_with_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
) -> Result<bool, SshError> {
    const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
    let mut agent =
        match russh::keys::agent::client::AgentClient::connect_named_pipe(OPENSSH_PIPE).await {
            Ok(agent) => agent,
            Err(e) => {
                tracing::info!(error = %e, "agente SSH no disponible");
                return Ok(false);
            }
        };
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| SshError::Agent(e.to_string()))?;
    for identity in identities {
        let key = identity.public_key().into_owned();
        let hash = handle.best_supported_rsa_hash().await?.flatten();
        match handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
        {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "el agente no pudo firmar"),
        }
    }
    Ok(false)
}

/// `true` para prompts como "Password:" o "Contraseña de ana:", no para "New password" ni códigos.
pub fn asks_for_password(prompt: &str) -> bool {
    let p = prompt.to_lowercase();
    (p.contains("password") || p.contains("contraseña"))
        && ![
            "new",
            "nueva",
            "retype",
            "again",
            "otp",
            "code",
            "código",
            "token",
            "verification",
        ]
        .iter()
        .any(|w| p.contains(w))
}

async fn keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    target: &ResolvedHost,
    user: &str,
    saved_password: Option<&str>,
    interactions: &mpsc::UnboundedSender<Interaction>,
) -> Result<bool, SshError> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    let mut used_saved_password = false;
    for _ in 0..MAX_KEYBOARD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                instructions,
                prompts,
                ..
            } => {
                let answers = match (prompts.as_slice(), saved_password) {
                    ([], _) => Vec::new(),
                    // Reutilizar la contraseña guardada solo si el servidor la pide explícitamente;
                    // un código 2FA o "nueva contraseña" debe responderlo el usuario.
                    ([only], Some(pw))
                        if !only.echo
                            && !used_saved_password
                            && asks_for_password(&only.prompt) =>
                    {
                        used_saved_password = true;
                        vec![pw.to_string()]
                    }
                    _ => {
                        let (reply, answer) = oneshot::channel();
                        interactions
                            .send(Interaction::KeyboardInteractive {
                                host: target.host.address.clone(),
                                instructions,
                                prompts: prompts
                                    .iter()
                                    .map(|p| (p.prompt.clone(), p.echo))
                                    .collect(),
                                reply,
                            })
                            .map_err(|_| SshError::InteractionClosed)?;
                        match answer.await.map_err(|_| SshError::InteractionClosed)? {
                            Some(answers) => answers,
                            None => return Ok(false),
                        }
                    }
                };
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_password_only_answers_password_prompts() {
        assert!(asks_for_password("Password: "));
        assert!(asks_for_password("ana@srv's password:"));
        assert!(asks_for_password("Contraseña: "));
        assert!(!asks_for_password("Verification code: "));
        assert!(!asks_for_password("New password: "));
        assert!(!asks_for_password("OTP token:"));
        assert!(!asks_for_password("Código: "));
    }
}
