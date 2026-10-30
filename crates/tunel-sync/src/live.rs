//! Sesiones compartidas desde el cliente: compartir una terminal abierta con un Team y
//! mirar las de los demás (ver [`tunel_core::sync::live`]).
//!
//! Cada sesión corre en su propia tarea, que habla con el servidor por WebSocket. La
//! aplicación se comunica con ella por canales: [`LiveHost`] para quien comparte y, para
//! quien mira, un [`SessionIo`] como el de cualquier terminal más un [`LiveViewer`].

use crate::SyncError;
use crate::api::LiveRole;
use crate::session::{Session, call};
use crate::teams::{KeyStatus, key_status};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::{CloseCode, Message, WebSocket};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::mpsc;
use tunel_core::io::{BackendIo, SessionInput, SessionIo, SessionOutput, session_pair};
use tunel_core::sync::live::{
    ControlContext, ControlKey, InputOpener, InputSealer, JoinNonce, LiveFrame, LiveKey, LiveMeta,
    MAX_FRAME, MAX_INPUT, MetaContext, OutputOpener, OutputSealer, open_meta, seal_meta,
    unwrap_control_key, wrap_control_key,
};
use tunel_core::sync::protocol::{
    ConnId, CreateLiveRequest, HostEvent, HostMessage, LiveAnnouncement, ViewerEvent, ViewerMessage,
};
use tunel_core::sync::{AccountKeypair, KeyProblem, PublicKey, SyncLocal, VaultKey};
use uuid::Uuid;

/// Trozo máximo de salida por fotograma.
const OUTPUT_CHUNK: usize = 16 * 1024;
/// Salida en cola sin enviar a partir de la cual se descarta lo nuevo y, cuando se vacía,
/// se manda la pantalla entera.
const OUTPUT_BACKLOG: usize = 4 * 1024 * 1024;
/// Restablece la terminal de quien mira antes de pintar una pantalla entera.
const RESET: &[u8] = b"\x1bc";

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

fn keypair(local: &SyncLocal) -> Result<&AccountKeypair, SyncError> {
    local.keypair.as_ref().ok_or(SyncError::NoKeypair)
}

fn with_token(session: &Session, local: &SyncLocal) -> SyncLocal {
    SyncLocal {
        token: session.current_token(),
        ..local.clone()
    }
}

fn to_message<T: serde::Serialize>(message: &T) -> Message {
    Message::Text(serde_json::to_string(message).expect("los mensajes siempre se serializan"))
}

/// Una sesión compartida en curso de un Team, tal como se ve antes de mirarla.
#[derive(Debug, Clone)]
pub struct LiveListing {
    pub team: String,
    pub id: String,
    /// Correo de quien comparte, según el servidor.
    pub owner: String,
    pub viewers: u32,
    /// Título, si se pudo abrir el anuncio (falla si se cifró con otra clave del Team).
    pub title: Option<String>,
    /// Si la clave pública del anuncio es la que se conoce de quien comparte. Con
    /// [`KeyStatus::Changed`], otra persona del Team se está haciendo pasar por ella.
    pub owner_key: Option<KeyStatus>,
    meta: Option<LiveMeta>,
}

impl LiveListing {
    /// Huella de la clave de quien comparte.
    pub fn owner_fingerprint(&self) -> Option<String> {
        self.meta.as_ref().map(|m| m.host.fingerprint())
    }
}

/// Sesiones compartidas en curso en el Team `team`.
pub async fn live_sessions(
    local: &SyncLocal,
    team: &str,
) -> Result<(SyncLocal, Vec<LiveListing>), SyncError> {
    let team_local = local
        .team(team)
        .ok_or_else(|| SyncError::NotFound("Team".into()))?;
    let mut session = Session::new(local)?;
    let summaries = call!(&mut session, |api, token| api.live_sessions(token, team))?;
    let listings = summaries
        .into_iter()
        .map(|summary| {
            let context = MetaContext {
                team,
                epoch: summary.epoch,
                session: &summary.id,
            };
            let meta = (summary.epoch == team_local.epoch)
                .then(|| open_meta(&team_local.key, context, &summary.meta).ok())
                .flatten();
            LiveListing {
                team: team.to_string(),
                owner_key: meta
                    .as_ref()
                    .map(|m| key_status(local, &summary.owner, m.host)),
                title: meta.as_ref().map(|m| m.title.clone()),
                id: summary.id,
                owner: summary.owner,
                viewers: summary.viewers,
                meta,
            }
        })
        .collect();
    Ok((with_token(&session, local), listings))
}

/// La clave pública de quien pide el control, solo si ya está fijada. Si no, el error
/// dice si falta confirmar la huella o si cambió (ver [`crate::teams::lookup_key`]).
pub async fn viewer_key(
    local: &SyncLocal,
    email: &str,
) -> Result<(SyncLocal, PublicKey), SyncError> {
    let mut session = Session::new(local)?;
    let found = call!(&mut session, |api, token| api.user_key(token, email))?;
    local.check_key(email, found.public_key)?;
    Ok((with_token(&session, local), found.public_key))
}

/// Lo que la aplicación pide a la tarea de una sesión que comparte.
enum HostCommand {
    Output(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Pantalla entera para quien llegó (`Some`) o para todos (`None`).
    Snapshot {
        to: Option<ConnId>,
        cols: u16,
        rows: u16,
        data: Vec<u8>,
    },
    Grant {
        conn: ConnId,
        key: PublicKey,
    },
    Revoke(ConnId),
    Kick(ConnId),
    Reannounce {
        key: VaultKey,
        epoch: u64,
    },
}

/// Lo que pasa en una sesión que se comparte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostUpdate {
    /// Llega alguien: hay que mandarle la pantalla con [`LiveHost::welcome`].
    Joined {
        conn: ConnId,
        email: String,
    },
    Left {
        conn: ConnId,
    },
    ControlRequested {
        conn: ConnId,
    },
    /// Lo que escribe quien tiene el control.
    Input {
        conn: ConnId,
        data: Vec<u8>,
    },
    /// Quien tenía el control lo pierde: llegó entrada que no se pudo abrir o faltaba
    /// algún trozo.
    ControlLost {
        conn: ConnId,
    },
    /// La sesión terminó; con un motivo si fue por un error.
    Ended(Option<String>),
}

/// Una terminal que se está compartiendo.
pub struct LiveHost {
    pub id: String,
    pub team: String,
    commands: mpsc::UnboundedSender<HostCommand>,
    updates: mpsc::UnboundedReceiver<HostUpdate>,
    /// Bytes de salida en cola sin enviar.
    backlog: Arc<AtomicUsize>,
    /// Se descartó salida: quien mira necesita la pantalla entera.
    resync: Arc<AtomicBool>,
}

impl LiveHost {
    fn command(&self, command: HostCommand) {
        let _ = self.commands.send(command);
    }

    /// Salida de la terminal. Si el servidor no da abasto, se descarta y se pide
    /// [`LiveHost::needs_resync`].
    pub fn output(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.backlog.load(Ordering::Relaxed) > OUTPUT_BACKLOG {
            self.resync.store(true, Ordering::Relaxed);
            return;
        }
        self.backlog.fetch_add(bytes.len(), Ordering::Relaxed);
        self.command(HostCommand::Output(bytes.to_vec()));
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        self.command(HostCommand::Resize { cols, rows });
    }

    /// Pantalla entera (ver `Emulator::snapshot`) para quien acaba de llegar.
    pub fn welcome(&self, conn: ConnId, cols: u16, rows: u16, snapshot: Vec<u8>) {
        self.command(HostCommand::Snapshot {
            to: Some(conn),
            cols,
            rows,
            data: snapshot,
        });
    }

    /// Se descartó salida y hay que mandar a todos la pantalla entera cuando se pueda.
    pub fn needs_resync(&self) -> bool {
        self.resync.load(Ordering::Relaxed) && self.backlog.load(Ordering::Relaxed) == 0
    }

    pub fn resync(&self, cols: u16, rows: u16, snapshot: Vec<u8>) {
        self.resync.store(false, Ordering::Relaxed);
        self.command(HostCommand::Snapshot {
            to: None,
            cols,
            rows,
            data: snapshot,
        });
    }

    /// Da el control a `conn`; `key` es su clave pública ya comprobada (ver
    /// [`viewer_key`]).
    pub fn grant(&self, conn: ConnId, key: PublicKey) {
        self.command(HostCommand::Grant { conn, key });
    }

    pub fn revoke(&self, conn: ConnId) {
        self.command(HostCommand::Revoke(conn));
    }

    pub fn kick(&self, conn: ConnId) {
        self.command(HostCommand::Kick(conn));
    }

    /// Vuelve a cifrar el anuncio con la clave nueva del Team.
    pub fn reannounce(&self, key: VaultKey, epoch: u64) {
        self.command(HostCommand::Reannounce { key, epoch });
    }

    pub fn try_update(&mut self) -> Option<HostUpdate> {
        self.updates.try_recv().ok()
    }

    /// Espera al siguiente aviso; `None` cuando la tarea ya terminó.
    pub async fn next_update(&mut self) -> Option<HostUpdate> {
        self.updates.recv().await
    }
}

/// Empieza a compartir una terminal con el Team `team`. Al soltar el [`LiveHost`], la
/// sesión termina.
pub async fn share(
    local: &SyncLocal,
    team: &str,
    title: &str,
) -> Result<(SyncLocal, LiveHost), SyncError> {
    let keypair = keypair(local)?.clone();
    let team_local = local
        .team(team)
        .ok_or_else(|| SyncError::NotFound("Team".into()))?;
    let id = Uuid::new_v4().to_string();
    let meta = LiveMeta {
        title: title.to_string(),
        key: LiveKey::generate(),
        host: keypair.public(),
    };
    let request = CreateLiveRequest {
        id: id.clone(),
        announcement: announcement(&team_local.key, team, team_local.epoch, &id, &meta)?,
    };
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api
        .create_live(token, team, &request))?;
    let socket = call!(&mut session, |api, token| api.connect_live(
        token,
        team,
        &id,
        LiveRole::Host
    ))?;
    let local = with_token(&session, local);
    let (commands_tx, commands) = mpsc::unbounded_channel();
    let (updates_tx, updates) = mpsc::unbounded_channel();
    let backlog = Arc::new(AtomicUsize::new(0));
    let (sink, stream) = socket.split();
    let task = HostTask {
        sink,
        session,
        team: team.to_string(),
        id: id.clone(),
        sealer: OutputSealer::new(&meta.key, &id),
        meta,
        keypair,
        viewers: HashMap::new(),
        grants: 0,
        updates: updates_tx,
        backlog: backlog.clone(),
    };
    tokio::spawn(task.run(stream, commands));
    Ok((
        local,
        LiveHost {
            id,
            team: team.to_string(),
            commands: commands_tx,
            updates,
            backlog,
            resync: Arc::new(AtomicBool::new(false)),
        },
    ))
}

fn announcement(
    key: &VaultKey,
    team: &str,
    epoch: u64,
    id: &str,
    meta: &LiveMeta,
) -> Result<LiveAnnouncement, SyncError> {
    let context = MetaContext {
        team,
        epoch,
        session: id,
    };
    Ok(LiveAnnouncement {
        epoch,
        meta: seal_meta(key, context, meta)?,
    })
}

/// Quien está mirando una sesión que se comparte.
struct Watcher {
    nonce: JoinNonce,
    /// Con el control: su concesión y lo que escribe.
    input: Option<(u64, InputOpener)>,
}

struct HostTask {
    sink: Sink,
    session: Session,
    team: String,
    id: String,
    meta: LiveMeta,
    keypair: AccountKeypair,
    sealer: OutputSealer,
    viewers: HashMap<ConnId, Watcher>,
    grants: u64,
    updates: mpsc::UnboundedSender<HostUpdate>,
    backlog: Arc<AtomicUsize>,
}

/// Cómo terminó la tarea de una sesión.
type Outcome = Result<(), String>;

impl HostTask {
    async fn run(mut self, mut stream: Stream, mut commands: mpsc::UnboundedReceiver<HostCommand>) {
        let outcome: Outcome = loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => {
                        if let Err(e) = self.command(command).await {
                            break Err(e);
                        }
                    }
                    None => {
                        let _ = self.sink.close().await;
                        break Ok(());
                    }
                },
                message = stream.next() => match message {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = self.event(&text).await {
                            break Err(e);
                        }
                    }
                    Some(Ok(Message::Close { code, reason })) => break closed(code, reason),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break Err(crate::api::live_error(e).to_string()),
                    None => break Err("se perdió la conexión con el servidor".into()),
                },
            }
        };
        let _ = self.updates.send(HostUpdate::Ended(outcome.err()));
    }

    async fn send(&mut self, message: &HostMessage) -> Outcome {
        self.sink
            .send(to_message(message))
            .await
            .map_err(|e| crate::api::live_error(e).to_string())
    }

    async fn broadcast(&mut self, frame: &LiveFrame) -> Outcome {
        let frame = self.sealer.seal(frame).map_err(|e| e.to_string())?;
        self.send(&HostMessage::Output { frame }).await
    }

    async fn command(&mut self, command: HostCommand) -> Outcome {
        match command {
            HostCommand::Output(bytes) => {
                for chunk in bytes.chunks(OUTPUT_CHUNK) {
                    self.broadcast(&LiveFrame::Output(chunk.to_vec())).await?;
                }
                self.backlog.fetch_sub(bytes.len(), Ordering::Relaxed);
            }
            HostCommand::Resize { cols, rows } => {
                self.broadcast(&LiveFrame::Resize { cols, rows }).await?;
            }
            HostCommand::Snapshot {
                to,
                cols,
                rows,
                data,
            } => {
                // Una pantalla que no cabe en un fotograma se manda en blanco: el
                // programa la redibujará al cambiar algo.
                let data = if data.len() + 4 > MAX_FRAME {
                    Vec::new()
                } else {
                    data
                };
                match to {
                    None => {
                        let frame = LiveFrame::Snapshot { cols, rows, data };
                        self.broadcast(&frame).await?;
                    }
                    Some(conn) => {
                        let Some(nonce) = self.viewers.get(&conn).map(|v| v.nonce) else {
                            return Ok(());
                        };
                        let frame = self
                            .sealer
                            .seal_join(&nonce, cols, rows, &data)
                            .map_err(|e| e.to_string())?;
                        self.send(&HostMessage::Join { to: conn, frame }).await?;
                    }
                }
            }
            HostCommand::Grant { conn, key } => self.grant(conn, key).await?,
            HostCommand::Revoke(conn) => {
                if let Some(viewer) = self.viewers.get_mut(&conn) {
                    viewer.input = None;
                    self.send(&HostMessage::Revoke { to: conn }).await?;
                }
            }
            HostCommand::Kick(conn) => {
                if self.viewers.remove(&conn).is_some() {
                    self.send(&HostMessage::Kick { to: conn }).await?;
                }
            }
            HostCommand::Reannounce { key, epoch } => {
                let announcement = announcement(&key, &self.team, epoch, &self.id, &self.meta)
                    .map_err(|e| e.to_string())?;
                if let Err(e) = self.update_announcement(&announcement).await {
                    tracing::warn!(error = %e, "no se pudo renovar el anuncio de la sesión");
                }
            }
        }
        Ok(())
    }

    async fn update_announcement(
        &mut self,
        announcement: &LiveAnnouncement,
    ) -> Result<(), SyncError> {
        let (team, id) = (&self.team, &self.id);
        call!(&mut self.session, |api, token| api.update_live(
            token,
            team,
            id,
            announcement
        ))
    }

    async fn grant(&mut self, conn: ConnId, key: PublicKey) -> Outcome {
        if !self.viewers.contains_key(&conn) {
            return Ok(());
        }
        self.grants += 1;
        let grant = self.grants;
        let context = ControlContext {
            session: &self.id,
            grant,
        };
        let control = ControlKey::generate();
        let wrapped =
            wrap_control_key(&control, context, &self.keypair, &key).map_err(|e| e.to_string())?;
        let opener = InputOpener::new(&control, context);
        if let Some(viewer) = self.viewers.get_mut(&conn) {
            viewer.input = Some((grant, opener));
        }
        self.send(&HostMessage::Grant {
            to: conn,
            grant,
            key: wrapped,
        })
        .await
    }

    async fn event(&mut self, text: &str) -> Outcome {
        let Ok(event) = serde_json::from_str::<HostEvent>(text) else {
            return Err("el servidor mandó un mensaje no válido".into());
        };
        let update = match event {
            HostEvent::Joined { conn, email, nonce } => {
                let Some(nonce) = JoinNonce::from_base64(&nonce) else {
                    return Err("el servidor mandó un número de llegada no válido".into());
                };
                self.viewers.insert(conn, Watcher { nonce, input: None });
                HostUpdate::Joined { conn, email }
            }
            HostEvent::Left { conn } => {
                self.viewers.remove(&conn);
                HostUpdate::Left { conn }
            }
            HostEvent::Request { conn } => HostUpdate::ControlRequested { conn },
            HostEvent::Input { conn, frame } => {
                let Some(viewer) = self.viewers.get_mut(&conn) else {
                    return Ok(());
                };
                let Some((_, opener)) = viewer.input.as_mut() else {
                    return Ok(());
                };
                match opener.open(&frame) {
                    Ok(data) => HostUpdate::Input { conn, data },
                    Err(e) => {
                        tracing::warn!(error = %e, conn, "entrada de una sesión compartida rechazada");
                        viewer.input = None;
                        self.send(&HostMessage::Revoke { to: conn }).await?;
                        HostUpdate::ControlLost { conn }
                    }
                }
            }
        };
        let _ = self.updates.send(update);
        Ok(())
    }
}

/// Motivo de cierre: `Ok` si la sesión terminó con normalidad.
fn closed(code: CloseCode, reason: String) -> Outcome {
    if code == CloseCode::Normal {
        Ok(())
    } else if reason.is_empty() {
        Err(format!("el servidor cerró la sesión ({code})"))
    } else {
        Err(reason)
    }
}

/// Lo que la aplicación pide a la tarea de una sesión que se mira.
enum ViewerCommand {
    RequestControl,
}

/// Cambios en una sesión que se mira, aparte de lo que muestra la terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerUpdate {
    /// Quien comparte dio (`true`) o quitó (`false`) el control.
    Control(bool),
}

/// Una sesión compartida que se está mirando.
pub struct LiveViewer {
    commands: mpsc::UnboundedSender<ViewerCommand>,
    updates: mpsc::UnboundedReceiver<ViewerUpdate>,
}

impl LiveViewer {
    pub fn request_control(&self) {
        let _ = self.commands.send(ViewerCommand::RequestControl);
    }

    pub fn try_update(&mut self) -> Option<ViewerUpdate> {
        self.updates.try_recv().ok()
    }

    pub async fn next_update(&mut self) -> Option<ViewerUpdate> {
        self.updates.recv().await
    }
}

/// Empieza a mirar una sesión. Devuelve el [`SessionIo`] de la terminal: lo que se
/// escribe solo llega a quien comparte con el control. La salida tiene que pasar por el
/// emulador y sus respuestas automáticas no deben enviarse: ya las da la terminal de
/// quien comparte.
pub async fn watch(
    local: &SyncLocal,
    listing: &LiveListing,
) -> Result<(SyncLocal, LiveViewer, SessionIo), SyncError> {
    let keypair = keypair(local)?.clone();
    let meta = listing.meta.clone().ok_or(SyncError::StaleKey)?;
    if let Some(KeyStatus::Changed) = listing.owner_key {
        return Err(KeyProblem::Changed(listing.owner.clone()).into());
    }
    let nonce = JoinNonce::generate();
    let mut session = Session::new(local)?;
    let socket = call!(&mut session, |api, token| api.connect_live(
        token,
        &listing.team,
        &listing.id,
        LiveRole::Watch(nonce)
    ))?;
    let (io, backend) = session_pair();
    let (commands_tx, commands) = mpsc::unbounded_channel();
    let (updates_tx, updates) = mpsc::unbounded_channel();
    let (sink, stream) = socket.split();
    let task = ViewerTask {
        sink,
        id: listing.id.clone(),
        opener: OutputOpener::new(&meta.key, &listing.id, &nonce),
        meta,
        keypair,
        control: None,
        backend,
        updates: updates_tx,
    };
    tokio::spawn(task.run(stream, commands));
    let viewer = LiveViewer {
        commands: commands_tx,
        updates,
    };
    Ok((with_token(&session, local), viewer, io))
}

struct ViewerTask {
    sink: Sink,
    id: String,
    meta: LiveMeta,
    keypair: AccountKeypair,
    opener: OutputOpener,
    control: Option<InputSealer>,
    backend: BackendIo,
    updates: mpsc::UnboundedSender<ViewerUpdate>,
}

impl ViewerTask {
    async fn run(
        mut self,
        mut stream: Stream,
        mut commands: mpsc::UnboundedReceiver<ViewerCommand>,
    ) {
        let outcome: Outcome = loop {
            tokio::select! {
                input = self.backend.input.recv() => match input {
                    Some(SessionInput::Data(bytes)) => {
                        if let Err(e) = self.typed(&bytes).await {
                            break Err(e);
                        }
                    }
                    Some(SessionInput::Resize { .. }) => {}
                    Some(SessionInput::Close) | None => {
                        let _ = self.sink.close().await;
                        break Ok(());
                    }
                },
                command = commands.recv() => match command {
                    Some(ViewerCommand::RequestControl) => {
                        if let Err(e) = self.send(&ViewerMessage::Request).await {
                            break Err(e);
                        }
                    }
                    None => {
                        let _ = self.sink.close().await;
                        break Ok(());
                    }
                },
                message = stream.next() => match message {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = self.event(&text) {
                            let _ = self.sink.close().await;
                            break Err(e);
                        }
                    }
                    Some(Ok(Message::Close { code, reason })) => break closed(code, reason),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break Err(crate::api::live_error(e).to_string()),
                    None => break Err("se perdió la conexión con el servidor".into()),
                },
            }
        };
        let end = match outcome {
            Ok(()) => SessionOutput::Closed { exit_status: None },
            Err(reason) => SessionOutput::Error(reason),
        };
        let _ = self.backend.output.send(end);
    }

    async fn send(&mut self, message: &ViewerMessage) -> Outcome {
        self.sink
            .send(to_message(message))
            .await
            .map_err(|e| crate::api::live_error(e).to_string())
    }

    /// Sin el control, lo que se escribe no sale del equipo.
    async fn typed(&mut self, bytes: &[u8]) -> Outcome {
        let Some(sealer) = self.control.as_mut() else {
            return Ok(());
        };
        let frames = bytes
            .chunks(MAX_INPUT)
            .map(|chunk| sealer.seal(chunk))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        for frame in frames {
            self.send(&ViewerMessage::Input { frame }).await?;
        }
        Ok(())
    }

    fn show(&self, frame: LiveFrame) {
        let output = &self.backend.output;
        match frame {
            LiveFrame::Output(data) => {
                let _ = output.send(SessionOutput::Data(data));
            }
            LiveFrame::Resize { cols, rows } => {
                let _ = output.send(SessionOutput::Resize { cols, rows });
            }
            LiveFrame::Snapshot { cols, rows, data } => {
                let _ = output.send(SessionOutput::Resize { cols, rows });
                let _ = output.send(SessionOutput::Data([RESET, &data].concat()));
            }
        }
    }

    fn event(&mut self, text: &str) -> Outcome {
        let Ok(event) = serde_json::from_str::<ViewerEvent>(text) else {
            return Err("el servidor mandó un mensaje no válido".into());
        };
        match event {
            ViewerEvent::Output { frame } => {
                let frame = self.opener.open(&frame).map_err(|e| e.to_string())?;
                if let Some(frame) = frame {
                    self.show(frame);
                }
            }
            ViewerEvent::Join { frame } => {
                let frame = self.opener.open_join(&frame).map_err(|e| e.to_string())?;
                self.show(frame);
            }
            ViewerEvent::Grant { grant, key } => {
                let context = ControlContext {
                    session: &self.id,
                    grant,
                };
                match unwrap_control_key(&key, context, &self.keypair, &self.meta.host) {
                    Ok(control) => {
                        self.control = Some(InputSealer::new(&control, context));
                        let _ = self.updates.send(ViewerUpdate::Control(true));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "clave de control de una sesión compartida no válida");
                    }
                }
            }
            ViewerEvent::Revoke => {
                self.control = None;
                let _ = self.updates.send(ViewerUpdate::Control(false));
            }
        }
        Ok(())
    }
}
