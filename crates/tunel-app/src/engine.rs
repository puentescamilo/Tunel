//! Puente entre la interfaz (hilo de egui) y las tareas asíncronas de red.

use crate::session::TerminalSession;
use anyhow::Context as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tunel_core::io::{SessionIo, SessionOutput, session_pair};
use tunel_core::{ForwardId, HostId, PortForward, Protocol, VaultData};
use tunel_ssh::forward::{self, ActiveForward};
use tunel_ssh::sftp::{RemoteEntry, SftpClient};
use tunel_ssh::shell::{self, ShellOptions};
use tunel_ssh::{ConnectContext, HostKeyLookup, Interaction, SshConnection, mosh};
use tunel_term::local::{self, CommandSpec};

/// Resultados de operaciones en segundo plano que la interfaz debe aplicar.
pub enum AppEvent {
    /// La conexión se guarda junto al cliente: si se suelta, el canal SFTP se cierra.
    SftpReady {
        tab: u64,
        connection: Arc<SshConnection>,
        client: Arc<SftpClient>,
        home: String,
    },
    SftpListing {
        tab: u64,
        path: String,
        entries: Vec<RemoteEntry>,
    },
    SftpProgress {
        tab: u64,
        label: String,
        bytes: u64,
    },
    SftpDone {
        tab: u64,
        message: String,
    },
    SftpFailed {
        tab: u64,
        error: String,
    },
    ForwardStarted {
        id: ForwardId,
        active: ActiveForward,
    },
    ForwardFailed {
        id: ForwardId,
        error: String,
    },
}

pub struct Engine {
    runtime: Runtime,
    ctx: egui::Context,
    interactions_tx: mpsc::UnboundedSender<Interaction>,
    pub interactions: mpsc::UnboundedReceiver<Interaction>,
    events_tx: mpsc::UnboundedSender<AppEvent>,
    pub events: mpsc::UnboundedReceiver<AppEvent>,
    next_id: u64,
}

fn host_key_lookup(vault: &VaultData) -> HostKeyLookup {
    let snapshot = vault.clone();
    Arc::new(move |host, port, algorithm, fingerprint| {
        snapshot.check_host_key(host, port, algorithm, fingerprint)
    })
}

impl Engine {
    pub fn new(ctx: egui::Context) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("tunel-red")
            .enable_all()
            .build()
            .context("no se pudo iniciar el runtime de red")?;
        let (interactions_tx, interactions) = mpsc::unbounded_channel();
        let (events_tx, events) = mpsc::unbounded_channel();
        Ok(Self {
            runtime,
            ctx,
            interactions_tx,
            interactions,
            events_tx,
            events,
            next_id: 1,
        })
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Reenvía la salida al hilo de la UI y pide repintar en cuanto llega algo.
    fn wake_on_output(&self, io: SessionIo) -> SessionIo {
        let SessionIo { input, mut output } = io;
        let (tx, rx) = mpsc::unbounded_channel();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            while let Some(msg) = output.recv().await {
                if tx.send(msg).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        SessionIo { input, output: rx }
    }

    fn connect_context(&self, vault: &VaultData) -> ConnectContext {
        let seconds = vault.settings.keepalive_seconds;
        ConnectContext {
            lookup: host_key_lookup(vault),
            interactions: self.interactions_tx.clone(),
            keepalive: (seconds > 0).then(|| Duration::from_secs(u64::from(seconds))),
            security_key: None,
        }
    }

    fn connect_task(
        &self,
        vault: &VaultData,
        host: HostId,
    ) -> anyhow::Result<impl Future<Output = Result<SshConnection, tunel_ssh::SshError>> + use<>>
    {
        let target = vault.resolve(host)?;
        let jumps = vault.resolve_jump_chain(host)?;
        let ctx = self.connect_context(vault);
        let ui = self.ctx.clone();
        Ok(async move {
            let result = SshConnection::connect(&ctx, &jumps, &target).await;
            ui.request_repaint();
            result
        })
    }

    pub fn open_host(
        &mut self,
        vault: &VaultData,
        host_id: HostId,
        cols: u16,
        rows: u16,
    ) -> anyhow::Result<TerminalSession> {
        let host = vault.host(host_id).context("host no encontrado")?.clone();
        let (io, backend) = session_pair();
        let scrollback = vault.settings.scrollback_lines;
        let title = host.display_name().to_string();
        match host.protocol() {
            Protocol::Ssh => {
                let connect = self.connect_task(vault, host_id)?;
                let options = ShellOptions {
                    cols,
                    rows,
                    env: host.env.clone(),
                    agent_forwarding: host.agent_forwarding,
                    x11_display: host.x11_forwarding.then(tunel_ssh::x11::default_display),
                    startup_script: host
                        .startup_snippet
                        .and_then(|s| vault.snippet(s))
                        .map(|s| s.script.clone()),
                };
                let output = backend.output.clone();
                self.runtime.spawn(async move {
                    let result = match connect.await {
                        Ok(conn) => shell::run_shell(&conn, options, backend).await,
                        Err(e) => Err(e),
                    };
                    if let Err(e) = result {
                        let _ = output.send(SessionOutput::Error(e.to_string()));
                    }
                });
            }
            Protocol::Mosh { server_command } => {
                let connect = self.connect_task(vault, host_id)?;
                let address = host.address.clone();
                let output = backend.output.clone();
                self.runtime.spawn(async move {
                    let result: anyhow::Result<()> = async {
                        let conn = connect.await?;
                        let server = mosh::start_server(
                            &conn,
                            &address,
                            server_command.as_deref(),
                            tunel_core::DEFAULT_MOSH_PORTS,
                        )
                        .await?;
                        conn.disconnect().await;
                        let spec = CommandSpec::mosh_client(&server.ip, server.port, &server.key);
                        local::spawn(&spec, cols, rows, backend)?;
                        Ok(())
                    }
                    .await;
                    if let Err(e) = result {
                        let _ = output.send(SessionOutput::Error(format!("Mosh: {e:#}")));
                    }
                });
            }
            Protocol::Telnet => {
                let (address, port) = (host.address.clone(), host.effective_port());
                self.runtime.spawn(async move {
                    let output = backend.output.clone();
                    if let Err(e) =
                        tunel_term::telnet::run(&address, port, cols, rows, backend).await
                    {
                        let _ = output.send(SessionOutput::Error(format!("Telnet: {e}")));
                    }
                });
            }
            Protocol::Serial { device, baud_rate } => {
                let output = backend.output.clone();
                if let Err(e) = tunel_term::serial::spawn(&device, baud_rate, backend) {
                    let _ = output.send(SessionOutput::Error(e.to_string()));
                }
            }
        }
        Ok(TerminalSession::new(
            title,
            Some(host_id),
            cols,
            rows,
            scrollback,
            self.wake_on_output(io),
        ))
    }

    pub fn open_local(
        &mut self,
        cols: u16,
        rows: u16,
        scrollback: usize,
    ) -> anyhow::Result<TerminalSession> {
        let (io, backend) = session_pair();
        local::spawn(&CommandSpec::default_shell(), cols, rows, backend)?;
        Ok(TerminalSession::new(
            "Local".into(),
            None,
            cols,
            rows,
            scrollback,
            self.wake_on_output(io),
        ))
    }

    pub fn open_sftp(&mut self, vault: &VaultData, host: HostId) -> anyhow::Result<u64> {
        let connect = self.connect_task(vault, host)?;
        let tab = self.next_id();
        let events = self.events_tx.clone();
        self.runtime.spawn(async move {
            let result: anyhow::Result<(Arc<SshConnection>, Arc<SftpClient>, String)> = async {
                let connection = Arc::new(connect.await?);
                let client = Arc::new(SftpClient::open(&connection).await?);
                let home = client.home().await?;
                Ok((connection, client, home))
            }
            .await;
            let _ = match result {
                Ok((connection, client, home)) => events.send(AppEvent::SftpReady {
                    tab,
                    connection,
                    client,
                    home,
                }),
                Err(e) => events.send(AppEvent::SftpFailed {
                    tab,
                    error: format!("{e:#}"),
                }),
            };
        });
        Ok(tab)
    }

    pub fn sftp_list(&self, tab: u64, client: Arc<SftpClient>, path: String) {
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            let _ = match client.list(&path).await {
                Ok(entries) => events.send(AppEvent::SftpListing { tab, path, entries }),
                Err(e) => events.send(AppEvent::SftpFailed {
                    tab,
                    error: e.to_string(),
                }),
            };
            ctx.request_repaint();
        });
    }

    /// Ejecuta una operación SFTP y notifica el resultado; luego refresca `refresh`.
    pub fn sftp_run<F, Fut>(
        &self,
        tab: u64,
        client: Arc<SftpClient>,
        refresh: String,
        label: String,
        op: F,
    ) where
        F: FnOnce(Arc<SftpClient>, mpsc::UnboundedSender<AppEvent>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), tunel_ssh::sftp::SftpError>> + Send,
    {
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            let result = op(client.clone(), events.clone()).await;
            let _ = match result {
                Ok(()) => events.send(AppEvent::SftpDone {
                    tab,
                    message: format!("{label}: listo"),
                }),
                Err(e) => events.send(AppEvent::SftpFailed {
                    tab,
                    error: format!("{label}: {e}"),
                }),
            };
            if let Ok(entries) = client.list(&refresh).await {
                let _ = events.send(AppEvent::SftpListing {
                    tab,
                    path: refresh,
                    entries,
                });
            }
            ctx.request_repaint();
        });
    }

    pub fn start_forward(&self, vault: &VaultData, rule: PortForward) -> anyhow::Result<()> {
        let connect = self.connect_task(vault, rule.host)?;
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            let id = rule.id;
            let result: anyhow::Result<ActiveForward> = async {
                let conn = Arc::new(connect.await?);
                Ok(forward::start(conn, rule).await?)
            }
            .await;
            let _ = match result {
                Ok(active) => events.send(AppEvent::ForwardStarted { id, active }),
                Err(e) => events.send(AppEvent::ForwardFailed {
                    id,
                    error: format!("{e:#}"),
                }),
            };
            ctx.request_repaint();
        });
        Ok(())
    }

    pub fn stop_forward(&self, active: ActiveForward) {
        self.runtime.spawn(async move { active.stop().await });
    }
}
