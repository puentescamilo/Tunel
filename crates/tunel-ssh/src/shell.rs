//! Shell interactiva sobre un canal SSH con PTY.

use crate::client::{SshConnection, SshError};
use crate::x11::{self, X11Forwarding};
use russh::ChannelMsg;
use std::collections::BTreeMap;
use std::sync::Arc;
use tunel_core::io::{BackendIo, SessionInput, SessionOutput};

pub const TERM_NAME: &str = "xterm-256color";

pub struct ShellOptions {
    pub cols: u16,
    pub rows: u16,
    pub env: BTreeMap<String, String>,
    pub agent_forwarding: bool,
    /// `DISPLAY` local al que reenviar X11; `None` lo desactiva.
    pub x11_display: Option<String>,
    /// Script que se envía nada más abrir la shell (snippet de inicio).
    pub startup_script: Option<String>,
}

/// Abre la shell y la atiende hasta que se cierre; pensado para ejecutarse en una tarea.
pub async fn run_shell(
    conn: &SshConnection,
    options: ShellOptions,
    io: BackendIo,
) -> Result<(), SshError> {
    let BackendIo { mut input, output } = io;
    let mut channel = conn.handle().channel_open_session().await?;
    if options.agent_forwarding {
        channel.agent_forward(false).await?;
    }
    if let Some(display) = &options.x11_display {
        match X11Forwarding::for_display(display).await {
            Ok(forwarding) => {
                let forwarding = Arc::new(forwarding);
                // Antes de pedirlo, para que los canales que lleguen ya lo encuentren.
                conn.set_x11(forwarding.clone());
                channel
                    .request_x11(
                        false,
                        false,
                        x11::AUTH_PROTOCOL,
                        forwarding.fake_cookie_hex(),
                        forwarding.screen(),
                    )
                    .await?;
            }
            Err(e) => {
                let notice = format!("\x1b[33mTúnel: reenvío X11 desactivado: {e}\x1b[0m\r\n");
                let _ = output.send(SessionOutput::Data(notice.into_bytes()));
            }
        }
    }
    for (name, value) in &options.env {
        // Muchos servidores solo aceptan variables de AcceptEnv; ignorar los rechazos.
        channel.set_env(false, name.clone(), value.clone()).await?;
    }
    channel
        .request_pty(
            false,
            TERM_NAME,
            u32::from(options.cols),
            u32::from(options.rows),
            0,
            0,
            &[],
        )
        .await?;
    channel.request_shell(true).await?;
    if let Some(script) = options.startup_script.filter(|s| !s.is_empty()) {
        let script = if script.ends_with('\n') {
            script
        } else {
            format!("{script}\n")
        };
        channel.data_bytes(script.into_bytes()).await?;
    }

    let mut exit_status = None;
    loop {
        tokio::select! {
            cmd = input.recv() => match cmd {
                Some(SessionInput::Data(bytes)) => channel.data_bytes(bytes).await?,
                Some(SessionInput::Resize { cols, rows }) => {
                    channel.window_change(u32::from(cols), u32::from(rows), 0, 0).await?;
                }
                Some(SessionInput::Close) | None => {
                    let _ = channel.close().await;
                    break;
                }
            },
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if output.send(SessionOutput::Data(data.to_vec())).is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
        }
    }
    let _ = output.send(SessionOutput::Closed { exit_status });
    Ok(())
}
