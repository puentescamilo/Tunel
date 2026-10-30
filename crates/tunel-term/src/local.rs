//! Terminal local (PTY del sistema) y procesos externos como `mosh-client`.

use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use tunel_core::io::{BackendIo, SessionInput, SessionOutput};

const READ_BUFFER: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error("no se pudo crear la PTY: {0}")]
    Pty(String),
    #[error("no se pudo iniciar {0}: {1}")]
    Spawn(String, String),
}

/// Programa a ejecutar; `None` en `program` abre la shell por defecto del usuario.
#[derive(Debug, Clone, Default)]
pub struct CommandSpec {
    pub program: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<std::path::PathBuf>,
}

impl CommandSpec {
    pub fn default_shell() -> Self {
        Self::default()
    }

    /// `mosh-client` del sistema con la clave de la sesión en el entorno, como hace `mosh`.
    pub fn mosh_client(ip: &str, port: u16, key: &str) -> Self {
        Self {
            program: Some("mosh-client".into()),
            args: vec![ip.into(), port.to_string()],
            env: vec![("MOSH_KEY".into(), key.into())],
            cwd: None,
        }
    }

    fn builder(&self) -> CommandBuilder {
        let mut cmd = match &self.program {
            Some(program) => {
                let mut c = CommandBuilder::new(program);
                c.args(&self.args);
                c
            }
            None => CommandBuilder::new_default_prog(),
        };
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        if let Some(dir) = self.cwd.clone().or_else(home_dir) {
            cmd.cwd(dir);
        }
        cmd
    }

    fn describe(&self) -> String {
        self.program.clone().unwrap_or_else(|| "la shell".into())
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(Into::into)
}

fn pty_size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// Lanza el programa en una PTY y conecta sus flujos con `io` usando hilos dedicados.
pub fn spawn(spec: &CommandSpec, cols: u16, rows: u16, io: BackendIo) -> Result<(), LocalError> {
    let pair = native_pty_system()
        .openpty(pty_size(cols, rows))
        .map_err(|e| LocalError::Pty(e.to_string()))?;
    let mut child = pair
        .slave
        .spawn_command(spec.builder())
        .map_err(|e| LocalError::Spawn(spec.describe(), e.to_string()))?;
    drop(pair.slave);
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| LocalError::Pty(e.to_string()))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| LocalError::Pty(e.to_string()))?;
    let BackendIo { input, output } = io;

    let reader_output = output.clone();
    std::thread::Builder::new()
        .name("tunel-pty-lectura".into())
        .spawn(move || {
            let mut buf = vec![0u8; READ_BUFFER];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if reader_output
                            .send(SessionOutput::Data(buf[..n].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let status = child.wait().ok().map(|s| s.exit_code());
            let _ = reader_output.send(SessionOutput::Closed {
                exit_status: status,
            });
        })
        .map_err(|e| LocalError::Pty(e.to_string()))?;

    std::thread::Builder::new()
        .name("tunel-pty-escritura".into())
        .spawn(move || write_loop(input, writer, pair.master, output))
        .map_err(|e| LocalError::Pty(e.to_string()))?;
    Ok(())
}

fn write_loop(
    mut input: tokio::sync::mpsc::UnboundedReceiver<SessionInput>,
    mut writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    output: tokio::sync::mpsc::UnboundedSender<SessionOutput>,
) {
    while let Some(cmd) = input.blocking_recv() {
        match cmd {
            SessionInput::Data(bytes) => {
                if let Err(e) = writer.write_all(&bytes).and_then(|_| writer.flush()) {
                    let _ = output.send(SessionOutput::Error(e.to_string()));
                    break;
                }
            }
            SessionInput::Resize { cols, rows } => {
                if let Err(e) = master.resize(pty_size(cols, rows)) {
                    tracing::debug!(error = %e, "no se pudo redimensionar la PTY");
                }
            }
            SessionInput::Close => break,
        }
    }
    // Al soltar el maestro la PTY se cierra y el proceso recibe SIGHUP.
    drop(writer);
    drop(master);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tunel_core::io::session_pair;

    #[test]
    fn spawned_command_output_reaches_session() {
        let (mut session, backend) = session_pair();
        let spec = CommandSpec {
            program: Some("/bin/echo".into()),
            args: vec!["tunel-ok".into()],
            ..CommandSpec::default()
        };
        spawn(&spec, 80, 24, backend).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut collected = Vec::new();
        let mut closed = false;
        while Instant::now() < deadline && !closed {
            match session.output.try_recv() {
                Ok(SessionOutput::Data(d)) => collected.extend(d),
                Ok(SessionOutput::Closed { .. }) => closed = true,
                Ok(SessionOutput::Error(e)) => panic!("{e}"),
                Ok(SessionOutput::Resize { .. }) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        assert!(String::from_utf8_lossy(&collected).contains("tunel-ok"));
        assert!(closed);
        let _ = session.input.send(SessionInput::Close);
    }

    #[test]
    fn mosh_spec_passes_key_through_environment_not_arguments() {
        let spec = CommandSpec::mosh_client("10.0.0.1", 60001, "clave");
        assert_eq!(spec.args, vec!["10.0.0.1", "60001"]);
        assert!(spec.env.contains(&("MOSH_KEY".into(), "clave".into())));
    }

    #[test]
    fn missing_program_reports_spawn_error() {
        let (_session, backend) = session_pair();
        let spec = CommandSpec {
            program: Some("/no/existe/tunel".into()),
            ..CommandSpec::default()
        };
        assert!(matches!(
            spawn(&spec, 80, 24, backend),
            Err(LocalError::Spawn(..))
        ));
    }
}
