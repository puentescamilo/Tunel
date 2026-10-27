//! Una pestaña de terminal: emulador + canales hacia su backend.

use std::io::Write;
use tunel_core::HostId;
use tunel_core::io::{SessionInput, SessionIo, SessionOutput};
use tunel_term::{Emulator, TermEvent};

/// Límite de bytes procesados por fotograma para que la UI siga respondiendo ante salidas enormes.
const MAX_BYTES_PER_FRAME: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Connecting,
    Connected,
    Closed(Option<u32>),
    Failed(String),
}

pub struct TerminalSession {
    pub title: String,
    pub host: Option<HostId>,
    pub emulator: Emulator,
    pub status: SessionStatus,
    pub bell: bool,
    /// La pestaña acaba de abrirse y debe recibir el foco del teclado.
    pub wants_focus: bool,
    io: SessionIo,
    log: Option<std::fs::File>,
    pending_clipboard: Option<String>,
}

impl TerminalSession {
    pub fn new(
        title: String,
        host: Option<HostId>,
        cols: u16,
        rows: u16,
        scrollback: usize,
        io: SessionIo,
    ) -> Self {
        Self {
            title,
            host,
            emulator: Emulator::new(cols, rows, scrollback),
            status: SessionStatus::Connecting,
            bell: false,
            wants_focus: true,
            io,
            log: None,
            pending_clipboard: None,
        }
    }

    pub fn is_alive(&self) -> bool {
        matches!(
            self.status,
            SessionStatus::Connecting | SessionStatus::Connected
        )
    }

    /// Procesa la salida pendiente. Devuelve `true` si cambió algo visible.
    pub fn pump(&mut self) -> bool {
        let mut changed = false;
        let mut budget = MAX_BYTES_PER_FRAME;
        while budget > 0 {
            let Ok(msg) = self.io.output.try_recv() else {
                break;
            };
            changed = true;
            match msg {
                SessionOutput::Data(bytes) => {
                    budget = budget.saturating_sub(bytes.len());
                    if self.status == SessionStatus::Connecting {
                        self.status = SessionStatus::Connected;
                    }
                    if let Some(log) = self.log.as_mut()
                        && let Err(e) = log.write_all(&bytes)
                    {
                        tracing::warn!(error = %e, "fallo al escribir el registro de sesión; se desactiva");
                        self.log = None;
                    }
                    for event in self.emulator.feed(&bytes) {
                        self.handle_event(event);
                    }
                }
                SessionOutput::Closed { exit_status } => {
                    self.status = SessionStatus::Closed(exit_status)
                }
                SessionOutput::Error(error) => self.status = SessionStatus::Failed(error),
            }
        }
        changed
    }

    fn handle_event(&mut self, event: TermEvent) {
        match event {
            TermEvent::Title(title) if !title.trim().is_empty() => self.title = title,
            TermEvent::Title(_) => {}
            TermEvent::Bell => self.bell = true,
            TermEvent::Reply(text) => self.send(text.into_bytes()),
            TermEvent::CopyToClipboard(text) => self.pending_clipboard = Some(text),
        }
    }

    pub fn take_clipboard(&mut self) -> Option<String> {
        self.pending_clipboard.take()
    }

    pub fn send(&self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            let _ = self.io.input.send(SessionInput::Data(bytes));
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        if self.emulator.resize(cols, rows) {
            let _ = self.io.input.send(SessionInput::Resize { cols, rows });
        }
    }

    pub fn close(&self) {
        let _ = self.io.input.send(SessionInput::Close);
    }

    pub fn is_logging(&self) -> bool {
        self.log.is_some()
    }

    pub fn start_log(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        self.log = Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        );
        Ok(())
    }

    pub fn stop_log(&mut self) {
        self.log = None;
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::io::session_pair;

    fn session() -> (TerminalSession, tunel_core::io::BackendIo) {
        let (io, backend) = session_pair();
        (
            TerminalSession::new("t".into(), None, 20, 4, 100, io),
            backend,
        )
    }

    #[test]
    fn data_marks_connected_and_reaches_emulator() {
        let (mut s, backend) = session();
        backend
            .output
            .send(SessionOutput::Data(b"hola".to_vec()))
            .unwrap();
        assert!(s.pump());
        assert_eq!(s.status, SessionStatus::Connected);
        assert_eq!(
            s.emulator
                .screen(tunel_term::palette::default_theme())
                .row_text(0),
            "hola"
        );
    }

    #[test]
    fn terminal_replies_are_sent_back_to_backend() {
        let (mut s, mut backend) = session();
        backend
            .output
            .send(SessionOutput::Data(b"\x1b[6n".to_vec()))
            .unwrap();
        s.pump();
        assert_eq!(
            backend.input.try_recv().unwrap(),
            SessionInput::Data(b"\x1b[1;1R".to_vec())
        );
    }

    #[test]
    fn title_and_errors_update_state() {
        let (mut s, backend) = session();
        backend
            .output
            .send(SessionOutput::Data(b"\x1b]2;srv\x07".to_vec()))
            .unwrap();
        backend
            .output
            .send(SessionOutput::Error("rechazado".into()))
            .unwrap();
        s.pump();
        assert_eq!(s.title, "srv");
        assert_eq!(s.status, SessionStatus::Failed("rechazado".into()));
        assert!(!s.is_alive());
    }

    #[test]
    fn resize_is_forwarded_only_when_size_changes() {
        let (mut s, mut backend) = session();
        s.resize(20, 4);
        assert!(backend.input.try_recv().is_err());
        s.resize(30, 5);
        assert_eq!(
            backend.input.try_recv().unwrap(),
            SessionInput::Resize { cols: 30, rows: 5 }
        );
    }

    #[test]
    fn session_log_records_raw_output() {
        let dir = std::env::temp_dir().join(format!("tunel-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.log");
        let (mut s, backend) = session();
        s.start_log(&path).unwrap();
        backend
            .output
            .send(SessionOutput::Data(b"registro".to_vec()))
            .unwrap();
        s.pump();
        s.stop_log();
        assert_eq!(std::fs::read(&path).unwrap(), b"registro");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dropping_session_closes_backend() {
        let (s, mut backend) = session();
        drop(s);
        assert_eq!(backend.input.try_recv().unwrap(), SessionInput::Close);
    }
}
