//! Una pestaña de terminal: emulador + canales hacia su backend.

use crate::live::{Live, Watcher};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use tunel_core::HostId;
use tunel_core::io::{SessionInput, SessionIo, SessionOutput};
use tunel_sync::live::{HostUpdate, ViewerUpdate};
use tunel_term::{Emulator, TermEvent};

/// Límite de bytes procesados por fotograma para que la UI siga respondiendo ante salidas enormes.
const MAX_BYTES_PER_FRAME: usize = 512 * 1024;

/// Identificador de cada pestaña de terminal; los índices cambian al cerrar pestañas.
static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Connecting,
    Connected,
    Closed(Option<u32>),
    Failed(String),
}

pub struct TerminalSession {
    pub key: u64,
    pub title: String,
    pub host: Option<HostId>,
    pub emulator: Emulator,
    pub status: SessionStatus,
    pub bell: bool,
    /// La pestaña acaba de abrirse y debe recibir el foco del teclado.
    pub wants_focus: bool,
    io: SessionIo,
    log: Option<std::fs::File>,
    /// Texto que el servidor pidió copiar (OSC 52); espera a que el usuario lo permita.
    pending_clipboard: Option<String>,
    /// Compartida con un Team, o una sesión de otra persona que se está mirando.
    pub live: Option<Live>,
    /// Avisos para la interfaz (llegadas, control, fin de la sesión compartida).
    notices: Vec<String>,
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
            key: NEXT_KEY.fetch_add(1, Ordering::Relaxed),
            title,
            host,
            emulator: Emulator::new(cols, rows, scrollback),
            status: SessionStatus::Connecting,
            bell: false,
            wants_focus: true,
            io,
            log: None,
            pending_clipboard: None,
            live: None,
            notices: Vec::new(),
        }
    }

    /// Se mira la sesión de otra persona: el tamaño y las respuestas son cosa suya.
    pub fn is_watching(&self) -> bool {
        matches!(self.live, Some(Live::Viewer(_)))
    }

    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
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
                    if let Some(Live::Host(share)) = &self.live {
                        share.host.output(&bytes);
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
                SessionOutput::Resize { cols, rows } => {
                    self.emulator.resize(cols, rows);
                }
            }
        }
        self.pump_live() || changed
    }

    /// Atiende la sesión compartida; devuelve `true` si cambió algo visible.
    fn pump_live(&mut self) -> bool {
        let Some(live) = self.live.as_mut() else {
            return false;
        };
        let mut changed = false;
        let mut typed = Vec::new();
        let mut ended = None;
        match live {
            Live::Host(share) => {
                while let Some(update) = share.host.try_update() {
                    changed = true;
                    match update {
                        HostUpdate::Joined { conn, email } => {
                            let (cols, rows) = self.emulator.size();
                            share
                                .host
                                .welcome(conn, cols, rows, self.emulator.snapshot());
                            self.notices
                                .push(format!("{email} está mirando «{}»", self.title));
                            share.viewers.insert(
                                conn,
                                Watcher {
                                    email,
                                    control: false,
                                },
                            );
                        }
                        HostUpdate::Left { conn } => share.forget(conn),
                        HostUpdate::ControlRequested { conn } => {
                            if share.viewers.contains_key(&conn) && !share.requests.contains(&conn)
                            {
                                share.requests.push(conn);
                            }
                        }
                        HostUpdate::Input { conn, data } => {
                            if share.viewers.get(&conn).is_some_and(|v| v.control) {
                                typed.push(data);
                            }
                        }
                        HostUpdate::ControlLost { conn } => {
                            if let Some(viewer) = share.viewers.get_mut(&conn) {
                                viewer.control = false;
                                self.notices.push(format!(
                                    "{} perdió el control: llegó entrada dañada o incompleta",
                                    viewer.email
                                ));
                            }
                        }
                        HostUpdate::Ended(reason) => ended = Some(reason),
                    }
                }
                if share.host.needs_resync() {
                    let (cols, rows) = self.emulator.size();
                    share.host.resync(cols, rows, self.emulator.snapshot());
                }
            }
            Live::Viewer(watching) => {
                while let Some(ViewerUpdate::Control(control)) = watching.viewer.try_update() {
                    changed = true;
                    watching.control = control;
                    watching.requested = false;
                    self.notices.push(if control {
                        format!("Tienes el control de «{}»", self.title)
                    } else {
                        format!("Ya no tienes el control de «{}»", self.title)
                    });
                }
            }
        }
        for data in typed {
            self.send(data);
        }
        if let Some(reason) = ended {
            self.live = None;
            self.notices.push(match reason {
                Some(reason) => format!("Se dejó de compartir «{}»: {reason}", self.title),
                None => format!("Se dejó de compartir «{}»", self.title),
            });
        }
        changed
    }

    fn handle_event(&mut self, event: TermEvent) {
        match event {
            // La pestaña lleva el nombre del host (o el que le dé el usuario), no el título
            // que pone el shell, que suele ser «usuario@máquina: ruta».
            TermEvent::Title(_) => {}
            TermEvent::Bell => self.bell = true,
            // Quien comparte ya responde desde su terminal; responder también desde aquí
            // escribiría en la suya.
            TermEvent::Reply(_) if self.is_watching() => {}
            TermEvent::Reply(text) => self.send(text.into_bytes()),
            TermEvent::CopyToClipboard(text) => self.pending_clipboard = Some(text),
        }
    }

    /// Petición de copiar al portapapeles que aún no se ha respondido.
    pub fn clipboard_request(&self) -> Option<&str> {
        self.pending_clipboard.as_deref()
    }

    /// Responde a la petición pendiente; devuelve el texto solo si el usuario lo permite.
    pub fn answer_clipboard(&mut self, allow: bool) -> Option<String> {
        self.pending_clipboard.take().filter(|_| allow)
    }

    pub fn send(&self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            let _ = self.io.input.send(SessionInput::Data(bytes));
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        // Al mirar, el tamaño es el de quien comparte.
        if self.is_watching() {
            return;
        }
        if self.emulator.resize(cols, rows) {
            let _ = self.io.input.send(SessionInput::Resize { cols, rows });
            if let Some(Live::Host(share)) = &self.live {
                let (cols, rows) = self.emulator.size();
                share.host.resize(cols, rows);
            }
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
    fn shell_titles_do_not_rename_the_tab_and_errors_update_state() {
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
        assert_eq!(s.title, "t");
        assert_eq!(s.status, SessionStatus::Failed("rechazado".into()));
        assert!(!s.is_alive());
    }

    fn watching() -> (TerminalSession, tunel_core::io::BackendIo) {
        let (mut s, backend) = session();
        s.live = Some(Live::Viewer(Box::new(crate::live::Watching {
            viewer: tunel_sync::live::LiveViewer::detached(),
            owner: "ana@ejemplo.com".into(),
            team_name: "Ops".into(),
            control: false,
            requested: false,
            unverified: None,
        })));
        (s, backend)
    }

    #[test]
    fn a_watched_session_does_not_answer_terminal_queries() {
        // Las respuestas ya las da la terminal de quien comparte; repetirlas escribiría en
        // su shell.
        let (mut s, mut backend) = watching();
        backend
            .output
            .send(SessionOutput::Data(b"\x1b[6n\x1b[c".to_vec()))
            .unwrap();
        s.pump();
        assert!(backend.input.try_recv().is_err());
    }

    #[test]
    fn a_watched_session_keeps_the_size_of_the_shared_terminal() {
        let (mut s, mut backend) = watching();
        backend
            .output
            .send(SessionOutput::Resize {
                cols: 120,
                rows: 40,
            })
            .unwrap();
        s.pump();
        s.resize(80, 24);
        assert_eq!(s.emulator.size(), (120, 40));
        assert!(backend.input.try_recv().is_err());
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
    fn osc52_copy_waits_for_the_user() {
        let (mut s, backend) = session();
        let osc52 = b"\x1b]52;c;aG9sYQ==\x07".to_vec();
        backend
            .output
            .send(SessionOutput::Data(osc52.clone()))
            .unwrap();
        s.pump();
        assert_eq!(s.clipboard_request(), Some("hola"));
        assert_eq!(s.answer_clipboard(false), None);
        assert_eq!(s.clipboard_request(), None);

        backend.output.send(SessionOutput::Data(osc52)).unwrap();
        s.pump();
        assert_eq!(s.answer_clipboard(true).as_deref(), Some("hola"));
    }

    #[test]
    fn dropping_session_closes_backend() {
        let (s, mut backend) = session();
        drop(s);
        assert_eq!(backend.input.try_recv().unwrap(), SessionInput::Close);
    }
}
