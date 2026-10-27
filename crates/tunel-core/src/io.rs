//! Canales comunes entre cualquier backend de sesión (SSH, Telnet, serie, local) y la terminal.

use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionInput {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutput {
    Data(Vec<u8>),
    Closed { exit_status: Option<u32> },
    Error(String),
}

/// Extremo que usa la interfaz para hablar con una sesión en ejecución.
pub struct SessionIo {
    pub input: mpsc::UnboundedSender<SessionInput>,
    pub output: mpsc::UnboundedReceiver<SessionOutput>,
}

/// Extremo que usa el backend.
pub struct BackendIo {
    pub input: mpsc::UnboundedReceiver<SessionInput>,
    pub output: mpsc::UnboundedSender<SessionOutput>,
}

pub fn session_pair() -> (SessionIo, BackendIo) {
    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (output_tx, output_rx) = mpsc::unbounded_channel();
    (
        SessionIo {
            input: input_tx,
            output: output_rx,
        },
        BackendIo {
            input: input_rx,
            output: output_tx,
        },
    )
}
