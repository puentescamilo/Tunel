//! Consola por puerto serie.

use std::io::{Read, Write};
use std::time::Duration;
use tunel_core::io::{BackendIo, SessionInput, SessionOutput};

const READ_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum SerialError {
    #[error("no se pudo abrir {0}: {1}")]
    Open(String, String),
}

/// Puertos disponibles en el sistema, para el selector de la interfaz.
pub fn available_ports() -> Vec<String> {
    serialport::available_ports()
        .map(|ports| ports.into_iter().map(|p| p.port_name).collect())
        .unwrap_or_default()
}

pub fn spawn(device: &str, baud_rate: u32, io: BackendIo) -> Result<(), SerialError> {
    let port = serialport::new(device, baud_rate)
        .timeout(READ_TIMEOUT)
        .open()
        .map_err(|e| SerialError::Open(device.to_string(), e.to_string()))?;
    let mut reader = port
        .try_clone()
        .map_err(|e| SerialError::Open(device.to_string(), e.to_string()))?;
    let mut writer = port;
    let BackendIo { mut input, output } = io;
    let reader_output = output.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_stop = stop.clone();

    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while !reader_stop.load(std::sync::atomic::Ordering::Relaxed) {
            match reader.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    if reader_output
                        .send(SessionOutput::Data(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    let _ = reader_output.send(SessionOutput::Error(e.to_string()));
                    break;
                }
            }
        }
        let _ = reader_output.send(SessionOutput::Closed { exit_status: None });
    });

    std::thread::spawn(move || {
        while let Some(cmd) = input.blocking_recv() {
            match cmd {
                SessionInput::Data(bytes) => {
                    if let Err(e) = writer.write_all(&bytes) {
                        let _ = output.send(SessionOutput::Error(e.to_string()));
                        break;
                    }
                }
                SessionInput::Resize { .. } => {}
                SessionInput::Close => break,
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    Ok(())
}
