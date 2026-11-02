//! Grabar las sesiones con los hosts de los Teams que lo piden (ver
//! `tunel_core::sync::recording`). La terminal pasa su salida al grabador, que la sube en
//! trozos desde una tarea aparte; la sesión nunca espera a la red.

use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tunel_core::HostId;
use tunel_core::sync::recording::RecordingEvent;
use tunel_core::vault::VaultData;
use tunel_sync::SyncError;
use tunel_sync::recording::Uploader;

/// Se sube un trozo al llegar a tantos bytes de salida, o cada `FLUSH_EVERY`.
const CHUNK_BYTES: usize = 512 * 1024;
const FLUSH_EVERY: Duration = Duration::from_secs(10);
/// Lo que se guarda en memoria sin poder subirlo; más, y se deja de grabar.
const MAX_BUFFERED: usize = 32 * 1024 * 1024;
/// Intentos de subir el último trozo al cerrar la sesión.
const FINAL_TRIES: u32 = 5;

/// El grabador de una terminal. Al soltarlo, se sube lo que quede y se cierra la grabación.
pub struct Recorder {
    tx: mpsc::UnboundedSender<RecordingEvent>,
    started: Instant,
    /// Para el aviso de la terminal.
    pub team_name: String,
}

impl Recorder {
    fn at_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn output(&self, data: &[u8]) {
        let _ = self.tx.send(RecordingEvent::Output {
            at_ms: self.at_ms(),
            data: data.to_vec(),
        });
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.tx.send(RecordingEvent::Resize {
            at_ms: self.at_ms(),
            cols,
            rows,
        });
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// El grabador para una sesión con `host`, si es de un Team que graba. La tarea que sube
/// los trozos la lanza `spawn`.
pub fn start(
    app: &crate::app::TunelApp,
    data: &VaultData,
    host: HostId,
    size: (u16, u16),
) -> Option<(
    Recorder,
    impl Future<Output = Option<String>> + Send + 'static,
)> {
    let host = data.host(host)?;
    let team = host.team.clone()?;
    let local = app.sync.local()?;
    if !tunel_sync::recording::team_records(local, &team) {
        return None;
    }
    let team_name = local.team(&team)?.name.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let label = host.display_name().to_string();
    let uploader = match Uploader::start(local, &team, &id, &label, now_millis(), size) {
        Ok(uploader) => uploader,
        Err(e) => {
            tracing::warn!(error = %e, "no se pudo empezar la grabación");
            return None;
        }
    };
    let (tx, rx) = mpsc::unbounded_channel();
    let recorder = Recorder {
        tx,
        started: Instant::now(),
        team_name,
    };
    Some((recorder, upload(rx, uploader, label)))
}

/// Un fallo que no se arregla reintentando: la grabación se deja.
fn is_final(error: &SyncError) -> bool {
    !error.is_transient()
}

/// Sube los eventos de `rx` hasta que la terminal suelta el grabador. Devuelve el aviso
/// para la interfaz si la grabación se interrumpió.
async fn upload(
    mut rx: mpsc::UnboundedReceiver<RecordingEvent>,
    mut uploader: Uploader,
    host: String,
) -> Option<String> {
    let stopped = |e: &dyn std::fmt::Display| {
        Some(format!(
            "La grabación de la sesión con «{host}» se detuvo: {e}"
        ))
    };
    let mut buffer = Vec::new();
    let mut buffered = 0;
    let mut ticks = tokio::time::interval(FLUSH_EVERY);
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => {
                    if let RecordingEvent::Output { data, .. } = &event {
                        buffered += data.len();
                    }
                    buffer.push(event);
                    if buffered > MAX_BUFFERED {
                        return stopped(&"no se puede subir al servidor");
                    }
                    if buffered < CHUNK_BYTES || uploader.has_pending() {
                        continue;
                    }
                }
                None => break,
            },
            _ = ticks.tick() => {}
        }
        let result = if uploader.has_pending() {
            uploader.retry().await
        } else if buffer.is_empty() {
            continue;
        } else {
            buffered = 0;
            uploader.send(&std::mem::take(&mut buffer), false).await
        };
        match result {
            Err(e) if is_final(&e) => return stopped(&e),
            Err(e) => tracing::info!(error = %e, "trozo de grabación pendiente"),
            Ok(()) => {}
        }
    }
    // La sesión terminó: primero lo pendiente y luego lo que quede, con el último trozo.
    let mut closed = false;
    let mut failures = 0;
    loop {
        let result = if uploader.has_pending() {
            uploader.retry().await
        } else if !closed {
            closed = true;
            uploader.send(&buffer, true).await
        } else {
            return None;
        };
        match result {
            Ok(()) => {}
            Err(e) if is_final(&e) => return stopped(&e),
            Err(e) => {
                failures += 1;
                if failures >= FINAL_TRIES {
                    return stopped(&e);
                }
                tokio::time::sleep(FLUSH_EVERY * failures).await;
            }
        }
    }
}
