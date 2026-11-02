//! Grabar las sesiones con los hosts de los Teams que lo piden (ver
//! `tunel_core::sync::recording`). La terminal pasa su salida al grabador, que la sube en
//! trozos desde una tarea aparte; la sesión nunca espera a la red.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, watch};
use tunel_core::HostId;
use tunel_core::sync::SyncLocal;
use tunel_core::sync::recording::RecordingEvent;
use tunel_core::vault::VaultData;
use tunel_sync::SyncError;
use tunel_sync::recording::Uploader;

/// Salida por trozo como mucho; se sube al llegar o cada `FLUSH_EVERY`.
const CHUNK_BYTES: usize = 512 * 1024;
const FLUSH_EVERY: Duration = Duration::from_secs(10);
/// Lo que espera en memoria sin poder subirse; más, y se deja de grabar.
const MAX_BUFFERED: usize = 32 * 1024 * 1024;
/// Fallos seguidos que se aguantan antes de dejar la grabación: al cerrar la sesión, o
/// con un conflicto, que se arregla al llegar la clave nueva del Team.
const MAX_FAILURES: u32 = 5;

/// Lo que comparten el grabador y su tarea.
#[derive(Default)]
struct Shared {
    /// Bytes enviados a la tarea que aún no están en un trozo.
    queued: AtomicUsize,
    /// La grabación se interrumpió: la terminal deja de avisar y de mandar.
    stopped: AtomicBool,
}

/// El grabador de una terminal. Al soltarlo, se sube lo que quede y se cierra la grabación.
pub struct Recorder {
    tx: mpsc::UnboundedSender<RecordingEvent>,
    started: Instant,
    shared: Arc<Shared>,
    /// Para el aviso de la terminal.
    pub team_name: String,
}

impl Recorder {
    fn at_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Se está grabando: si se interrumpió, la terminal ya no lo dice.
    pub fn active(&self) -> bool {
        !self.shared.stopped.load(Ordering::Relaxed)
    }

    pub fn output(&self, data: &[u8]) {
        if !self.active() {
            return;
        }
        // Sin red, la salida no puede crecer en memoria sin límite.
        let queued = self.shared.queued.fetch_add(data.len(), Ordering::Relaxed);
        if queued + data.len() > MAX_BUFFERED {
            self.shared.stopped.store(true, Ordering::Relaxed);
            return;
        }
        let _ = self.tx.send(RecordingEvent::Output {
            at_ms: self.at_ms(),
            data: data.to_vec(),
        });
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        if self.active() {
            let _ = self.tx.send(RecordingEvent::Resize {
                at_ms: self.at_ms(),
                cols,
                rows,
            });
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// La tarea que sube una grabación; devuelve el aviso si se interrumpió.
pub type Upload = std::pin::Pin<Box<dyn Future<Output = Option<String>> + Send>>;

/// El grabador para una sesión con `host`, si es de un Team que graba, y la tarea que sube
/// los trozos. `Err` si el Team graba pero no se pudo empezar: hay que decirlo.
pub fn start(
    app: &crate::app::TunelApp,
    data: &VaultData,
    host: HostId,
    size: (u16, u16),
) -> Result<Option<(Recorder, Upload)>, String> {
    let Some(host) = data.host(host) else {
        return Ok(None);
    };
    let (Some(team), Some(local)) = (host.team.clone(), app.sync.local()) else {
        return Ok(None);
    };
    if !tunel_sync::recording::team_records(local, &team) {
        return Ok(None);
    }
    let team_name = local
        .team(&team)
        .map(|t| t.name.clone())
        .unwrap_or_default();
    let id = uuid::Uuid::new_v4().to_string();
    let label = host.display_name().to_string();
    let uploader = Uploader::start(local, &team, &id, &label, now_millis(), size)
        .map_err(|e| format!("El Team «{team_name}» graba sus sesiones, pero esta no: {e}"))?;
    let (tx, rx) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared::default());
    let recorder = Recorder {
        tx,
        started: Instant::now(),
        shared: shared.clone(),
        team_name,
    };
    let task = Task {
        rx,
        uploader,
        shared,
        latest: app.sync.watch_local(),
        host: label,
        buffer: Vec::new(),
    };
    Ok(Some((recorder, Box::pin(task.run()))))
}

/// Un fallo que no se arregla reintentando. Un conflicto sí: es la clave del Team, que
/// cambió y llega con la siguiente sincronización.
fn is_final(error: &SyncError) -> bool {
    !error.is_transient() && !matches!(error, SyncError::Conflict(_))
}

/// Los primeros eventos de `buffer` hasta `CHUNK_BYTES` de salida (al menos uno), sacados
/// de él. Una salida enorme de una vez se parte.
fn next_chunk(buffer: &mut Vec<RecordingEvent>) -> Vec<RecordingEvent> {
    let mut size = 0;
    let mut take = 0;
    for event in buffer.iter() {
        let len = match event {
            RecordingEvent::Output { data, .. } => data.len(),
            RecordingEvent::Resize { .. } => 0,
        };
        if take > 0 && size + len > CHUNK_BYTES {
            break;
        }
        size += len;
        take += 1;
    }
    let mut chunk: Vec<RecordingEvent> = buffer.drain(..take).collect();
    if let Some(RecordingEvent::Output { at_ms, data }) = chunk.last_mut()
        && data.len() > CHUNK_BYTES
    {
        let rest = data.split_off(CHUNK_BYTES);
        buffer.insert(
            0,
            RecordingEvent::Output {
                at_ms: *at_ms,
                data: rest,
            },
        );
    }
    chunk
}

struct Task {
    rx: mpsc::UnboundedReceiver<RecordingEvent>,
    uploader: Uploader,
    shared: Arc<Shared>,
    latest: watch::Receiver<Option<SyncLocal>>,
    host: String,
    buffer: Vec<RecordingEvent>,
}

impl Task {
    fn stopped(&self, why: &dyn std::fmt::Display) -> Option<String> {
        self.shared.stopped.store(true, Ordering::Relaxed);
        Some(format!(
            "La grabación de la sesión con «{}» se detuvo: {why}",
            self.host
        ))
    }

    fn take(&mut self, event: RecordingEvent) {
        if let RecordingEvent::Output { data, .. } = &event {
            self.shared.queued.fetch_sub(data.len(), Ordering::Relaxed);
        }
        self.buffer.push(event);
    }

    fn buffered(&self) -> usize {
        self.buffer
            .iter()
            .map(|e| match e {
                RecordingEvent::Output { data, .. } => data.len(),
                RecordingEvent::Resize { .. } => 0,
            })
            .sum()
    }

    /// Sube lo pendiente y lo que haya en el búfer, con `last` en el último trozo.
    async fn flush(&mut self, last: bool) -> Result<(), SyncError> {
        if let Some(local) = self.latest.borrow_and_update().as_ref() {
            self.uploader.refresh(local)?;
        }
        self.uploader.retry().await?;
        loop {
            let chunk = next_chunk(&mut self.buffer);
            let closing = last && self.buffer.is_empty();
            if chunk.is_empty() && !closing {
                return Ok(());
            }
            self.uploader.send(&chunk, closing).await?;
            if closing {
                return Ok(());
            }
        }
    }

    async fn run(mut self) -> Option<String> {
        let mut ticks = tokio::time::interval(FLUSH_EVERY);
        let mut failures = 0;
        let mut open = true;
        while open {
            tokio::select! {
                event = self.rx.recv() => match event {
                    Some(event) => {
                        self.take(event);
                        if self.buffered() < CHUNK_BYTES {
                            continue;
                        }
                    }
                    None => open = false,
                },
                _ = ticks.tick() => {}
            }
            if self.shared.stopped.load(Ordering::Relaxed) || self.buffered() > MAX_BUFFERED {
                return self.stopped(&"no se puede subir al servidor");
            }
            if !open {
                break;
            }
            match self.flush(false).await {
                Ok(()) => failures = 0,
                Err(e) if is_final(&e) => return self.stopped(&e),
                Err(e) => {
                    failures += 1;
                    tracing::info!(error = %e, "trozo de grabación pendiente");
                }
            }
        }
        // La sesión terminó: se cierra la grabación, con unos cuantos intentos.
        loop {
            match self.flush(true).await {
                Ok(()) => return None,
                Err(e) if is_final(&e) => return self.stopped(&e),
                Err(e) => {
                    failures += 1;
                    if failures >= MAX_FAILURES {
                        return self.stopped(&e);
                    }
                    tokio::time::sleep(FLUSH_EVERY * failures).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(len: usize) -> RecordingEvent {
        RecordingEvent::Output {
            at_ms: 1,
            data: vec![b'x'; len],
        }
    }

    #[test]
    fn chunks_are_cut_at_the_size_limit() {
        let mut buffer = vec![output(300 * 1024), output(300 * 1024), output(10)];
        assert_eq!(next_chunk(&mut buffer).len(), 1);
        assert_eq!(next_chunk(&mut buffer).len(), 2);
        assert!(next_chunk(&mut buffer).is_empty());
    }

    #[test]
    fn a_huge_output_is_split() {
        let mut buffer = vec![output(CHUNK_BYTES * 2 + 5)];
        let mut sizes = Vec::new();
        while !buffer.is_empty() {
            let chunk = next_chunk(&mut buffer);
            if let [RecordingEvent::Output { data, .. }] = chunk.as_slice() {
                sizes.push(data.len());
            }
        }
        assert_eq!(sizes, [CHUNK_BYTES, CHUNK_BYTES, 5]);
    }
}
