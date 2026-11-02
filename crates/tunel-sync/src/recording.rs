//! Grabaciones de sesiones de los Teams (ver `tunel_core::sync::recording`): subirlas
//! mientras se graban y, para los admins, listarlas, abrirlas y borrarlas.

use crate::SyncError;
use crate::audit::{Trust, keys_by_epoch, signer_key};
use crate::session::{Session, call};
use tunel_core::sync::audit::clean_name;
use tunel_core::sync::local::normalize_email;
use tunel_core::sync::protocol::{RecordingChunk, RecordingDownload, RecordingSummary};
use tunel_core::sync::recording::{
    ChunkWriter, OpenedChunk, RecordingEvent, RecordingHeader, SignedChunk,
};
use tunel_core::sync::{AccountKeypair, SyncLocal, TeamLocal};

/// El Team graba las sesiones con sus hosts, según su lista de miembros.
pub fn team_records(local: &SyncLocal, team: &str) -> bool {
    local
        .team(team)
        .and_then(|t| t.roster.as_ref())
        .is_some_and(|r| r.record_sessions)
}

/// Sube una grabación trozo a trozo. Un trozo que no llegó se reintenta tal cual antes de
/// hacer el siguiente, así el servidor los recibe en orden.
pub struct Uploader {
    session: Session,
    pair: AccountKeypair,
    team: TeamLocal,
    id: String,
    writer: ChunkWriter,
    /// El trozo hecho que falta por subir, ya cifrado: un reintento manda exactamente lo
    /// mismo, y el servidor lo reconoce si ya le había llegado.
    pending: Option<(SignedChunk, RecordingChunk)>,
}

impl Uploader {
    /// Empieza la grabación `id` de una sesión con `host` en `team`.
    pub fn start(
        local: &SyncLocal,
        team: &str,
        id: &str,
        host: &str,
        started_at: u64,
        (cols, rows): (u16, u16),
    ) -> Result<Self, SyncError> {
        let team = local
            .team(team)
            .cloned()
            .ok_or_else(|| SyncError::NotFound(team.into()))?;
        let pair = local.keypair.clone().ok_or(SyncError::NoKeypair)?;
        let header = RecordingHeader {
            host: clean_name(host),
            actor: normalize_email(&local.email),
            started_at,
            cols,
            rows,
        };
        Ok(Self {
            session: Session::new(local)?,
            writer: ChunkWriter::new(&team.id, id, header),
            pair,
            team,
            id: id.to_string(),
            pending: None,
        })
    }

    /// Hay un trozo hecho que aún no llegó al servidor.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Adopta la clave nueva del Team si `local` la trae, para que lo que se grabe desde
    /// ahora no vaya con la que tiene quien salió.
    pub fn refresh(&mut self, local: &SyncLocal) -> Result<(), SyncError> {
        let Some(team) = local
            .team(&self.team.id)
            .filter(|t| t.epoch > self.team.epoch)
        else {
            return Ok(());
        };
        self.team = team.clone();
        if let Some((signed, _)) = self.pending.take() {
            self.pending = Some(self.sealed(signed)?);
        }
        Ok(())
    }

    fn sealed(&self, signed: SignedChunk) -> Result<(SignedChunk, RecordingChunk), SyncError> {
        let upload = RecordingChunk {
            seq: signed.seq,
            epoch: self.team.epoch,
            last: signed.last,
            blob: signed.seal(&self.team.key, self.team.epoch)?,
        };
        Ok((signed, upload))
    }

    /// Sube el trozo pendiente, si lo hay, y luego uno nuevo con `events`. Si falla, el
    /// trozo queda pendiente y `events` ya va en él: no hay que volver a pasarlos.
    pub async fn send(&mut self, events: &[RecordingEvent], last: bool) -> Result<(), SyncError> {
        self.retry().await?;
        let signed = self.writer.next(events, last, &self.pair)?;
        self.pending = Some(self.sealed(signed)?);
        self.retry().await
    }

    /// Vuelve a intentar el trozo pendiente.
    pub async fn retry(&mut self) -> Result<(), SyncError> {
        let Some((_, upload)) = &self.pending else {
            return Ok(());
        };
        let (team, id, upload) = (&self.team.id, &self.id, upload.clone());
        call!(&mut self.session, |api, token| api
            .add_recording_chunk(token, team, id, &upload))?;
        self.pending = None;
        Ok(())
    }
}

/// Las grabaciones de `team`, de la más reciente a la más vieja. Solo para admins.
pub async fn list(local: &SyncLocal, team: &str) -> Result<Vec<RecordingSummary>, SyncError> {
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api.recordings(token, team))
}

pub async fn delete(local: &SyncLocal, team: &str, id: &str) -> Result<(), SyncError> {
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api
        .delete_recording(token, team, id))
}

/// Una grabación abierta, hasta donde se pudo comprobar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// `None` si ni el primer trozo se pudo leer.
    pub header: Option<RecordingHeader>,
    pub events: Vec<RecordingEvent>,
    /// Llegó el último trozo: la sesión terminó y no falta nada.
    pub complete: bool,
    pub trust: Trust,
    /// Por qué se dejó de leer antes del final, si pasó.
    pub problem: Option<String>,
}

/// Lo que se abre de una grabación como mucho, en bytes de salida más un poco por evento:
/// una grabación hecha a propósito para no caber en memoria se corta aquí.
const MAX_OPENED_BYTES: usize = 256 * 1024 * 1024;
const EVENT_OVERHEAD: usize = 32;

fn event_size(event: &RecordingEvent) -> usize {
    EVENT_OVERHEAD
        + match event {
            RecordingEvent::Output { data, .. } => data.len(),
            RecordingEvent::Resize { .. } => 0,
        }
}

fn assemble(
    local: &SyncLocal,
    team: &TeamLocal,
    id: &str,
    author: &str,
    download: &RecordingDownload,
) -> Recording {
    let keys = keys_by_epoch(team, &download.previous_keys);
    let mut recording = Recording {
        header: None,
        events: Vec::new(),
        complete: false,
        trust: Trust::Unknown,
        problem: None,
    };
    let mut previous: Option<OpenedChunk> = None;
    let mut signer = None;
    let mut opened_bytes = 0;
    for (index, chunk) in download.chunks.iter().enumerate() {
        let opened = if recording.complete {
            Err("hay trozos después del último")
        } else if chunk.seq != index as u64 {
            Err("faltan trozos de la grabación")
        } else if let Some(key) = keys.get(&chunk.epoch) {
            OpenedChunk::open(&chunk.blob, key, &team.id, id, chunk.seq, chunk.epoch)
                .map_err(|_| "un trozo está dañado o no es de esta grabación")
        } else {
            Err("un trozo está cifrado con una clave que este equipo no tiene")
        };
        let mut opened = match opened {
            Ok(o) if o.follows(previous.as_ref()) => o,
            Ok(_) => {
                recording.problem = Some("los trozos no siguen el orden en que se grabaron".into());
                break;
            }
            Err(e) => {
                recording.problem = Some(e.into());
                break;
            }
        };
        if let Some(header) = &opened.header {
            let actor = clean_name(&normalize_email(&header.actor));
            signer = signer_key(local, team, &actor);
            recording.trust = match signer {
                _ if actor != normalize_email(author) => Trust::Forged,
                Some(_) => Trust::Verified,
                None => Trust::Unknown,
            };
            recording.header = Some(RecordingHeader {
                host: clean_name(&header.host),
                actor,
                ..header.clone()
            });
        }
        if signer.is_some_and(|key| !opened.signed_by(&key)) {
            recording.trust = Trust::Forged;
        }
        opened_bytes += opened.events.iter().map(event_size).sum::<usize>();
        if opened_bytes > MAX_OPENED_BYTES {
            recording.problem = Some("es demasiado grande para abrirla entera".into());
            break;
        }
        recording.events.append(&mut opened.events);
        recording.complete = opened.last;
        previous = Some(opened);
    }
    if recording.problem.is_some() {
        recording.complete = false;
    }
    recording
}

/// Descarga y abre la grabación `id` de `team`, subida por `author`. Solo para admins.
pub async fn open(
    local: &SyncLocal,
    team: &str,
    id: &str,
    author: &str,
) -> Result<Recording, SyncError> {
    let team = local
        .team(team)
        .cloned()
        .ok_or_else(|| SyncError::NotFound(team.into()))?;
    let mut session = Session::new(local)?;
    let download = call!(&mut session, |api, token| api
        .recording(token, &team.id, id))?;
    Ok(assemble(local, &team, id, author, &download))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::sync::protocol::TeamRole;
    use tunel_core::sync::{Contact, SyncState, VaultKey};

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";
    const REC: &str = "0f8b2c1e-1111-4222-8333-944455556666";

    fn team(key: VaultKey) -> TeamLocal {
        TeamLocal {
            id: TEAM.into(),
            name: "Infra".into(),
            role: TeamRole::Admin,
            epoch: 0,
            key,
            state: SyncState::new(uuid::Uuid::from_u128(1)),
            rekey_needed: false,
            roster: None,
        }
    }

    fn admin_knowing(bob: &AccountKeypair) -> SyncLocal {
        let mut local: SyncLocal = serde_json::from_value(serde_json::json!({
            "server": "https://tunel.ejemplo.com",
            "email": "ana@ejemplo.com",
            "auth": "",
            "vault_key": VaultKey::generate(),
            "token": null,
            "state": SyncState::new(uuid::Uuid::from_u128(1)),
        }))
        .unwrap();
        local.contacts.insert(
            "bob@ejemplo.com".into(),
            Contact {
                key: bob.public(),
                verified: true,
            },
        );
        local
    }

    /// Tres trozos de Bob firmados con `signer`, cifrados con `key`.
    fn chunks(key: &VaultKey, signer: &AccountKeypair) -> Vec<RecordingChunk> {
        let header = RecordingHeader {
            host: "web".into(),
            actor: "bob@ejemplo.com".into(),
            started_at: 0,
            cols: 80,
            rows: 24,
        };
        let mut writer = ChunkWriter::new(TEAM, REC, header);
        (0..3)
            .map(|i| {
                let event = RecordingEvent::Output {
                    at_ms: i,
                    data: vec![b'a' + i as u8],
                };
                let chunk = writer.next(&[event], i == 2, signer).unwrap();
                RecordingChunk {
                    seq: chunk.seq,
                    epoch: 0,
                    last: chunk.last,
                    blob: chunk.seal(key, 0).unwrap(),
                }
            })
            .collect()
    }

    fn open_with(chunks: Vec<RecordingChunk>, key: VaultKey, bob: &AccountKeypair) -> Recording {
        let download = RecordingDownload {
            chunks,
            previous_keys: Vec::new(),
        };
        assemble(
            &admin_knowing(bob),
            &team(key),
            REC,
            "bob@ejemplo.com",
            &download,
        )
    }

    #[test]
    fn a_whole_recording_opens_complete_and_verified() {
        let key = VaultKey::generate();
        let bob = AccountKeypair::generate();
        let recording = open_with(chunks(&key, &bob), key, &bob);
        assert!(recording.complete);
        assert_eq!(recording.trust, Trust::Verified);
        assert_eq!(recording.events.len(), 3);
    }

    #[test]
    fn a_missing_or_swapped_chunk_stops_the_reading_there() {
        let key = VaultKey::generate();
        let bob = AccountKeypair::generate();
        let mut missing = chunks(&key, &bob);
        missing.remove(1);
        let recording = open_with(missing, key.clone(), &bob);
        assert!(!recording.complete);
        assert_eq!(recording.events.len(), 1);
        assert!(recording.problem.is_some());

        // El servidor cambia los números para que el orden parezca bueno.
        let mut swapped = chunks(&key, &bob);
        swapped.swap(1, 2);
        let recording = open_with(swapped, key, &bob);
        assert!(!recording.complete);
        assert_eq!(recording.events.len(), 1);
    }

    #[test]
    fn nothing_counts_after_the_last_chunk() {
        let key = VaultKey::generate();
        let bob = AccountKeypair::generate();
        let mut all = chunks(&key, &bob);
        let header = RecordingHeader {
            host: "web".into(),
            actor: "bob@ejemplo.com".into(),
            started_at: 0,
            cols: 80,
            rows: 24,
        };
        // Un cuarto trozo bien encadenado tras el que decía ser el último.
        let mut writer = ChunkWriter::new(TEAM, REC, header);
        let signed: Vec<_> = (0..4)
            .map(|i| writer.next(&[], i == 2, &bob).unwrap())
            .collect();
        all.push(RecordingChunk {
            seq: 3,
            epoch: 0,
            last: false,
            blob: signed[3].seal(&key, 0).unwrap(),
        });
        let recording = open_with(all, key, &bob);
        assert!(!recording.complete);
        assert!(recording.problem.is_some());
    }

    #[test]
    fn a_recording_signed_by_someone_else_is_flagged() {
        let key = VaultKey::generate();
        let bob = AccountKeypair::generate();
        let eve = AccountKeypair::generate();
        let recording = open_with(chunks(&key, &eve), key, &bob);
        assert_eq!(recording.trust, Trust::Forged);
    }
}
