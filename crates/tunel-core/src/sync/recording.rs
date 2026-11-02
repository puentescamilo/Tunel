//! Grabación de las sesiones de un Team: lo que muestra la terminal de un host del Team,
//! para que los admins lo revisen después. Solo se graba la salida y los cambios de
//! tamaño, nunca lo que se teclea: por ahí pasan contraseñas.
//!
//! La grabación se sube en trozos. Cada trozo lleva comprimidos sus eventos, la huella del
//! anterior y, el primero, la cabecera (host, quién, cuándo). Lo firma quien graba con la
//! clave de su cuenta y va cifrado con la clave del Team: el servidor no lo puede leer, ni
//! cambiar, quitar o reordenar trozos sin que se note. Sí puede quedarse sin los últimos.

use super::keys::{SealedBlob, SyncCryptoError, VaultKey};
use super::team::{AccountKeypair, PublicKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const AAD_CHUNK: &[u8] = b"tunel-equipo-grabacion-v1:";
const SIGNATURE_DOMAIN: &[u8] = b"tunel-equipo-grabacion-firma-v1:";
/// Eventos de un trozo, ya descomprimidos: lo que pasa de aquí no es un trozo de Túnel.
pub const MAX_CHUNK_EVENTS_BYTES: usize = 8 * 1024 * 1024;
const OUTPUT: u8 = 0;
const RESIZE: u8 = 1;

/// Algo que pasó en la terminal, a tantos milisegundos del principio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordingEvent {
    Output { at_ms: u64, data: Vec<u8> },
    Resize { at_ms: u64, cols: u16, rows: u16 },
}

impl RecordingEvent {
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Output { at_ms, .. } | Self::Resize { at_ms, .. } => *at_ms,
        }
    }
}

/// Los eventos en binario y comprimidos.
fn encode_events(events: &[RecordingEvent]) -> Result<Vec<u8>, SyncCryptoError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    let mut write = |bytes: &[u8]| {
        encoder
            .write_all(bytes)
            .map_err(|_| SyncCryptoError::Corrupt)
    };
    for event in events {
        match event {
            RecordingEvent::Output { at_ms, data } => {
                let len = u32::try_from(data.len()).map_err(|_| SyncCryptoError::Corrupt)?;
                write(&[OUTPUT])?;
                write(&at_ms.to_le_bytes())?;
                write(&len.to_le_bytes())?;
                write(data)?;
            }
            RecordingEvent::Resize { at_ms, cols, rows } => {
                write(&[RESIZE])?;
                write(&at_ms.to_le_bytes())?;
                write(&cols.to_le_bytes())?;
                write(&rows.to_le_bytes())?;
            }
        }
    }
    encoder.finish().map_err(|_| SyncCryptoError::Corrupt)
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], SyncCryptoError> {
    if bytes.len() < n {
        return Err(SyncCryptoError::Corrupt);
    }
    let (head, rest) = bytes.split_at(n);
    *bytes = rest;
    Ok(head)
}

fn decode_events(compressed: &[u8]) -> Result<Vec<RecordingEvent>, SyncCryptoError> {
    let mut plain = Vec::new();
    // Como mucho un byte de más, para saber si se pasa sin descomprimirlo todo.
    DeflateDecoder::new(compressed)
        .take(MAX_CHUNK_EVENTS_BYTES as u64 + 1)
        .read_to_end(&mut plain)
        .map_err(|_| SyncCryptoError::Corrupt)?;
    if plain.len() > MAX_CHUNK_EVENTS_BYTES {
        return Err(SyncCryptoError::Corrupt);
    }
    let mut rest = plain.as_slice();
    let mut events = Vec::new();
    let u64_at = |b: &[u8]| u64::from_le_bytes(b.try_into().expect("8 bytes"));
    let u16_at = |b: &[u8]| u16::from_le_bytes(b.try_into().expect("2 bytes"));
    while !rest.is_empty() {
        let kind = take(&mut rest, 1)?[0];
        let at_ms = u64_at(take(&mut rest, 8)?);
        events.push(match kind {
            OUTPUT => {
                let len = u32::from_le_bytes(take(&mut rest, 4)?.try_into().expect("4 bytes"));
                let data = take(&mut rest, len as usize)?.to_vec();
                RecordingEvent::Output { at_ms, data }
            }
            RESIZE => RecordingEvent::Resize {
                at_ms,
                cols: u16_at(take(&mut rest, 2)?),
                rows: u16_at(take(&mut rest, 2)?),
            },
            _ => return Err(SyncCryptoError::Corrupt),
        });
    }
    Ok(events)
}

/// De qué es la grabación. Va solo en el primer trozo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingHeader {
    /// Nombre del host tal como lo veía quien se conectó.
    pub host: String,
    /// Correo de quien se conectó, en minúsculas.
    pub actor: String,
    /// Milisegundos desde 1970, según su reloj.
    pub started_at: u64,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Serialize, Deserialize)]
struct ChunkPayload {
    team: String,
    recording: String,
    seq: u64,
    /// Huella del trozo anterior; `None` en el primero.
    prev: Option<String>,
    /// Es el último: la sesión terminó.
    last: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    header: Option<RecordingHeader>,
    /// Eventos comprimidos, en base64.
    events: String,
}

#[derive(Serialize, Deserialize)]
struct Signed {
    payload: String,
    signature: String,
}

fn digest(payload: &str) -> String {
    Sha256::digest(payload.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn message(payload: &str) -> Vec<u8> {
    [SIGNATURE_DOMAIN, payload.as_bytes()].concat()
}

fn aad(team: &str, recording: &str, seq: u64, epoch: u64) -> Vec<u8> {
    [
        AAD_CHUNK,
        team.as_bytes(),
        b":",
        recording.as_bytes(),
        b":",
        &seq.to_be_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

/// Un trozo firmado, listo para cifrar con la clave que tenga el Team al subirlo.
#[derive(Clone)]
pub struct SignedChunk {
    pub seq: u64,
    pub last: bool,
    team: String,
    recording: String,
    signed: Zeroizing<String>,
}

impl SignedChunk {
    pub fn seal(&self, key: &VaultKey, epoch: u64) -> Result<SealedBlob, SyncCryptoError> {
        key.seal_blob(
            self.signed.as_bytes(),
            &aad(&self.team, &self.recording, self.seq, epoch),
        )
    }

    /// Bytes que ocupa antes de cifrar.
    pub fn len(&self) -> usize {
        self.signed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signed.is_empty()
    }
}

/// Va haciendo los trozos de una grabación, en orden.
pub struct ChunkWriter {
    team: String,
    recording: String,
    header: Option<RecordingHeader>,
    seq: u64,
    prev: Option<String>,
}

impl ChunkWriter {
    pub fn new(team: &str, recording: &str, header: RecordingHeader) -> Self {
        Self {
            team: team.to_string(),
            recording: recording.to_string(),
            header: Some(header),
            seq: 0,
            prev: None,
        }
    }

    /// El trozo siguiente con `events`; `last` cierra la grabación.
    pub fn next(
        &mut self,
        events: &[RecordingEvent],
        last: bool,
        pair: &AccountKeypair,
    ) -> Result<SignedChunk, SyncCryptoError> {
        let payload = ChunkPayload {
            team: self.team.clone(),
            recording: self.recording.clone(),
            seq: self.seq,
            prev: self.prev.clone(),
            last,
            header: self.header.take(),
            events: B64.encode(encode_events(events)?),
        };
        let payload = serde_json::to_string(&payload).map_err(|_| SyncCryptoError::Corrupt)?;
        let signed = Signed {
            signature: B64.encode(pair.sign(&message(&payload))),
            payload,
        };
        let chunk = SignedChunk {
            seq: self.seq,
            last,
            team: self.team.clone(),
            recording: self.recording.clone(),
            signed: Zeroizing::new(
                serde_json::to_string(&signed).map_err(|_| SyncCryptoError::Corrupt)?,
            ),
        };
        self.prev = Some(digest(&signed.payload));
        self.seq += 1;
        Ok(chunk)
    }
}

/// Un trozo descifrado. Quien lo abre comprueba la firma y que siga al anterior.
#[derive(Debug)]
pub struct OpenedChunk {
    pub header: Option<RecordingHeader>,
    pub last: bool,
    pub events: Vec<RecordingEvent>,
    prev: Option<String>,
    digest: String,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl OpenedChunk {
    pub fn open(
        blob: &SealedBlob,
        key: &VaultKey,
        team: &str,
        recording: &str,
        seq: u64,
        epoch: u64,
    ) -> Result<Self, SyncCryptoError> {
        let plain = key.open_blob(blob, &aad(team, recording, seq, epoch))?;
        let signed: Signed =
            serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)?;
        let payload: ChunkPayload =
            serde_json::from_str(&signed.payload).map_err(|_| SyncCryptoError::Corrupt)?;
        if payload.team != team || payload.recording != recording || payload.seq != seq {
            return Err(SyncCryptoError::Mismatch);
        }
        // La cabecera va en el primero y solo en él.
        if payload.header.is_some() != (seq == 0) {
            return Err(SyncCryptoError::Mismatch);
        }
        let compressed = B64
            .decode(&payload.events)
            .map_err(|_| SyncCryptoError::Corrupt)?;
        Ok(Self {
            header: payload.header,
            last: payload.last,
            events: decode_events(&compressed)?,
            prev: payload.prev,
            digest: digest(&signed.payload),
            message: message(&signed.payload),
            signature: B64
                .decode(&signed.signature)
                .map_err(|_| SyncCryptoError::Corrupt)?,
        })
    }

    /// Viene justo después de `previous` (o es el primero, si no hay anterior).
    pub fn follows(&self, previous: Option<&OpenedChunk>) -> bool {
        self.prev == previous.map(|p| p.digest.clone())
    }

    pub fn signed_by(&self, key: &PublicKey) -> bool {
        key.verify(&self.message, &self.signature)
    }
}

/// La grabación en formato asciicast v2, el de asciinema, para verla con otras
/// herramientas. Los bytes que no son UTF-8 se sustituyen.
pub fn to_asciicast(header: &RecordingHeader, events: &[RecordingEvent]) -> String {
    let seconds = |at_ms: u64| at_ms as f64 / 1000.0;
    let first = serde_json::json!({
        "version": 2,
        "width": header.cols,
        "height": header.rows,
        "timestamp": header.started_at / 1000,
        "title": super::audit::clean_name(&format!("{} · {}", header.host, header.actor)),
    });
    let mut out = format!("{first}\n");
    for event in events {
        let line = match event {
            RecordingEvent::Output { at_ms, data } => {
                serde_json::json!([seconds(*at_ms), "o", String::from_utf8_lossy(data)])
            }
            RecordingEvent::Resize { at_ms, cols, rows } => {
                serde_json::json!([seconds(*at_ms), "r", format!("{cols}x{rows}")])
            }
        };
        out.push_str(&format!("{line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";
    const REC: &str = "grabacion-1";

    fn header() -> RecordingHeader {
        RecordingHeader {
            host: "web".into(),
            actor: "ana@ejemplo.com".into(),
            started_at: 1_700_000_000_000,
            cols: 80,
            rows: 24,
        }
    }

    fn output(at_ms: u64, text: &str) -> RecordingEvent {
        RecordingEvent::Output {
            at_ms,
            data: text.as_bytes().to_vec(),
        }
    }

    fn open(chunk: &SignedChunk, key: &VaultKey) -> Result<OpenedChunk, SyncCryptoError> {
        OpenedChunk::open(&chunk.seal(key, 2).unwrap(), key, TEAM, REC, chunk.seq, 2)
    }

    #[test]
    fn events_round_trip_compressed() {
        let events = vec![
            output(0, "hola\r\n"),
            RecordingEvent::Resize {
                at_ms: 5,
                cols: 120,
                rows: 40,
            },
            RecordingEvent::Output {
                at_ms: 9,
                data: vec![0xff, 0x00, 0x1b],
            },
        ];
        let encoded = encode_events(&events).unwrap();
        assert_eq!(decode_events(&encoded).unwrap(), events);
        let repetitive = vec![output(0, &"x".repeat(100_000))];
        assert!(encode_events(&repetitive).unwrap().len() < 1000);
    }

    #[test]
    fn a_decompression_bomb_or_garbage_is_rejected() {
        let bomb = vec![RecordingEvent::Output {
            at_ms: 0,
            data: vec![0; MAX_CHUNK_EVENTS_BYTES + 1],
        }];
        assert!(decode_events(&encode_events(&bomb).unwrap()).is_err());
        let mut truncated = DeflateEncoder::new(Vec::new(), Compression::default());
        truncated
            .write_all(&[OUTPUT, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0])
            .unwrap();
        assert!(decode_events(&truncated.finish().unwrap()).is_err());
    }

    #[test]
    fn chunks_open_in_order_and_carry_the_header_once() {
        let key = VaultKey::generate();
        let ana = AccountKeypair::generate();
        let mut writer = ChunkWriter::new(TEAM, REC, header());
        let first = writer.next(&[output(0, "a")], false, &ana).unwrap();
        let second = writer.next(&[output(10, "b")], true, &ana).unwrap();
        let first = open(&first, &key).unwrap();
        let second = open(&second, &key).unwrap();
        assert_eq!(first.header, Some(header()));
        assert_eq!(second.header, None);
        assert!(first.follows(None));
        assert!(second.follows(Some(&first)));
        assert!(!first.follows(Some(&second)));
        assert!(second.last && !first.last);
        assert!(first.signed_by(&ana.public()));
        assert!(!first.signed_by(&AccountKeypair::generate().public()));
    }

    #[test]
    fn the_export_is_asciicast_v2() {
        let events = vec![
            output(1500, "hola"),
            RecordingEvent::Resize {
                at_ms: 2000,
                cols: 100,
                rows: 30,
            },
        ];
        let cast = to_asciicast(&header(), &events);
        let lines: Vec<serde_json::Value> = cast
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["version"], 2);
        assert_eq!(lines[0]["width"], 80);
        assert_eq!(lines[0]["timestamp"], 1_700_000_000);
        assert_eq!(lines[1], serde_json::json!([1.5, "o", "hola"]));
        assert_eq!(lines[2], serde_json::json!([2.0, "r", "100x30"]));
    }

    #[test]
    fn a_chunk_only_opens_in_its_place() {
        let key = VaultKey::generate();
        let ana = AccountKeypair::generate();
        let mut writer = ChunkWriter::new(TEAM, REC, header());
        let chunk = writer.next(&[output(0, "a")], false, &ana).unwrap();
        let sealed = chunk.seal(&key, 2).unwrap();
        assert!(OpenedChunk::open(&sealed, &key, TEAM, REC, 0, 2).is_ok());
        assert!(OpenedChunk::open(&sealed, &key, TEAM, REC, 1, 2).is_err());
        assert!(OpenedChunk::open(&sealed, &key, TEAM, "otra", 0, 2).is_err());
        assert!(OpenedChunk::open(&sealed, &key, TEAM, REC, 0, 3).is_err());
        assert!(OpenedChunk::open(&sealed, &VaultKey::generate(), TEAM, REC, 0, 2).is_err());
    }
}
