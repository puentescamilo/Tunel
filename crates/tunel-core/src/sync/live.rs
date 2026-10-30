//! Sesiones compartidas: una persona deja ver una terminal abierta a los miembros de su
//! Team y puede darle el control a alguno.
//!
//! - Quien comparte genera una clave de sesión y la publica en el anuncio, cifrado con la
//!   clave del Team: solo los miembros pueden abrirlo. Con esa clave se cifra todo lo que
//!   muestra la terminal; el servidor solo reenvía los fotogramas.
//! - Cada fotograma lleva un número de orden y quien mira exige que sean consecutivos: el
//!   servidor no puede quitar, repetir ni desordenar ninguno sin que se note.
//! - Quien llega a mitad de sesión recibe primero la pantalla entera, ligada a un número
//!   aleatorio que eligió al conectarse y con el número del siguiente fotograma. Así el
//!   servidor no puede darle una pantalla antigua grabada para otra persona.
//! - Para escribir hace falta una clave de control que quien comparte envuelve para esa
//!   persona con X25519, como la clave de un Team. Quien solo mira tiene la clave de
//!   sesión, pero no puede escribir; el servidor tampoco.

use super::keys::{SealedBlob, SyncCryptoError, VaultKey, expand};
use super::team::{AccountKeypair, PublicKey};
use crate::crypto::{self, KEY_LEN, MasterKey};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

const AAD_META: &[u8] = b"tunel-sesion-anuncio-v1:";
const INFO_OUTPUT: &[u8] = b"tunel-sesion-salida-v1";
const AAD_OUTPUT: &[u8] = b"tunel-sesion-fotograma-v1:";
const AAD_JOIN: &[u8] = b"tunel-sesion-llegada-v1:";
const INFO_CONTROL_WRAP: &[u8] = b"tunel-sesion-control-envoltura-v1";
const AAD_CONTROL_KEY: &[u8] = b"tunel-sesion-control-clave-v1:";
const AAD_INPUT: &[u8] = b"tunel-sesion-entrada-v1:";
/// Tope del título de una sesión, en bytes.
pub const MAX_LIVE_TITLE: usize = 200;
/// Tope del contenido de un fotograma, en bytes: cifrado y en base64 cabe en un mensaje
/// del servidor.
pub const MAX_FRAME: usize = 512 * 1024;
/// Tope de lo que se escribe en un fotograma; lo que se pega se trocea.
pub const MAX_INPUT: usize = 4 * 1024;
/// Bytes del número de orden con que empieza cada fotograma.
const SEQ_LEN: usize = 8;
/// Tamaño máximo de la terminal compartida, en columnas y filas: quien mira reserva la
/// pantalla de ese tamaño.
pub const MAX_DIMENSION: u16 = 1000;
/// Bytes del número aleatorio con que llega quien mira.
const NONCE_LEN: usize = 16;

fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rng().fill_bytes(key.as_mut());
    key
}

fn key_from_slice(bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, SyncCryptoError> {
    let key: [u8; KEY_LEN] = bytes.try_into().map_err(|_| SyncCryptoError::Corrupt)?;
    Ok(Zeroizing::new(key))
}

/// Clave de una sesión compartida: la tienen quien comparte y todos los miembros del Team.
#[derive(Clone)]
pub struct LiveKey(Zeroizing<[u8; KEY_LEN]>);

impl LiveKey {
    pub fn generate() -> Self {
        Self(random_key())
    }
}

impl fmt::Debug for LiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LiveKey(…)")
    }
}

/// Lo que se anuncia al Team, cifrado con su clave.
#[derive(Debug, Clone)]
pub struct LiveMeta {
    pub title: String,
    pub key: LiveKey,
    /// Clave pública de quien comparte: con ella se abren las claves de control.
    pub host: PublicKey,
}

#[derive(Serialize, Deserialize)]
struct MetaWire {
    title: String,
    key: String,
    host: PublicKey,
}

fn meta_aad(team: &str, epoch: u64, session: &str) -> Vec<u8> {
    [
        AAD_META,
        team.as_bytes(),
        b":",
        &epoch.to_be_bytes(),
        b":",
        session.as_bytes(),
    ]
    .concat()
}

/// Recorta el título a [`MAX_LIVE_TITLE`] bytes sin partir un carácter.
fn clip_title(title: &str) -> &str {
    let mut end = title.len().min(MAX_LIVE_TITLE);
    while !title.is_char_boundary(end) {
        end -= 1;
    }
    &title[..end]
}

/// Dónde se publica un anuncio: Team, época de su clave y sesión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaContext<'a> {
    pub team: &'a str,
    pub epoch: u64,
    pub session: &'a str,
}

impl MetaContext<'_> {
    fn aad(&self) -> Vec<u8> {
        meta_aad(self.team, self.epoch, self.session)
    }
}

/// Cifra el anuncio de una sesión con la clave del Team.
pub fn seal_meta(
    team_key: &VaultKey,
    context: MetaContext<'_>,
    meta: &LiveMeta,
) -> Result<SealedBlob, SyncCryptoError> {
    let wire = MetaWire {
        title: clip_title(&meta.title).to_string(),
        key: B64.encode(meta.key.0.as_ref()),
        host: meta.host,
    };
    let plain = Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| SyncCryptoError::Corrupt)?);
    team_key.seal_blob(&plain, &context.aad())
}

pub fn open_meta(
    team_key: &VaultKey,
    context: MetaContext<'_>,
    blob: &SealedBlob,
) -> Result<LiveMeta, SyncCryptoError> {
    let plain = team_key.open_blob(blob, &context.aad())?;
    let wire: MetaWire = serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)?;
    let key = Zeroizing::new(
        B64.decode(&wire.key)
            .map_err(|_| SyncCryptoError::Corrupt)?,
    );
    if wire.title.len() > MAX_LIVE_TITLE {
        return Err(SyncCryptoError::Corrupt);
    }
    Ok(LiveMeta {
        title: wire.title,
        key: LiveKey(key_from_slice(&key)?),
        host: wire.host,
    })
}

/// Lo que viaja de quien comparte a quien mira.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveFrame {
    /// Salida de la terminal, tal como llega del programa.
    Output(Vec<u8>),
    /// Quien comparte cambió el tamaño de su terminal.
    Resize { cols: u16, rows: u16 },
    /// La pantalla entera: sus bytes reproducen en una terminal vacía de ese tamaño lo
    /// que se ve ahora. Se manda a quien llega y, a todos, si hubo que descartar salida.
    Snapshot { cols: u16, rows: u16, data: Vec<u8> },
}

const KIND_OUTPUT: u8 = 0;
const KIND_RESIZE: u8 = 1;
const KIND_SNAPSHOT: u8 = 2;

impl LiveFrame {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Output(data) => [&[KIND_OUTPUT][..], data].concat(),
            Self::Resize { cols, rows } => {
                [&[KIND_RESIZE][..], &cols.to_be_bytes(), &rows.to_be_bytes()].concat()
            }
            Self::Snapshot { cols, rows, data } => [
                &[KIND_SNAPSHOT][..],
                &cols.to_be_bytes(),
                &rows.to_be_bytes(),
                data,
            ]
            .concat(),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, SyncCryptoError> {
        let (&kind, rest) = bytes.split_first().ok_or(SyncCryptoError::Corrupt)?;
        let size = |rest: &[u8]| -> Result<(u16, u16), SyncCryptoError> {
            let [c0, c1, r0, r1, ..] = rest else {
                return Err(SyncCryptoError::Corrupt);
            };
            let cols = u16::from_be_bytes([*c0, *c1]);
            let rows = u16::from_be_bytes([*r0, *r1]);
            let valid = |n: u16| (1..=MAX_DIMENSION).contains(&n);
            if !valid(cols) || !valid(rows) {
                return Err(SyncCryptoError::Corrupt);
            }
            Ok((cols, rows))
        };
        match kind {
            KIND_OUTPUT => Ok(Self::Output(rest.to_vec())),
            KIND_RESIZE if rest.len() == 4 => {
                let (cols, rows) = size(rest)?;
                Ok(Self::Resize { cols, rows })
            }
            KIND_SNAPSHOT => {
                let (cols, rows) = size(rest)?;
                Ok(Self::Snapshot {
                    cols,
                    rows,
                    data: rest[4..].to_vec(),
                })
            }
            _ => Err(SyncCryptoError::Corrupt),
        }
    }

    /// Bytes que ocupa el contenido; no puede pasar de [`MAX_FRAME`].
    pub fn len(&self) -> usize {
        match self {
            Self::Output(data) => data.len(),
            Self::Resize { .. } => 4,
            Self::Snapshot { data, .. } => data.len() + 4,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Cifra y descifra fotogramas numerados de un solo sentido.
struct FrameKey {
    key: MasterKey,
    aad: Vec<u8>,
}

impl FrameKey {
    fn seal(&self, seq: u64, body: &[u8]) -> Result<SealedBlob, SyncCryptoError> {
        let plain = Zeroizing::new([&seq.to_be_bytes()[..], body].concat());
        Ok(SealedBlob::from_sealed(&crypto::seal(
            &self.key, &plain, &self.aad,
        )?))
    }

    fn open(&self, blob: &SealedBlob) -> Result<(u64, Zeroizing<Vec<u8>>), SyncCryptoError> {
        let plain = crypto::open(&self.key, &blob.to_sealed()?, &self.aad)?;
        let (seq, body) = plain
            .split_first_chunk::<SEQ_LEN>()
            .ok_or(SyncCryptoError::Corrupt)?;
        Ok((u64::from_be_bytes(*seq), Zeroizing::new(body.to_vec())))
    }
}

/// Exige números de orden consecutivos: falta, sobra o se repite alguno, y es un error.
#[derive(Debug)]
struct Sequence(u64);

impl Sequence {
    fn accept(&mut self, seq: u64) -> Result<(), SyncCryptoError> {
        if seq != self.0 {
            return Err(SyncCryptoError::Replayed);
        }
        self.0 += 1;
        Ok(())
    }
}

fn output_key(key: &LiveKey, session: &str) -> FrameKey {
    FrameKey {
        key: MasterKey::from_bytes(expand(key.0.as_ref(), INFO_OUTPUT)),
        aad: [AAD_OUTPUT, session.as_bytes()].concat(),
    }
}

/// La pantalla para quien llega va ligada a su número de llegada y, en lugar de su propio
/// número de orden, lleva el del siguiente fotograma.
fn join_key(key: &LiveKey, session: &str, nonce: &JoinNonce) -> FrameKey {
    FrameKey {
        key: MasterKey::from_bytes(expand(key.0.as_ref(), INFO_OUTPUT)),
        aad: [AAD_JOIN, session.as_bytes(), b":", &nonce.0].concat(),
    }
}

/// Número aleatorio que elige quien mira al conectarse; el servidor se lo pasa a quien
/// comparte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinNonce([u8; NONCE_LEN]);

impl JoinNonce {
    pub fn generate() -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        Self(nonce)
    }

    /// En base64 apto para URL: viaja en la dirección del WebSocket.
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64(text: &str) -> Option<Self> {
        Some(Self(URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()?))
    }
}

/// Cifra lo que muestra la terminal compartida.
pub struct OutputSealer {
    key: LiveKey,
    session: String,
    stream: FrameKey,
    next: u64,
}

impl OutputSealer {
    pub fn new(key: &LiveKey, session: &str) -> Self {
        Self {
            key: key.clone(),
            session: session.to_string(),
            stream: output_key(key, session),
            next: 0,
        }
    }

    /// Fotograma para todos los que miran.
    pub fn seal(&mut self, frame: &LiveFrame) -> Result<SealedBlob, SyncCryptoError> {
        if frame.len() > MAX_FRAME {
            return Err(SyncCryptoError::Corrupt);
        }
        let sealed = self.stream.seal(self.next, &frame.encode())?;
        self.next += 1;
        Ok(sealed)
    }

    /// La pantalla para quien acaba de llegar con `nonce`; después recibirá los
    /// fotogramas desde el siguiente que se cifre.
    pub fn seal_join(
        &self,
        nonce: &JoinNonce,
        cols: u16,
        rows: u16,
        data: &[u8],
    ) -> Result<SealedBlob, SyncCryptoError> {
        let frame = LiveFrame::Snapshot {
            cols,
            rows,
            data: data.to_vec(),
        };
        if frame.len() > MAX_FRAME {
            return Err(SyncCryptoError::Corrupt);
        }
        join_key(&self.key, &self.session, nonce).seal(self.next, &frame.encode())
    }
}

/// Descifra lo que muestra una terminal compartida y comprueba que no falta nada.
pub struct OutputOpener {
    stream: FrameKey,
    join: FrameKey,
    /// Siguiente número de orden esperado; `None` hasta recibir la pantalla de llegada.
    sequence: Option<Sequence>,
}

impl OutputOpener {
    /// Quien mira llega con `nonce`, el que mandó al conectarse.
    pub fn new(key: &LiveKey, session: &str, nonce: &JoinNonce) -> Self {
        Self {
            stream: output_key(key, session),
            join: join_key(key, session, nonce),
            sequence: None,
        }
    }

    /// La pantalla de llegada. Solo hay una, y tiene que estar ligada a este `nonce`.
    pub fn open_join(&mut self, blob: &SealedBlob) -> Result<LiveFrame, SyncCryptoError> {
        if self.sequence.is_some() {
            return Err(SyncCryptoError::Replayed);
        }
        let (next, body) = self.join.open(blob)?;
        let frame = LiveFrame::decode(&body)?;
        if !matches!(frame, LiveFrame::Snapshot { .. }) {
            return Err(SyncCryptoError::Corrupt);
        }
        self.sequence = Some(Sequence(next));
        Ok(frame)
    }

    /// Un fotograma para todos. Los que llegan antes de la pantalla de llegada ya están
    /// incluidos en ella: se comprueban y se descartan (`None`).
    pub fn open(&mut self, blob: &SealedBlob) -> Result<Option<LiveFrame>, SyncCryptoError> {
        let (seq, body) = self.stream.open(blob)?;
        let frame = LiveFrame::decode(&body)?;
        match self.sequence.as_mut() {
            None => Ok(None),
            Some(sequence) => {
                sequence.accept(seq)?;
                Ok(Some(frame))
            }
        }
    }
}

/// Clave con la que una persona escribe en la terminal compartida.
#[derive(Clone)]
pub struct ControlKey(Zeroizing<[u8; KEY_LEN]>);

impl ControlKey {
    pub fn generate() -> Self {
        Self(random_key())
    }
}

impl fmt::Debug for ControlKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlKey(…)")
    }
}

/// A qué sesión y a qué concesión de control pertenece una clave de control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlContext<'a> {
    pub session: &'a str,
    /// Número de la concesión: cada vez que se da el control, uno nuevo.
    pub grant: u64,
}

impl ControlContext<'_> {
    fn key_aad(&self) -> Vec<u8> {
        [
            AAD_CONTROL_KEY,
            self.session.as_bytes(),
            b":",
            &self.grant.to_be_bytes(),
        ]
        .concat()
    }

    fn input_aad(&self) -> Vec<u8> {
        [
            AAD_INPUT,
            self.session.as_bytes(),
            b":",
            &self.grant.to_be_bytes(),
        ]
        .concat()
    }
}

/// Envuelve la clave de control para `viewer`: solo esa cuenta la abre, y sabe que la
/// envolvió quien comparte.
pub fn wrap_control_key(
    key: &ControlKey,
    context: ControlContext<'_>,
    host: &AccountKeypair,
    viewer: &PublicKey,
) -> Result<SealedBlob, SyncCryptoError> {
    let host_public = host.public();
    let wrapping = host.wrapping_key(INFO_CONTROL_WRAP, viewer, &host_public, viewer)?;
    let sealed = crypto::seal(&wrapping, key.0.as_ref(), &context.key_aad())?;
    Ok(SealedBlob::from_sealed(&sealed))
}

pub fn unwrap_control_key(
    blob: &SealedBlob,
    context: ControlContext<'_>,
    viewer: &AccountKeypair,
    host: &PublicKey,
) -> Result<ControlKey, SyncCryptoError> {
    let viewer_public = viewer.public();
    let wrapping = viewer.wrapping_key(INFO_CONTROL_WRAP, host, host, &viewer_public)?;
    let plain = crypto::open(&wrapping, &blob.to_sealed()?, &context.key_aad())?;
    Ok(ControlKey(key_from_slice(&plain)?))
}

fn input_key(key: &ControlKey, context: ControlContext<'_>) -> FrameKey {
    FrameKey {
        key: MasterKey::from_bytes(key.0.clone()),
        aad: context.input_aad(),
    }
}

/// Cifra lo que escribe quien tiene el control.
pub struct InputSealer {
    key: FrameKey,
    next: u64,
}

impl InputSealer {
    pub fn new(key: &ControlKey, context: ControlContext<'_>) -> Self {
        Self {
            key: input_key(key, context),
            next: 0,
        }
    }

    pub fn seal(&mut self, data: &[u8]) -> Result<SealedBlob, SyncCryptoError> {
        if data.len() > MAX_INPUT {
            return Err(SyncCryptoError::Corrupt);
        }
        let sealed = self.key.seal(self.next, data)?;
        self.next += 1;
        Ok(sealed)
    }
}

/// Descifra lo que escribe quien tiene el control, sin admitir que falte nada: quitar
/// unas letras puede cambiar el sentido de una orden.
pub struct InputOpener {
    key: FrameKey,
    sequence: Sequence,
}

impl InputOpener {
    pub fn new(key: &ControlKey, context: ControlContext<'_>) -> Self {
        Self {
            key: input_key(key, context),
            sequence: Sequence(0),
        }
    }

    pub fn open(&mut self, blob: &SealedBlob) -> Result<Vec<u8>, SyncCryptoError> {
        let (seq, body) = self.key.open(blob)?;
        self.sequence.accept(seq)?;
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";
    const SESSION: &str = "0f1e2d3c-4b5a-4968-8776-655443322110";

    fn meta(host: &AccountKeypair) -> LiveMeta {
        LiveMeta {
            title: "web-01".into(),
            key: LiveKey::generate(),
            host: host.public(),
        }
    }

    fn at(epoch: u64, session: &str) -> MetaContext<'_> {
        MetaContext {
            team: TEAM,
            epoch,
            session,
        }
    }

    fn grant(n: u64) -> ControlContext<'static> {
        ControlContext {
            session: SESSION,
            grant: n,
        }
    }

    fn output(text: &str) -> LiveFrame {
        LiveFrame::Output(text.as_bytes().to_vec())
    }

    /// Quien mira recibe la pantalla de llegada y queda sincronizado.
    fn joined(key: &LiveKey, sealer: &OutputSealer) -> OutputOpener {
        let nonce = JoinNonce::generate();
        let mut opener = OutputOpener::new(key, SESSION, &nonce);
        let join = sealer.seal_join(&nonce, 80, 24, b"$ ").unwrap();
        opener.open_join(&join).unwrap();
        opener
    }

    #[test]
    fn the_announcement_opens_only_with_the_team_key_epoch_and_session() {
        let team_key = VaultKey::generate();
        let host = AccountKeypair::generate();
        let meta = meta(&host);
        let sealed = seal_meta(&team_key, at(2, SESSION), &meta).unwrap();
        let opened = open_meta(&team_key, at(2, SESSION), &sealed).unwrap();
        assert_eq!(opened.title, "web-01");
        assert_eq!(opened.host, host.public());
        assert!(open_meta(&VaultKey::generate(), at(2, SESSION), &sealed).is_err());
        assert!(open_meta(&team_key, at(2, "otra"), &sealed).is_err());
        assert!(open_meta(&team_key, at(3, SESSION), &sealed).is_err());
    }

    #[test]
    fn long_titles_are_clipped_on_a_character_boundary() {
        let team_key = VaultKey::generate();
        let host = AccountKeypair::generate();
        let mut meta = meta(&host);
        meta.title = "ñ".repeat(MAX_LIVE_TITLE);
        let sealed = seal_meta(&team_key, at(0, SESSION), &meta).unwrap();
        let opened = open_meta(&team_key, at(0, SESSION), &sealed).unwrap();
        assert_eq!(opened.title.len(), MAX_LIVE_TITLE);
        assert!(opened.title.chars().all(|c| c == 'ñ'));
    }

    #[test]
    fn a_viewer_syncs_on_its_join_screen_and_then_gets_every_frame() {
        let key = LiveKey::generate();
        let mut sealer = OutputSealer::new(&key, SESSION);
        let before = sealer.seal(&output("antes")).unwrap();
        let nonce = JoinNonce::generate();
        let join = sealer.seal_join(&nonce, 120, 40, b"pantalla").unwrap();
        let frames = [
            output("hola\r\n"),
            output(""),
            LiveFrame::Resize {
                cols: 100,
                rows: 30,
            },
            LiveFrame::Snapshot {
                cols: 100,
                rows: 30,
                data: b"\x1b[2J$ ".to_vec(),
            },
        ];
        let sealed: Vec<_> = frames.iter().map(|f| sealer.seal(f).unwrap()).collect();

        let mut opener = OutputOpener::new(&key, SESSION, &nonce);
        // Lo que llegó antes de la pantalla ya está en ella.
        assert_eq!(opener.open(&before).unwrap(), None);
        assert_eq!(
            opener.open_join(&join).unwrap(),
            LiveFrame::Snapshot {
                cols: 120,
                rows: 40,
                data: b"pantalla".to_vec()
            }
        );
        for (frame, blob) in frames.iter().zip(&sealed) {
            assert_eq!(opener.open(blob).unwrap().as_ref(), Some(frame));
        }
    }

    #[test]
    fn a_dropped_repeated_or_reordered_frame_is_detected() {
        let key = LiveKey::generate();
        let mut sealer = OutputSealer::new(&key, SESSION);
        let mut opener = joined(&key, &sealer);
        let a = sealer.seal(&output("a")).unwrap();
        let b = sealer.seal(&output("b")).unwrap();
        let c = sealer.seal(&output("c")).unwrap();

        let mut dropped = joined(&key, &OutputSealer::new(&key, SESSION));
        dropped.open(&a).unwrap();
        assert!(matches!(dropped.open(&c), Err(SyncCryptoError::Replayed)));

        opener.open(&a).unwrap();
        assert!(matches!(opener.open(&a), Err(SyncCryptoError::Replayed)));
        let mut reordered = joined(&key, &OutputSealer::new(&key, SESSION));
        assert!(matches!(reordered.open(&b), Err(SyncCryptoError::Replayed)));
    }

    #[test]
    fn a_join_screen_recorded_for_someone_else_is_rejected() {
        let key = LiveKey::generate();
        let sealer = OutputSealer::new(&key, SESSION);
        let other = JoinNonce::generate();
        let recorded = sealer.seal_join(&other, 80, 24, b"vieja").unwrap();
        let mut opener = OutputOpener::new(&key, SESSION, &JoinNonce::generate());
        assert!(opener.open_join(&recorded).is_err());
        // Un fotograma normal tampoco sirve como pantalla de llegada, ni al revés.
        let mut sealer = OutputSealer::new(&key, SESSION);
        let normal = sealer.seal(&output("x")).unwrap();
        assert!(opener.open_join(&normal).is_err());
        let mut fresh = OutputOpener::new(&key, SESSION, &other);
        assert_eq!(fresh.open(&recorded).ok(), None);
    }

    #[test]
    fn only_one_join_screen_is_accepted() {
        let key = LiveKey::generate();
        let sealer = OutputSealer::new(&key, SESSION);
        let nonce = JoinNonce::generate();
        let join = sealer.seal_join(&nonce, 80, 24, b"").unwrap();
        let mut opener = OutputOpener::new(&key, SESSION, &nonce);
        opener.open_join(&join).unwrap();
        assert!(matches!(
            opener.open_join(&join),
            Err(SyncCryptoError::Replayed)
        ));
    }

    #[test]
    fn frames_from_another_session_or_key_are_rejected() {
        let key = LiveKey::generate();
        let sealed = OutputSealer::new(&key, SESSION).seal(&output("x")).unwrap();
        let nonce = JoinNonce::generate();
        assert!(
            OutputOpener::new(&key, "otra", &nonce)
                .open(&sealed)
                .is_err()
        );
        assert!(
            OutputOpener::new(&LiveKey::generate(), SESSION, &nonce)
                .open(&sealed)
                .is_err()
        );
    }

    #[test]
    fn oversized_frames_and_terminals_are_refused() {
        let key = LiveKey::generate();
        let mut sealer = OutputSealer::new(&key, SESSION);
        assert!(
            sealer
                .seal(&LiveFrame::Output(vec![0; MAX_FRAME + 1]))
                .is_err()
        );
        assert!(sealer.seal(&LiveFrame::Output(vec![0; MAX_FRAME])).is_ok());
        let huge = LiveFrame::Resize {
            cols: MAX_DIMENSION + 1,
            rows: 24,
        };
        let sealed = sealer.seal(&huge).unwrap();
        let mut opener = joined(&key, &OutputSealer::new(&key, SESSION));
        assert!(opener.open(&sealed).is_err());
        let nonce = JoinNonce::generate();
        let join = sealer.seal_join(&nonce, 80, 0, b"").unwrap();
        assert!(
            OutputOpener::new(&key, SESSION, &nonce)
                .open_join(&join)
                .is_err()
        );
    }

    #[test]
    fn only_the_viewer_opens_its_control_key_and_knows_who_wrapped_it() {
        let host = AccountKeypair::generate();
        let viewer = AccountKeypair::generate();
        let other = AccountKeypair::generate();
        let key = ControlKey::generate();
        let wrapped = wrap_control_key(&key, grant(1), &host, &viewer.public()).unwrap();

        let opened = unwrap_control_key(&wrapped, grant(1), &viewer, &host.public()).unwrap();
        assert!(unwrap_control_key(&wrapped, grant(1), &other, &host.public()).is_err());
        assert!(unwrap_control_key(&wrapped, grant(1), &viewer, &other.public()).is_err());
        assert!(unwrap_control_key(&wrapped, grant(2), &viewer, &host.public()).is_err());

        let mut sealer = InputSealer::new(&opened, grant(1));
        let mut opener = InputOpener::new(&key, grant(1));
        let typed = sealer.seal(b"ls\r").unwrap();
        assert_eq!(opener.open(&typed).unwrap(), b"ls\r");
        assert!(matches!(
            opener.open(&typed),
            Err(SyncCryptoError::Replayed)
        ));
    }

    #[test]
    fn dropped_keystrokes_are_detected() {
        let control = ControlKey::generate();
        let mut sealer = InputSealer::new(&control, grant(1));
        let _rm = sealer.seal(b"rm -rf /tmp").unwrap();
        let rest = sealer.seal(b"/x\r").unwrap();
        let mut opener = InputOpener::new(&control, grant(1));
        assert!(matches!(opener.open(&rest), Err(SyncCryptoError::Replayed)));
    }

    #[test]
    fn the_session_key_cannot_write() {
        // Quien solo mira tiene la clave de sesión: no le sirve para fabricar entrada.
        let live = LiveKey::generate();
        let control = ControlKey::generate();
        let forged = OutputSealer::new(&live, SESSION)
            .seal(&output("rm -rf /\r"))
            .unwrap();
        assert!(InputOpener::new(&control, grant(1)).open(&forged).is_err());
    }

    #[test]
    fn input_from_an_older_grant_or_too_long_is_rejected() {
        let control = ControlKey::generate();
        let typed = InputSealer::new(&control, grant(1)).seal(b"x").unwrap();
        assert!(InputOpener::new(&control, grant(2)).open(&typed).is_err());
        let mut sealer = InputSealer::new(&control, grant(1));
        assert!(sealer.seal(&vec![b'a'; MAX_INPUT + 1]).is_err());
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert!(LiveFrame::decode(&[]).is_err());
        assert!(LiveFrame::decode(&[KIND_RESIZE, 0, 80]).is_err());
        assert!(LiveFrame::decode(&[KIND_RESIZE, 0, 80, 0, 24, 9]).is_err());
        assert!(LiveFrame::decode(&[KIND_SNAPSHOT, 0, 80]).is_err());
        assert!(LiveFrame::decode(&[7]).is_err());
    }

    #[test]
    fn join_nonces_round_trip_as_base64() {
        let nonce = JoinNonce::generate();
        assert_eq!(JoinNonce::from_base64(&nonce.to_base64()), Some(nonce));
        assert_eq!(JoinNonce::from_base64("AAAA"), None);
    }

    #[test]
    fn debug_output_hides_the_keys() {
        assert_eq!(format!("{:?}", LiveKey::generate()), "LiveKey(…)");
        assert_eq!(format!("{:?}", ControlKey::generate()), "ControlKey(…)");
    }
}
