//! Sincronización de la bóveda entre equipos a través de un servidor que solo guarda
//! datos cifrados. La bóveda local sigue siendo la principal: funciona sin conexión y
//! sus cambios esperan en una cola hasta que el servidor está disponible.
//!
//! El servidor no puede leer ni falsificar registros, y el [`manifest::Manifest`] delata
//! que oculte alguno o devuelva una versión antigua. Sí puede negarse a responder, y a un
//! equipo que nunca ha sincronizado puede darle un manifiesto antiguo pero completo.
//! Cualquier equipo con la clave de bóveda puede escribir cualquier registro, incluidos los
//! snippets que se ejecutan al conectar.

pub mod hlc;
pub mod keys;
pub mod local;
pub mod manifest;
pub mod protocol;
pub mod record;
pub mod space;
pub mod state;
pub mod team;

pub use hlc::Hlc;
pub use keys::{AccountKeys, RecordEnvelope, SealedBlob, SealedRecord, SyncCryptoError, VaultKey};
pub use local::{Contact, Invitation, KeyChanged, SyncLocal, TeamLocal};
pub use manifest::{Manifest, ManifestError};
pub use record::{Change, RecordKey, RecordKind};
pub use state::SyncState;
pub use team::{AccountKeypair, PublicKey, TeamKeyContext};
