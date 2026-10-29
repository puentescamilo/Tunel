//! Sincronización de la bóveda entre equipos a través de un servidor que solo guarda
//! datos cifrados. La bóveda local sigue siendo la principal: funciona sin conexión y
//! sus cambios esperan en una cola hasta que el servidor está disponible.
//!
//! El servidor no puede leer ni falsificar registros. Lo que aún puede hacer, y se
//! resolverá con un manifiesto firmado junto al servidor, es devolver una versión antigua
//! de un registro a un equipo que no la conoce, o no entregarle alguno. Además, cualquier
//! equipo con la clave de bóveda puede escribir cualquier registro, incluidos los snippets
//! que se ejecutan al conectar.

pub mod hlc;
pub mod keys;
pub mod record;
pub mod state;

pub use hlc::Hlc;
pub use keys::{AccountKeys, RecordEnvelope, SealedBlob, SealedRecord, SyncCryptoError, VaultKey};
pub use record::{Change, RecordKey, RecordKind};
pub use state::SyncState;
