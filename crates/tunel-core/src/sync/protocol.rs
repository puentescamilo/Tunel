//! Mensajes JSON entre el cliente y el servidor de sincronización.
//!
//! Están aquí, y no en el servidor, para que los dos lados usen exactamente los mismos.

use super::keys::{SealedBlob, SealedRecord};
use crate::crypto::KdfParams;
use serde::{Deserialize, Serialize};

/// Registros que se pueden subir en una petición.
pub const MAX_PUSH_RECORDS: usize = 500;
/// Registros que devuelve como mucho cada página al descargar.
pub const PULL_PAGE_SIZE: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
}

/// Parámetros para derivar las claves de la cuenta antes de iniciar sesión.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginResponse {
    pub kdf: KdfParams,
    /// Sal en base64.
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub kdf: KdfParams,
    /// Sal en base64.
    pub salt: String,
    /// Clave de acceso en base64; el servidor solo guarda un hash.
    pub auth: String,
    /// Clave de bóveda envuelta con la clave de cifrado de la cuenta.
    pub vault_key: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    /// Se envía después como `Authorization: Bearer <token>`.
    pub token: String,
    pub vault_key: SealedBlob,
}

/// Manifiesto cifrado con su número de versión, que el servidor sí ve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBlob {
    pub version: u64,
    #[serde(flatten)]
    pub blob: SealedBlob,
}

/// Una página de cambios a partir de un cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    pub records: Vec<SealedRecord>,
    /// Cursor para pedir la página siguiente.
    pub cursor: u64,
    /// Hay más páginas.
    pub more: bool,
    /// Manifiesto actual; `None` si nadie ha subido nada todavía.
    pub manifest: Option<ManifestBlob>,
}

/// Subida de cambios. Solo se acepta si `base_version` es la versión actual del
/// manifiesto; si otro equipo subió algo antes, el servidor responde 409 y el cliente
/// tiene que descargar, fusionar y volver a intentarlo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub base_version: u64,
    pub manifest: ManifestBlob,
    pub records: Vec<SealedRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    pub cursor: u64,
}

/// Cuerpo de las respuestas de error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
