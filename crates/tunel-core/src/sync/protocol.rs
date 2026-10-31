//! Mensajes JSON entre el cliente y el servidor de sincronización.
//!
//! Están aquí, y no en el servidor, para que los dos lados usen exactamente los mismos.

use super::keys::{SealedBlob, SealedRecord};
use super::team::PublicKey;
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

/// Par de claves de la cuenta tal como lo guarda el servidor: la privada, cifrada con la
/// clave de la bóveda personal. Las cuentas creadas antes de los equipos no tienen uno
/// hasta que un equipo unido a ellas lo sube.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeysBlob {
    pub public_key: PublicKey,
    pub private_key: SealedBlob,
}

/// Clave pública de otra cuenta, para invitarla a un equipo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserKeyResponse {
    pub email: String,
    pub public_key: PublicKey,
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
    /// Época de la clave con la que están cifrados los registros de un equipo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

/// Subida de cambios. Solo se acepta si `base_version` es la versión actual del
/// manifiesto; si otro equipo subió algo antes, el servidor responde 409 y el cliente
/// tiene que descargar, fusionar y volver a intentarlo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub base_version: u64,
    pub manifest: ManifestBlob,
    pub records: Vec<SealedRecord>,
    /// En un equipo, época de la clave con la que se cifró; si ya hay otra, el servidor
    /// responde 409 y el cliente tiene que recuperar la clave nueva.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    pub cursor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeamRole {
    /// Invita, expulsa, cambia roles y renueva la clave del equipo.
    Admin,
    Member,
}

/// Un equipo del que la cuenta es miembro, con su clave envuelta para ella.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamSummary {
    /// UUID que elige quien crea el equipo.
    pub id: String,
    /// Nombre cifrado con la clave del equipo; `None` en una invitación pendiente.
    pub name: Option<SealedBlob>,
    pub role: TeamRole,
    pub epoch: u64,
    /// Clave del equipo envuelta para esta cuenta; `None` en una invitación pendiente,
    /// así quien la rechaza nunca tuvo la clave y no hace falta renovarla.
    pub key: Option<SealedBlob>,
    /// Administrador que la envolvió, y su clave pública, para abrirla.
    pub wrapped_by: String,
    pub wrapped_by_key: PublicKey,
    /// Invitación que la cuenta todavía no ha aceptado: solo sabe quién la invita.
    #[serde(default)]
    pub pending: bool,
    /// Alguien salió y la clave está pendiente de renovar; lo hace un administrador.
    #[serde(default)]
    pub rekey_needed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTeamRequest {
    pub id: String,
    pub name: SealedBlob,
    /// Clave del equipo envuelta por y para quien lo crea, en la época 0.
    pub key: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamMember {
    pub email: String,
    pub role: TeamRole,
    pub public_key: PublicKey,
    /// Invitado que todavía no ha aceptado.
    #[serde(default)]
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub role: TeamRole,
    /// Época de la clave envuelta; tiene que ser la actual.
    pub epoch: u64,
    pub key: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: TeamRole,
}

/// Clave nueva del equipo envuelta para un miembro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberKey {
    pub email: String,
    pub key: SealedBlob,
}

/// Renueva la clave del equipo: sustituye todos sus registros por los mismos cifrados
/// con la clave nueva, en una sola operación. Se hace al sacar a alguien.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateTeamRequest {
    /// Época nueva: la actual más uno.
    pub epoch: u64,
    /// Versión actual del manifiesto; el nuevo es la siguiente.
    pub base_version: u64,
    pub name: SealedBlob,
    /// Una por cada miembro actual, ni más ni menos.
    pub keys: Vec<MemberKey>,
    pub manifest: ManifestBlob,
    pub records: Vec<SealedRecord>,
}

/// Cuerpo de las respuestas de error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Anuncia una sesión compartida con un Team. El anuncio va cifrado con la clave del Team
/// en la época indicada (ver [`super::live`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveAnnouncement {
    pub epoch: u64,
    pub meta: SealedBlob,
}

/// Abre una sesión compartida. El identificador lo elige quien comparte, un UUID, porque
/// el anuncio va cifrado ligado a él.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateLiveRequest {
    pub id: String,
    #[serde(flatten)]
    pub announcement: LiveAnnouncement,
}

/// Una sesión compartida en curso, tal como la ven los miembros del Team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveSummary {
    pub id: String,
    /// Correo de quien comparte.
    pub owner: String,
    pub epoch: u64,
    pub meta: SealedBlob,
    /// Personas mirando ahora mismo.
    pub viewers: u32,
}

/// Identifica, dentro de una sesión, la conexión de cada persona que mira.
pub type ConnId = u32;

/// Mensajes de quien comparte al servidor, por WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HostMessage {
    /// Fotograma para todos los que miran.
    Output {
        frame: SealedBlob,
    },
    /// La pantalla para quien acaba de llegar.
    Join {
        to: ConnId,
        frame: SealedBlob,
    },
    /// Da el control a una persona con la clave de control envuelta para ella.
    Grant {
        to: ConnId,
        grant: u64,
        key: SealedBlob,
    },
    Revoke {
        to: ConnId,
    },
    /// Echa a una persona de la sesión.
    Kick {
        to: ConnId,
    },
}

/// Mensajes del servidor a quien comparte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HostEvent {
    /// Llega alguien; `nonce` es el número aleatorio con que se conectó, en base64.
    Joined {
        conn: ConnId,
        email: String,
        nonce: String,
    },
    Left {
        conn: ConnId,
    },
    /// La persona pide el control.
    Request {
        conn: ConnId,
    },
    /// Lo que escribe una persona con el control, cifrado con su clave de control.
    Input {
        conn: ConnId,
        frame: SealedBlob,
    },
}

/// Mensajes de quien mira al servidor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ViewerMessage {
    Request,
    Input { frame: SealedBlob },
}

/// Mensajes del servidor a quien mira.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ViewerEvent {
    Output { frame: SealedBlob },
    Join { frame: SealedBlob },
    Grant { grant: u64, key: SealedBlob },
    Revoke,
}

/// Un proveedor de identidad (Google, Microsoft 365, OpenID Connect) configurado en el
/// servidor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProvider {
    /// Identificador para las rutas: `google`, `microsoft` u `oidc`.
    pub id: String,
    /// Nombre para el botón, como «Google».
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthProviders {
    pub providers: Vec<AuthProvider>,
}

/// Canjea el código que el servidor dejó en el equipo al terminar el inicio de sesión
/// con el proveedor. `verifier` demuestra que lo pide quien empezó (PKCE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTokenRequest {
    pub code: String,
    pub verifier: String,
}

/// Resultado de iniciar sesión con un proveedor de identidad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "estado", rename_all = "snake_case")]
pub enum OAuthLogin {
    /// La cuenta ya existe: su sesión y la clave de bóveda, envuelta con la clave que sale
    /// de la contraseña maestra de Túnel.
    Existing {
        email: String,
        token: String,
        kdf: KdfParams,
        /// Sal en base64.
        salt: String,
        vault_key: SealedBlob,
    },
    /// No hay cuenta con ese correo y se puede crear con `ticket` (ver
    /// [`OAuthRegisterRequest`]).
    New { email: String, ticket: String },
}

/// Crea la cuenta de quien inició sesión con un proveedor de identidad. No lleva clave
/// de acceso: la identidad la confirmó el proveedor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthRegisterRequest {
    pub ticket: String,
    pub kdf: KdfParams,
    /// Sal en base64.
    pub salt: String,
    /// Clave de bóveda envuelta con la clave que sale de la contraseña maestra.
    pub vault_key: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthRegisterResponse {
    pub token: String,
}

/// Vuelve a envolver la clave de bóveda de una cuenta de proveedor de identidad, al
/// cambiar la contraseña maestra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyUpdate {
    /// La clave envuelta que se sustituye, tal como se recibió al iniciar sesión: sin ella
    /// no se puede cambiar, así una sesión robada no basta para dejar la bóveda inservible.
    pub previous: SealedBlob,
    pub kdf: KdfParams,
    /// Sal en base64.
    pub salt: String,
    pub vault_key: SealedBlob,
}
