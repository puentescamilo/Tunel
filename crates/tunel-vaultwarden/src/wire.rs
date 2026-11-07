//! Lo que viaja por la red, tal como lo escribe Vaultwarden. Los textos de los elementos van
//! cifrados (EncString); se descifran en [`crate::vault`].

use serde::{Deserialize, Serialize};

/// Los tipos de elemento de Bitwarden que usa Túnel; el resto (tarjetas, notas, identidades
/// personales) se ignora sin descifrarlo.
pub const LOGIN: u8 = 1;
pub const SSH_KEY: u8 = 5;

/// Tipo de campo personalizado oculto.
pub const HIDDEN_FIELD: u8 = 1;
/// Política «Quitar la bóveda individual»: solo se guarda en colecciones.
pub const PERSONAL_OWNERSHIP_POLICY: u8 = 5;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: u8,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    /// La clave de usuario cifrada con la clave maestra. Falta si la cuenta no tiene
    /// contraseña maestra (SSO con dispositivos de confianza).
    #[serde(rename = "Key", alias = "key")]
    pub key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub collections: Vec<CollectionData>,
    #[serde(default)]
    pub ciphers: Vec<CipherData>,
    #[serde(default)]
    pub policies: Vec<PolicyData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyData {
    #[serde(rename = "type")]
    pub kind: u8,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    /// Id del usuario: va en `encryptedFor` al crear elementos.
    #[serde(default)]
    pub id: String,
    pub private_key: Option<String>,
    #[serde(default)]
    pub organizations: Vec<OrganizationData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationData {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionData {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    #[serde(default)]
    pub hide_passwords: bool,
}

/// Un elemento, al leerlo y al crearlo.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    #[serde(default, skip_serializing)]
    pub id: String,
    #[serde(rename = "type")]
    pub kind: u8,
    pub organization_id: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub login: Option<LoginData>,
    pub ssh_key: Option<SshKeyData>,
    pub fields: Option<Vec<FieldData>>,
    /// Clave propia del elemento, cifrada con la del usuario o la de la organización.
    pub key: Option<String>,
    /// Quién cifró el elemento. Vaultwarden (desde web-v2025.6.0) lo exige al crear y
    /// responde 422 si falta o no es el usuario de la sesión.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_for: Option<String>,
    #[serde(skip_serializing)]
    pub deleted_date: Option<String>,
    #[serde(default, skip_serializing)]
    pub collection_ids: Vec<String>,
    /// Falso si la colección oculta las contraseñas a esta persona.
    #[serde(default = "yes", skip_serializing)]
    pub view_password: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<UriData>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UriData {
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyData {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FieldData {
    #[serde(rename = "type")]
    pub kind: u8,
    pub name: Option<String>,
    pub value: Option<String>,
}

/// Lo que se manda para crear un elemento en una organización.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCipher<'a> {
    pub cipher: &'a CipherData,
    pub collection_ids: &'a [String],
}

#[derive(Debug, Deserialize)]
pub struct Created {
    pub id: String,
}
