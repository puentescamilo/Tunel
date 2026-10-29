//! Crear una cuenta, unir un equipo a una existente y desvincularlo.

use crate::api::{Api, ServerUrl};
use crate::{SyncError, now_millis};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tunel_core::crypto::KdfParams;
use tunel_core::sync::keys::{MIN_SALT_LEN, kdf_is_strong};
use tunel_core::sync::protocol::RegisterRequest;
use tunel_core::sync::{AccountKeys, SyncLocal, SyncState, VaultKey};
use tunel_core::vault::VaultData;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Parámetros de Argon2id de las cuentas; el servidor solo admite estos.
const ACCOUNT_KDF: KdfParams = KdfParams::RECOMMENDED;

/// Un servidor malicioso podría pedir parámetros débiles para luego probar contraseñas a
/// bajo coste con la clave de acceso que recibe. No se acepta nada por debajo de los de
/// las cuentas.
fn kdf_acceptable(salt: &[u8], kdf: KdfParams) -> bool {
    kdf_is_strong(salt, kdf)
        && kdf.memory_kib >= ACCOUNT_KDF.memory_kib
        && kdf.iterations >= ACCOUNT_KDF.iterations
}

/// Argon2id con 64 MiB tarda: se calcula fuera del runtime asíncrono.
async fn derive(
    password: Zeroizing<String>,
    salt: Vec<u8>,
    kdf: KdfParams,
) -> Result<AccountKeys, SyncError> {
    tokio::task::spawn_blocking(move || AccountKeys::derive(password.as_bytes(), &salt, kdf))
        .await
        .map_err(|e| SyncError::Internal(e.to_string()))?
        .map_err(|e| match e {
            tunel_core::sync::SyncCryptoError::WeakKdf => SyncError::WeakKdf,
            other => other.into(),
        })
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Crea una cuenta nueva con el contenido actual de la bóveda, que queda pendiente de
/// subir, y devuelve la configuración de este equipo.
pub async fn create_account(
    server: &ServerUrl,
    email: &str,
    password: Zeroizing<String>,
    data: &VaultData,
) -> Result<SyncLocal, SyncError> {
    let api = Api::new(server)?;
    let email = normalize_email(email);
    let salt: [u8; MIN_SALT_LEN] = rand::random();
    let keys = derive(password, salt.to_vec(), ACCOUNT_KDF).await?;
    let vault_key = VaultKey::generate();
    api.register(&RegisterRequest {
        email: email.clone(),
        kdf: ACCOUNT_KDF,
        salt: B64.encode(salt),
        auth: keys.auth_token().to_string(),
        vault_key: vault_key.wrap(&keys)?,
    })
    .await?;
    let auth = keys.auth_token();
    let session = api.login(&email, &auth).await?;
    let device = Uuid::new_v4();
    Ok(SyncLocal {
        server: server.base.clone(),
        email,
        auth,
        vault_key,
        token: Some(Zeroizing::new(session.token)),
        state: SyncState::adopt(device, data, now_millis())?,
    })
}

/// Une este equipo a una cuenta existente. Lo que ya hubiera en la bóveda local se
/// combina con la de la cuenta en la primera sincronización.
pub async fn sign_in(
    server: &ServerUrl,
    email: &str,
    password: Zeroizing<String>,
    data: &VaultData,
) -> Result<SyncLocal, SyncError> {
    let api = Api::new(server)?;
    let email = normalize_email(email);
    let params = api.prelogin(&email).await?;
    let salt = B64
        .decode(&params.salt)
        .map_err(|_| SyncError::Internal("sal no válida".into()))?;
    if !kdf_acceptable(&salt, params.kdf) {
        return Err(SyncError::WeakKdf);
    }
    let keys = derive(password, salt, params.kdf).await?;
    let auth = keys.auth_token();
    let session = api.login(&email, &auth).await?;
    // Si la contraseña no es la de la cuenta, el servidor ya habría respondido 401; si
    // aun así no se puede abrir la clave, los datos del servidor están manipulados.
    let vault_key = VaultKey::unwrap(&session.vault_key, &keys)?;
    let device = Uuid::new_v4();
    Ok(SyncLocal {
        server: server.base.clone(),
        email,
        auth,
        vault_key,
        token: Some(Zeroizing::new(session.token)),
        state: SyncState::adopt(device, data, now_millis())?,
    })
}

/// Cierra la sesión en el servidor. Si no hay conexión no pasa nada: el token caduca.
pub async fn sign_out(local: &SyncLocal) -> Result<(), SyncError> {
    let server = crate::check_server_url(&local.server)?;
    match &local.token {
        Some(token) => Api::new(&server)?.logout(token).await,
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weaker_parameters_than_the_accounts_are_refused() {
        let salt = [0u8; MIN_SALT_LEN];
        assert!(kdf_acceptable(&salt, ACCOUNT_KDF));
        let weaker = KdfParams {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        };
        assert!(!kdf_acceptable(&salt, weaker));
        assert!(!kdf_acceptable(&salt[..8], ACCOUNT_KDF));
    }
}
