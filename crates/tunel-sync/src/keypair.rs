//! Par de claves de la cuenta, necesario para los equipos.
//!
//! El primer equipo que lo necesita lo crea y lo sube; los demás lo descargan. Las cuentas
//! creadas antes de los equipos lo reciben así en su siguiente sincronización, sin que
//! haga falta la contraseña: la clave privada va cifrada con la clave de bóveda.

use crate::SyncError;
use crate::api::Api;
use tunel_core::sync::protocol::AccountKeysBlob;
use tunel_core::sync::{AccountKeypair, VaultKey};

/// Recupera el par de la cuenta o, si todavía no tiene, crea uno y lo sube.
pub(crate) async fn fetch_or_create(
    api: &Api,
    token: &str,
    vault: &VaultKey,
) -> Result<AccountKeypair, SyncError> {
    if let Some(keys) = api.keys(token).await? {
        return open(&keys, vault);
    }
    let pair = AccountKeypair::generate();
    let blob = AccountKeysBlob {
        public_key: pair.public(),
        private_key: pair.seal(vault)?,
    };
    match api.upload_keys(token, &blob).await {
        Ok(()) => Ok(pair),
        // Otro equipo de la misma cuenta lo subió a la vez: vale el suyo.
        Err(SyncError::Conflict(_)) => match api.keys(token).await? {
            Some(keys) => open(&keys, vault),
            None => Err(SyncError::Misbehaving(
                "dice que la cuenta tiene claves pero no las devuelve",
            )),
        },
        Err(e) => Err(e),
    }
}

/// Como [`fetch_or_create`], pero sin fallar: un servidor anterior a los equipos no
/// tiene claves, y eso no impide sincronizar la bóveda personal. Se reintenta en la
/// siguiente ronda.
pub(crate) async fn try_fetch_or_create(
    api: &Api,
    token: &str,
    vault: &VaultKey,
) -> Option<AccountKeypair> {
    match fetch_or_create(api, token, vault).await {
        Ok(pair) => Some(pair),
        Err(e) => {
            tracing::warn!(error = %e, "no se pudo obtener el par de claves de la cuenta");
            None
        }
    }
}

fn open(keys: &AccountKeysBlob, vault: &VaultKey) -> Result<AccountKeypair, SyncError> {
    Ok(AccountKeypair::open(
        &keys.private_key,
        &keys.public_key,
        vault,
    )?)
}
