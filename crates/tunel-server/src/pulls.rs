//! Límite de descargas de registros a la vez. Una página ocupa memoria hasta que el
//! cliente termina de leerla, que puede ser mucho después de que el manejador responda:
//! el límite de peticiones a la vez no la cubre. El permiso de una descarga va dentro del
//! cuerpo de la respuesta y se suelta cuando el cuerpo se termina de enviar o se descarta.

use axum::body::Body;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Reparte los permisos de descarga: unos pocos por cuenta y un máximo entre todas.
pub(crate) struct PullLimiter {
    total: Arc<Semaphore>,
    per_account: usize,
    accounts: Arc<Mutex<HashMap<i64, usize>>>,
}

/// Permiso de una descarga en curso.
pub(crate) struct PullPermit {
    _total: OwnedSemaphorePermit,
    account: i64,
    accounts: Arc<Mutex<HashMap<i64, usize>>>,
}

impl PullLimiter {
    pub(crate) fn new(total: usize, per_account: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_account,
            accounts: Arc::default(),
        }
    }

    /// Un permiso para `account`, o `None` si esa cuenta o el servidor ya tienen todas
    /// las descargas que admiten.
    pub(crate) fn try_begin(&self, account: i64) -> Option<PullPermit> {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let running = accounts.entry(account).or_default();
        if *running >= self.per_account {
            return None;
        }
        let total = self.total.clone().try_acquire_owned().ok()?;
        *running += 1;
        Some(PullPermit {
            _total: total,
            account,
            accounts: self.accounts.clone(),
        })
    }
}

impl Drop for PullPermit {
    fn drop(&mut self) {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(running) = accounts.get_mut(&self.account) {
            *running -= 1;
            if *running == 0 {
                accounts.remove(&self.account);
            }
        }
    }
}

/// Respuesta JSON que conserva `permit` hasta que se termina de enviar.
pub(crate) fn json_holding<T: serde::Serialize>(
    value: &T,
    permit: PullPermit,
) -> Result<Response, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    let stream =
        futures_util::stream::once(async move { Ok::<_, Infallible>(bytes) }).map(move |chunk| {
            let _held = &permit;
            chunk
        });
    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Body::from_stream(stream),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_account_and_the_server_have_a_limit() {
        let limiter = PullLimiter::new(3, 2);
        let a1 = limiter.try_begin(1).unwrap();
        let _a2 = limiter.try_begin(1).unwrap();
        assert!(limiter.try_begin(1).is_none(), "la cuenta ya tiene dos");
        let _b1 = limiter.try_begin(2).unwrap();
        assert!(limiter.try_begin(3).is_none(), "el servidor ya tiene tres");
        drop(a1);
        assert!(
            limiter.try_begin(1).is_some(),
            "al acabar una se libera su sitio"
        );
    }

    #[tokio::test]
    async fn the_permit_lives_until_the_body_is_dropped() {
        let limiter = PullLimiter::new(1, 1);
        let response = json_holding(&"hola", limiter.try_begin(1).unwrap()).unwrap();
        assert!(limiter.try_begin(1).is_none(), "sin leer, sigue ocupado");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"\"hola\"");
        assert!(
            limiter.try_begin(1).is_some(),
            "leído y descartado, se libera"
        );
    }
}
