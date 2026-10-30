//! Sesión con el servidor que se renueva sola con la clave de acceso guardada.

use crate::SyncError;
use crate::api::{Api, ServerUrl};
use tunel_core::sync::SyncLocal;
use zeroize::Zeroizing;

pub(crate) struct Session {
    pub api: Api,
    email: String,
    auth: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}

impl Session {
    pub fn new(local: &SyncLocal) -> Result<Self, SyncError> {
        let server: ServerUrl = crate::check_server_url(&local.server)?;
        Ok(Self {
            api: Api::new(&server)?,
            email: local.email.clone(),
            auth: local.auth.clone(),
            token: local.token.clone(),
        })
    }

    /// Token vigente, para guardarlo en la configuración al terminar.
    pub fn into_token(self) -> Option<Zeroizing<String>> {
        self.token
    }

    pub async fn token(&mut self) -> Result<Zeroizing<String>, SyncError> {
        if let Some(token) = &self.token {
            return Ok(token.clone());
        }
        let session = self.api.login(&self.email, &self.auth).await?;
        let token = Zeroizing::new(session.token);
        self.token = Some(token.clone());
        Ok(token)
    }

    /// Inicia sesión de nuevo con la clave guardada: el token caducó o se revocó.
    pub async fn renew(&mut self) -> Result<Zeroizing<String>, SyncError> {
        self.token = None;
        self.token().await
    }
}

/// Hace una llamada con el token de la sesión; si caducó o se revocó, inicia sesión de
/// nuevo con la clave guardada y la repite una vez. Es una macro y no una función con un
/// cierre asíncrono porque el futuro resultante tiene que ser `Send`.
macro_rules! call {
    ($session:expr, |$api:ident, $token:ident| $body:expr) => {{
        let session: &mut $crate::session::Session = $session;
        let first = session.token().await?;
        let result = {
            let $api = &session.api;
            let $token: &str = &first;
            $body.await
        };
        match result {
            Err($crate::SyncError::Unauthorized) => {
                let renewed = session.renew().await?;
                let $api = &session.api;
                let $token: &str = &renewed;
                $body.await
            }
            other => other,
        }
    }};
}
pub(crate) use call;
