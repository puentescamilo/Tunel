//! Llamadas HTTP al servidor de sincronización.

use crate::SyncError;
use reqwest::{Client, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::net::IpAddr;
use std::time::Duration;
use tunel_core::sync::protocol::*;

const TIMEOUT: Duration = Duration::from_secs(30);
/// Los mensajes de error del servidor se muestran en la interfaz: se recortan.
const MAX_ERROR_MESSAGE: usize = 200;

/// URL del servidor ya comprobada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    /// URL base sin barra final.
    pub base: String,
    /// `true` si se habla HTTP sin cifrar (solo se admite en el propio equipo o en la red local).
    pub plaintext: bool,
}

fn is_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unique_local(),
        Err(_) => false,
    }
}

/// Comprueba la URL que escribe el usuario. Exige HTTPS salvo para el propio equipo o una
/// IP de la red local, porque por HTTP la clave de acceso y el token viajan sin cifrar.
pub fn check_server_url(text: &str) -> Result<ServerUrl, SyncError> {
    let invalid = |why: &str| SyncError::InvalidServer(why.to_string());
    let url = Url::parse(text.trim()).map_err(|_| invalid("la dirección no es válida"))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid("falta el nombre del servidor"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(
            "la dirección no puede llevar usuario ni contraseña",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("la dirección no puede llevar parámetros"));
    }
    let plaintext = match url.scheme() {
        "https" => false,
        "http" if is_local(host) => true,
        "http" => {
            return Err(invalid(
                "usa https://; http:// solo se admite en este equipo o en la red local",
            ));
        }
        _ => return Err(invalid("la dirección debe empezar por https://")),
    };
    Ok(ServerUrl {
        base: url.as_str().trim_end_matches('/').to_string(),
        plaintext,
    })
}

pub struct Api {
    client: Client,
    base: String,
}

impl Api {
    pub fn new(server: &ServerUrl) -> Result<Self, SyncError> {
        // Sin redirecciones: solo se comprobó la URL original, y seguir una podría reenviar
        // la clave de acceso a otro sitio o por HTTP.
        let client = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!server.plaintext)
            .user_agent(concat!("Tunel/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(SyncError::Network)?;
        Ok(Self {
            client,
            base: server.base.clone(),
        })
    }

    /// Envía la petición y convierte las respuestas de error en [`SyncError`].
    async fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, SyncError> {
        let response = request.send().await.map_err(SyncError::Network)?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let message = response
            .json::<ErrorResponse>()
            .await
            .map(|e| e.error.chars().take(MAX_ERROR_MESSAGE).collect())
            .unwrap_or_default();
        Err(match status {
            StatusCode::UNAUTHORIZED => SyncError::Unauthorized,
            StatusCode::CONFLICT => SyncError::Conflict(message),
            StatusCode::TOO_MANY_REQUESTS => SyncError::TooManyAttempts,
            StatusCode::FORBIDDEN => SyncError::RegistrationClosed,
            StatusCode::SERVICE_UNAVAILABLE => SyncError::Busy,
            StatusCode::INSUFFICIENT_STORAGE => SyncError::QuotaExceeded,
            other => SyncError::Server {
                status: other.as_u16(),
                message,
            },
        })
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, SyncError> {
        self.execute(request)
            .await?
            .json()
            .await
            .map_err(SyncError::Network)
    }

    fn post<B: Serialize>(&self, path: &str, body: &B) -> reqwest::RequestBuilder {
        self.client.post(format!("{}{path}", self.base)).json(body)
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, SyncError> {
        self.send(self.post(
            "/v1/prelogin",
            &PreloginRequest {
                email: email.into(),
            },
        ))
        .await
    }

    pub async fn register(&self, request: &RegisterRequest) -> Result<(), SyncError> {
        match self.execute(self.post("/v1/accounts", request)).await {
            Ok(_) => Ok(()),
            Err(SyncError::Conflict(_)) => Err(SyncError::AccountExists),
            Err(e) => Err(e),
        }
    }

    pub async fn login(&self, email: &str, auth: &str) -> Result<LoginResponse, SyncError> {
        self.send(self.post(
            "/v1/sessions",
            &LoginRequest {
                email: email.into(),
                auth: auth.into(),
            },
        ))
        .await
    }

    pub async fn logout(&self, token: &str) -> Result<(), SyncError> {
        self.execute(
            self.client
                .delete(format!("{}/v1/sessions/current", self.base))
                .bearer_auth(token),
        )
        .await
        .map(|_| ())
    }

    pub async fn pull(&self, token: &str, since: u64) -> Result<PullResponse, SyncError> {
        self.send(
            self.client
                .get(format!("{}/v1/records?since={since}", self.base))
                .bearer_auth(token),
        )
        .await
    }

    pub async fn push(
        &self,
        token: &str,
        request: &PushRequest,
    ) -> Result<PushResponse, SyncError> {
        self.send(self.post("/v1/records", request).bearer_auth(token))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_accepted_and_normalised() {
        let url = check_server_url(" https://tunel.ejemplo.com/ ").unwrap();
        assert_eq!(url.base, "https://tunel.ejemplo.com");
        assert!(!url.plaintext);
        assert_eq!(
            check_server_url("https://ejemplo.com/tunel/").unwrap().base,
            "https://ejemplo.com/tunel"
        );
    }

    #[test]
    fn plain_http_only_for_this_machine_or_the_local_network() {
        for local in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://192.168.1.20:8080",
            "http://10.0.0.5",
            "http://172.16.10.153:8080",
            "http://[::1]:8080",
        ] {
            assert!(check_server_url(local).unwrap().plaintext, "{local}");
        }
        for remote in [
            "http://tunel.ejemplo.com",
            "http://8.8.8.8",
            "ftp://x",
            "tunel.com",
            "",
        ] {
            assert!(check_server_url(remote).is_err(), "{remote}");
        }
    }

    #[test]
    fn credentials_and_parameters_in_the_url_are_rejected() {
        assert!(check_server_url("https://ana:clave@ejemplo.com").is_err());
        assert!(check_server_url("https://ejemplo.com/?x=1").is_err());
    }
}
