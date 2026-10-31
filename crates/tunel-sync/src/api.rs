//! Llamadas HTTP al servidor de sincronización.

use crate::SyncError;
use reqwest::{Client, StatusCode, Url};
use reqwest_websocket::{Upgrade, WebSocket};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::net::IpAddr;
use std::time::Duration;
use tunel_core::sync::live::JoinNonce;
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

/// Los errores de red se muestran en la interfaz: sin la dirección del servidor, que la
/// interfaz oculta como si fuera una contraseña.
fn network(error: reqwest::Error) -> SyncError {
    SyncError::Network(error.without_url())
}

pub struct Api {
    client: Client,
    /// Para los WebSocket de las sesiones compartidas: solo HTTP/1.1, que es donde existe
    /// la actualización a WebSocket, y sin tiempo total, porque la conexión dura lo que la
    /// sesión.
    live: Client,
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
            .map_err(network)?;
        let live = Client::builder()
            .http1_only()
            .connect_timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!server.plaintext)
            .user_agent(concat!("Tunel/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(network)?;
        Ok(Self {
            client,
            live,
            base: server.base.clone(),
        })
    }

    /// Envía la petición y convierte las respuestas de error en [`SyncError`].
    async fn execute(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, SyncError> {
        let response = request.send().await.map_err(network)?;
        if response.status().is_success() {
            return Ok(response);
        }
        Err(error_from(response).await)
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, SyncError> {
        self.execute(request).await?.json().await.map_err(network)
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
            Err(SyncError::Forbidden(message)) => Err(SyncError::RegistrationClosed(message)),
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

    fn get(&self, token: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}{path}", self.base))
            .bearer_auth(token)
    }

    /// Ruta de los registros de la bóveda personal (`team` es `None`) o de un equipo.
    fn records_path(team: Option<&str>) -> String {
        match team {
            None => "/v1/records".into(),
            Some(team) => format!("/v1/teams/{}/records", segment(team)),
        }
    }

    pub async fn pull(
        &self,
        token: &str,
        team: Option<&str>,
        since: u64,
    ) -> Result<PullResponse, SyncError> {
        let path = format!("{}?since={since}", Self::records_path(team));
        self.send(self.get(token, &path)).await
    }

    pub async fn push(
        &self,
        token: &str,
        team: Option<&str>,
        request: &PushRequest,
    ) -> Result<PushResponse, SyncError> {
        self.send(
            self.post(&Self::records_path(team), request)
                .bearer_auth(token),
        )
        .await
    }

    /// Par de claves de la cuenta; `None` si todavía no se ha subido ninguno.
    pub async fn keys(&self, token: &str) -> Result<Option<AccountKeysBlob>, SyncError> {
        match self.send(self.get(token, "/v1/keys")).await {
            Ok(keys) => Ok(Some(keys)),
            Err(SyncError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn upload_keys(&self, token: &str, keys: &AccountKeysBlob) -> Result<(), SyncError> {
        let request = self
            .client
            .put(format!("{}/v1/keys", self.base))
            .bearer_auth(token)
            .json(keys);
        self.execute(request).await.map(|_| ())
    }

    pub async fn user_key(&self, token: &str, email: &str) -> Result<UserKeyResponse, SyncError> {
        let path = format!("/v1/users/{}/key", segment(email));
        self.send(self.get(token, &path)).await
    }

    pub async fn teams(&self, token: &str) -> Result<Vec<TeamSummary>, SyncError> {
        self.send(self.get(token, "/v1/teams")).await
    }

    pub async fn create_team(
        &self,
        token: &str,
        request: &CreateTeamRequest,
    ) -> Result<(), SyncError> {
        let request = self.post("/v1/teams", request).bearer_auth(token);
        self.execute(request).await.map(|_| ())
    }

    pub async fn accept(&self, token: &str, team: &str) -> Result<(), SyncError> {
        let path = format!("/v1/teams/{}/accept", segment(team));
        self.execute(self.post(&path, &()).bearer_auth(token))
            .await
            .map(|_| ())
    }

    pub async fn delete_team(&self, token: &str, team: &str) -> Result<(), SyncError> {
        let request = self
            .client
            .delete(format!("{}/v1/teams/{}", self.base, segment(team)))
            .bearer_auth(token);
        self.execute(request).await.map(|_| ())
    }

    pub async fn members(&self, token: &str, team: &str) -> Result<Vec<TeamMember>, SyncError> {
        let path = format!("/v1/teams/{}/members", segment(team));
        self.send(self.get(token, &path)).await
    }

    pub async fn add_member(
        &self,
        token: &str,
        team: &str,
        request: &AddMemberRequest,
    ) -> Result<(), SyncError> {
        let path = format!("/v1/teams/{}/members", segment(team));
        self.execute(self.post(&path, request).bearer_auth(token))
            .await
            .map(|_| ())
    }

    fn member_url(&self, team: &str, email: &str) -> String {
        format!(
            "{}/v1/teams/{}/members/{}",
            self.base,
            segment(team),
            segment(email)
        )
    }

    pub async fn set_role(
        &self,
        token: &str,
        team: &str,
        email: &str,
        role: TeamRole,
    ) -> Result<(), SyncError> {
        let request = self
            .client
            .patch(self.member_url(team, email))
            .bearer_auth(token)
            .json(&UpdateMemberRequest { role });
        self.execute(request).await.map(|_| ())
    }

    pub async fn remove_member(
        &self,
        token: &str,
        team: &str,
        email: &str,
    ) -> Result<(), SyncError> {
        let request = self
            .client
            .delete(self.member_url(team, email))
            .bearer_auth(token);
        self.execute(request).await.map(|_| ())
    }

    pub async fn rotate_team(
        &self,
        token: &str,
        team: &str,
        request: &RotateTeamRequest,
    ) -> Result<PushResponse, SyncError> {
        let path = format!("/v1/teams/{}/rotate", segment(team));
        self.send(self.post(&path, request).bearer_auth(token))
            .await
    }

    /// Proveedores de identidad del servidor. Uno anterior a ellos no tiene la ruta: se
    /// toma como que no hay ninguno.
    pub async fn auth_providers(&self) -> Result<Vec<AuthProvider>, SyncError> {
        let request = self.client.get(format!("{}/v1/auth/providers", self.base));
        match self.send::<AuthProviders>(request).await {
            Ok(list) => Ok(list.providers),
            Err(SyncError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Dirección que se abre en el navegador para iniciar sesión con `provider`.
    pub fn oauth_start_url(
        &self,
        provider: &str,
        port: u16,
        challenge: &str,
        state: &str,
    ) -> String {
        format!(
            "{}/v1/auth/{}/start?port={port}&challenge={challenge}&state={state}",
            self.base,
            segment(provider)
        )
    }

    pub async fn oauth_token(&self, request: &OAuthTokenRequest) -> Result<OAuthLogin, SyncError> {
        self.send(self.post("/v1/auth/token", request)).await
    }

    pub async fn oauth_register(
        &self,
        request: &OAuthRegisterRequest,
    ) -> Result<OAuthRegisterResponse, SyncError> {
        self.send(self.post("/v1/accounts/oauth", request)).await
    }

    pub async fn update_vault_key(
        &self,
        token: &str,
        update: &VaultKeyUpdate,
    ) -> Result<(), SyncError> {
        let request = self
            .client
            .put(format!("{}/v1/accounts/current/vault-key", self.base))
            .bearer_auth(token)
            .json(update);
        self.execute(request).await.map(|_| ())
    }

    fn live_path(team: &str) -> String {
        format!("/v1/teams/{}/live", segment(team))
    }

    pub async fn live_sessions(
        &self,
        token: &str,
        team: &str,
    ) -> Result<Vec<LiveSummary>, SyncError> {
        self.send(self.get(token, &Self::live_path(team))).await
    }

    pub async fn create_live(
        &self,
        token: &str,
        team: &str,
        request: &CreateLiveRequest,
    ) -> Result<(), SyncError> {
        let request = self
            .post(&Self::live_path(team), request)
            .bearer_auth(token);
        self.execute(request).await.map(|_| ())
    }

    pub async fn update_live(
        &self,
        token: &str,
        team: &str,
        id: &str,
        announcement: &LiveAnnouncement,
    ) -> Result<(), SyncError> {
        let url = format!("{}{}/{}", self.base, Self::live_path(team), segment(id));
        let request = self.client.put(url).bearer_auth(token).json(announcement);
        self.execute(request).await.map(|_| ())
    }

    pub async fn delete_live(&self, token: &str, team: &str, id: &str) -> Result<(), SyncError> {
        let url = format!("{}{}/{}", self.base, Self::live_path(team), segment(id));
        self.execute(self.client.delete(url).bearer_auth(token))
            .await
            .map(|_| ())
    }

    /// Abre el WebSocket de una sesión compartida, como quien la comparte o como quien
    /// la mira.
    pub async fn connect_live(
        &self,
        token: &str,
        team: &str,
        id: &str,
        role: LiveRole,
    ) -> Result<WebSocket, SyncError> {
        let role = match role {
            LiveRole::Host => "host".to_string(),
            LiveRole::Watch(nonce) => format!("watch?nonce={}", nonce.to_base64()),
        };
        let url = format!(
            "{}{}/{}/{role}",
            self.base,
            Self::live_path(team),
            segment(id)
        );
        let response = self
            .live
            .get(url)
            .bearer_auth(token)
            .upgrade()
            .send()
            .await
            .map_err(live_error)?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(error_from(response.into_inner()).await);
        }
        response.into_websocket().await.map_err(live_error)
    }
}

/// Con qué papel se conecta una cuenta a una sesión compartida.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveRole {
    Host,
    /// Quien mira llega con un número aleatorio (ver [`JoinNonce`]).
    Watch(JoinNonce),
}

/// Los errores del WebSocket, sin la dirección del servidor.
pub(crate) fn live_error(error: reqwest_websocket::Error) -> SyncError {
    match error {
        reqwest_websocket::Error::Reqwest(e) => network(e),
        other => SyncError::Live(other.to_string()),
    }
}

/// Convierte una respuesta de error del servidor en [`SyncError`].
async fn error_from(response: reqwest::Response) -> SyncError {
    let status = response.status();
    let message = response
        .json::<ErrorResponse>()
        .await
        .map(|e| e.error.chars().take(MAX_ERROR_MESSAGE).collect())
        .unwrap_or_default();
    match status {
        StatusCode::UNAUTHORIZED => SyncError::Unauthorized,
        StatusCode::CONFLICT => SyncError::Conflict(message),
        StatusCode::TOO_MANY_REQUESTS => SyncError::TooManyAttempts,
        StatusCode::FORBIDDEN => SyncError::Forbidden(message),
        StatusCode::SERVICE_UNAVAILABLE => SyncError::Busy,
        StatusCode::INSUFFICIENT_STORAGE => SyncError::QuotaExceeded,
        StatusCode::NOT_FOUND => SyncError::NotFound(message),
        StatusCode::LOCKED => SyncError::RekeyNeeded,
        other => SyncError::Server {
            status: other.as_u16(),
            message,
        },
    }
}

/// Codifica un trozo de ruta: un correo o identificador no puede añadir segmentos. Los
/// puntos también, porque `..` se resolvería como «subir un nivel».
fn segment(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'~' | b'@' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
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
    fn path_segments_cannot_escape_their_route() {
        assert_eq!(segment("ana@ejemplo.com"), "ana@ejemplo%2Ecom");
        assert_eq!(segment("../x?y#z"), "%2E%2E%2Fx%3Fy%23z");
        assert_eq!(segment("a b"), "a%20b");
    }

    #[test]
    fn credentials_and_parameters_in_the_url_are_rejected() {
        assert!(check_server_url("https://ana:clave@ejemplo.com").is_err());
        assert!(check_server_url("https://ejemplo.com/?x=1").is_err());
    }
}
