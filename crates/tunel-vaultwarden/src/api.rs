//! Llamadas HTTP a Vaultwarden. No descifran nada: devuelven lo que manda el servidor.

use crate::VwError;
use crate::crypto::Kdf;
use crate::wire::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
use serde_json::Value;
use std::net::IpAddr;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
/// Los mensajes del servidor se muestran en la interfaz: se recortan.
const MAX_MESSAGE: usize = 200;
/// Vaultwarden solo manda los elementos de tipo *SSH Key* a clientes de esta versión o más.
const CLIENT_VERSION: &str = "2024.12.0";
const CLIENT_ID: &str = "desktop";

/// El tipo de dispositivo de Bitwarden de la app de escritorio de cada sistema.
const DEVICE_TYPE: u8 = if cfg!(target_os = "windows") {
    6
} else if cfg!(target_os = "macos") {
    7
} else {
    8
};

/// Este equipo, tal como lo ve Vaultwarden en la lista de dispositivos de la cuenta. El
/// identificador debe ser siempre el mismo en el mismo equipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
}

/// URL del servidor ya comprobada, sin barra final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    base: String,
    plaintext: bool,
}

impl ServerUrl {
    pub fn as_str(&self) -> &str {
        &self.base
    }
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

/// Comprueba la dirección que escribe el usuario, con las mismas reglas que la del servidor
/// de sincronización: HTTPS salvo en este equipo o en la red local.
pub fn check_server_url(text: &str) -> Result<ServerUrl, VwError> {
    let invalid = |why: &str| VwError::InvalidServer(why.to_string());
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

/// Sin la dirección del servidor: la interfaz la oculta como si fuera una contraseña.
fn network(error: reqwest::Error) -> VwError {
    VwError::Network(error.without_url())
}

#[derive(Clone)]
pub struct Api {
    client: Client,
    base: String,
}

impl Api {
    pub fn new(server: &ServerUrl) -> Result<Self, VwError> {
        let mut headers = HeaderMap::new();
        headers.insert("Bitwarden-Client-Name", HeaderValue::from_static(CLIENT_ID));
        headers.insert(
            "Bitwarden-Client-Version",
            HeaderValue::from_static(CLIENT_VERSION),
        );
        headers.insert("Device-Type", HeaderValue::from(u16::from(DEVICE_TYPE)));
        // Sin redirecciones: solo se comprobó la URL original, y seguir una podría reenviar
        // el hash de la contraseña o el token a otro sitio o por HTTP.
        let client = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!server.plaintext)
            .user_agent(concat!("Tunel/", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .build()
            .map_err(network)?;
        Ok(Self {
            client,
            base: server.base.clone(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn execute(&self, request: RequestBuilder) -> Result<Response, VwError> {
        let response = request.send().await.map_err(network)?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = response.json::<Value>().await.unwrap_or(Value::Null);
        Err(error_from(status, &body))
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, VwError> {
        self.execute(request)
            .await?
            .json()
            .await
            .map_err(|_| VwError::Unexpected)
    }

    pub async fn prelogin(&self, email: &str) -> Result<Kdf, VwError> {
        let body = serde_json::json!({ "email": email });
        let res: PreloginResponse = self
            .json(
                self.client
                    .post(self.url("/identity/accounts/prelogin"))
                    .json(&body),
            )
            .await?;
        kdf_from(&res)
    }

    /// Pide un token. `fields` son los campos del formulario propios de cada forma de entrar.
    pub async fn token(
        &self,
        fields: &[(&str, &str)],
        device: &Device,
        email: Option<&str>,
    ) -> Result<TokenResponse, VwError> {
        let device_type = DEVICE_TYPE.to_string();
        let mut form: Vec<(&str, &str)> = vec![
            ("client_id", CLIENT_ID),
            ("deviceType", &device_type),
            ("deviceIdentifier", &device.id),
            ("deviceName", &device.name),
        ];
        form.extend_from_slice(fields);
        let mut request = self
            .client
            .post(self.url("/identity/connect/token"))
            .form(&form);
        if let Some(email) = email {
            request = request.header("Auth-Email", URL_SAFE_NO_PAD.encode(email));
        }
        // Vaultwarden responde a una contraseña incorrecta con 400 y `"error": ""` en vez de
        // `invalid_grant`: en este punto cualquier 400 es un rechazo.
        match self.json(request).await {
            Err(VwError::Server {
                status: 400,
                message,
            }) => Err(VwError::Rejected(message)),
            other => other,
        }
    }

    /// Pide al servidor que mande por correo el código del segundo factor.
    pub async fn send_email_code(
        &self,
        email: &str,
        password_hash: &str,
        device: &Device,
    ) -> Result<(), VwError> {
        let body = serde_json::json!({
            "email": email,
            "masterPasswordHash": password_hash,
            "deviceIdentifier": device.id,
        });
        self.execute(
            self.client
                .post(self.url("/api/two-factor/send-email-login"))
                .json(&body),
        )
        .await
        .map(drop)
    }

    pub async fn sync(&self, token: &str) -> Result<SyncResponse, VwError> {
        self.json(
            self.client
                .get(self.url("/api/sync?excludeDomains=true"))
                .bearer_auth(token),
        )
        .await
    }

    /// Crea un elemento y devuelve su id. Con colecciones, va a la organización del elemento.
    pub async fn create(
        &self,
        token: &str,
        cipher: &CipherData,
        collection_ids: &[String],
    ) -> Result<String, VwError> {
        let request = if cipher.organization_id.is_some() {
            self.client
                .post(self.url("/api/ciphers/create"))
                .json(&OrganizationCipher {
                    cipher,
                    collection_ids,
                })
        } else {
            self.client.post(self.url("/api/ciphers")).json(cipher)
        };
        let created: Created = self.json(request.bearer_auth(token)).await?;
        Ok(created.id)
    }

    /// Borra un elemento del todo (no a la papelera).
    pub async fn delete(&self, token: &str, id: &str) -> Result<(), VwError> {
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(VwError::Unexpected);
        }
        self.execute(
            self.client
                .delete(self.url(&format!("/api/ciphers/{id}")))
                .bearer_auth(token),
        )
        .await
        .map(drop)
    }
}

fn kdf_from(res: &PreloginResponse) -> Result<Kdf, VwError> {
    match res.kdf {
        0 => Ok(Kdf::Pbkdf2 {
            iterations: res.kdf_iterations,
        }),
        1 => Ok(Kdf::Argon2id {
            iterations: res.kdf_iterations,
            memory_mib: res.kdf_memory.ok_or(VwError::Unexpected)?,
            parallelism: res.kdf_parallelism.ok_or(VwError::Unexpected)?,
        }),
        other => Err(VwError::Unsupported(format!(
            "la derivación de contraseña {other}"
        ))),
    }
}

/// El segundo factor que pide la cuenta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorProvider {
    /// Aplicación de códigos TOTP.
    Authenticator,
    Email,
    /// Duo, YubiKey OTP, WebAuthn…: Túnel aún no los admite.
    Other(u8),
}

impl TwoFactorProvider {
    pub fn code(self) -> u8 {
        match self {
            Self::Authenticator => 0,
            Self::Email => 1,
            Self::Other(code) => code,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Authenticator,
            1 => Self::Email,
            other => Self::Other(other),
        }
    }
}

/// Un campo del JSON sin distinguir mayúsculas: Vaultwarden mezcla `ErrorModel` y `message`.
fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

fn message_from(body: &Value) -> String {
    let text = field(body, "ErrorModel")
        .and_then(|m| field(m, "Message"))
        .or_else(|| field(body, "error_description"))
        .or_else(|| field(body, "message"))
        .and_then(Value::as_str)
        .unwrap_or("sin detalles");
    text.chars().take(MAX_MESSAGE).collect()
}

fn providers_from(body: &Value) -> Option<Vec<TwoFactorProvider>> {
    let list = field(body, "TwoFactorProviders")?.as_array()?;
    let codes = list.iter().filter_map(|p| match p {
        Value::Number(n) => n.as_u64().and_then(|n| u8::try_from(n).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    });
    Some(codes.map(TwoFactorProvider::from_code).collect())
}

pub(crate) fn error_from(status: StatusCode, body: &Value) -> VwError {
    if status == StatusCode::UNAUTHORIZED {
        return VwError::SessionExpired;
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return VwError::TooManyAttempts;
    }
    if let Some(providers) = providers_from(body).filter(|p| !p.is_empty()) {
        return VwError::TwoFactorRequired(providers);
    }
    let message = message_from(body);
    if field(body, "error").and_then(Value::as_str) == Some("invalid_grant") {
        return VwError::Rejected(message);
    }
    VwError::Server {
        status: status.as_u16(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_https_except_on_this_machine_or_the_local_network() {
        let ok = check_server_url(" https://vault.example.com/ ").unwrap();
        assert_eq!(ok.as_str(), "https://vault.example.com");
        assert!(
            check_server_url("http://192.168.1.10:8080")
                .unwrap()
                .plaintext
        );
        for bad in [
            "http://vault.example.com",
            "ftp://vault.example.com",
            "https://user:pw@vault.example.com",
            "https://vault.example.com/?x=1",
            "vault.example.com",
        ] {
            assert!(check_server_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_kdf_comes_from_prelogin() {
        let pbkdf2 = PreloginResponse {
            kdf: 0,
            kdf_iterations: 600_000,
            kdf_memory: None,
            kdf_parallelism: None,
        };
        assert_eq!(
            kdf_from(&pbkdf2).unwrap(),
            Kdf::Pbkdf2 {
                iterations: 600_000
            }
        );
        let argon: PreloginResponse = serde_json::from_value(json!({
            "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4, "salt": null
        }))
        .unwrap();
        assert_eq!(
            kdf_from(&argon).unwrap(),
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4
            }
        );
        let unknown = PreloginResponse { kdf: 9, ..pbkdf2 };
        assert!(matches!(kdf_from(&unknown), Err(VwError::Unsupported(_))));
    }

    #[test]
    fn login_errors_say_what_happened() {
        let two_factor = json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "1"],
        });
        assert!(matches!(
            error_from(StatusCode::BAD_REQUEST, &two_factor),
            VwError::TwoFactorRequired(p) if p == [TwoFactorProvider::Authenticator, TwoFactorProvider::Email]
        ));
        let numbers = json!({ "twoFactorProviders": [7] });
        assert!(matches!(
            error_from(StatusCode::BAD_REQUEST, &numbers),
            VwError::TwoFactorRequired(p) if p == [TwoFactorProvider::Other(7)]
        ));
        let wrong = json!({
            "error": "invalid_grant",
            "error_description": "Username or password is incorrect. Try again",
            "ErrorModel": { "Message": "Username or password is incorrect. Try again" },
        });
        assert!(matches!(
            error_from(StatusCode::BAD_REQUEST, &wrong),
            VwError::Rejected(m) if m.starts_with("Username or password")
        ));
        assert!(matches!(
            error_from(StatusCode::UNAUTHORIZED, &Value::Null),
            VwError::SessionExpired
        ));
        let limited = json!({ "message": "Too many login requests" });
        assert!(matches!(
            error_from(StatusCode::TOO_MANY_REQUESTS, &limited),
            VwError::TooManyAttempts
        ));
        let long = json!({ "message": "x".repeat(1000) });
        assert!(matches!(
            error_from(StatusCode::INTERNAL_SERVER_ERROR, &long),
            VwError::Server { status: 500, message } if message.len() == MAX_MESSAGE
        ));
    }
}
