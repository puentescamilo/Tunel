//! Iniciar sesión con un proveedor de identidad (Google, Microsoft 365, OpenID Connect).
//!
//! El proveedor solo dice quién es la persona: la clave de bóveda de estas cuentas se
//! envuelve con la que sale de la contraseña maestra de Túnel, que tiene que ser fuerte y
//! la misma en todos los equipos. El servidor sigue sin poder leer nada.
//!
//! 1. [`begin`] escucha en un puerto libre de `127.0.0.1` y da la dirección que hay que
//!    abrir en el navegador, con un reto PKCE y un `state` propios.
//! 2. [`OAuthStart::wait`] espera a que el navegador vuelva con el código, comprueba el
//!    `state` y lo canjea demostrando el PKCE.
//! 3. [`complete`] abre la clave de bóveda con la contraseña maestra, o crea la cuenta.

use crate::account::{ACCOUNT_KDF, derive, kdf_acceptable};
use crate::api::{Api, ServerUrl};
use crate::{SyncError, keypair, now_millis};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tunel_core::sync::keys::MIN_SALT_LEN;
use tunel_core::sync::protocol::{
    AuthProvider, OAuthLogin, OAuthRegisterRequest, OAuthTokenRequest, VaultKeyUpdate,
};
use tunel_core::sync::{OAuthAccount, SyncLocal, SyncState, VaultKey};
use tunel_core::vault::VaultData;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Tiempo para completar el inicio de sesión en el navegador.
const BROWSER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Tope de una petición del navegador a la dirección local.
const MAX_REQUEST: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Proveedores de identidad del servidor; vacío si no tiene ninguno.
pub async fn providers(server: &ServerUrl) -> Result<Vec<AuthProvider>, SyncError> {
    Api::new(server)?.auth_providers().await
}

/// Un inicio de sesión esperando a que el navegador vuelva.
pub struct OAuthStart {
    /// Dirección que hay que abrir en el navegador.
    pub url: String,
    server: ServerUrl,
    provider: AuthProvider,
    listener: TcpListener,
    verifier: Zeroizing<String>,
    state: String,
}

/// Empieza a iniciar sesión con `provider`: escucha en un puerto libre de este equipo y
/// devuelve la dirección para el navegador.
pub async fn begin(server: &ServerUrl, provider: AuthProvider) -> Result<OAuthStart, SyncError> {
    let api = Api::new(server)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| SyncError::Internal(format!("no se pudo abrir un puerto local: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| SyncError::Internal(e.to_string()))?
        .port();
    let verifier = Zeroizing::new(B64_URL.encode(rand::random::<[u8; 32]>()));
    let challenge = B64_URL.encode(Sha256::digest(verifier.as_bytes()));
    let state = B64_URL.encode(rand::random::<[u8; 16]>());
    Ok(OAuthStart {
        url: api.oauth_start_url(&provider.id, port, &challenge, &state),
        server: server.clone(),
        provider,
        listener,
        verifier,
        state,
    })
}

/// Quién inició sesión y qué dijo el servidor: si la cuenta ya existía o hay que crearla.
pub struct OAuthSignIn {
    server: ServerUrl,
    provider: AuthProvider,
    login: OAuthLogin,
}

impl OAuthSignIn {
    pub fn email(&self) -> &str {
        match &self.login {
            OAuthLogin::Existing { email, .. } | OAuthLogin::New { email, .. } => email,
        }
    }

    /// No había cuenta con ese correo: [`complete`] la creará.
    pub fn is_new(&self) -> bool {
        matches!(self.login, OAuthLogin::New { .. })
    }

    pub fn provider_name(&self) -> &str {
        &self.provider.name
    }
}

/// Lo que llegó del navegador a la dirección local.
#[derive(Debug, PartialEq, Eq)]
enum Return {
    Code(String),
    Error(String),
    /// Otra cosa (un icono, una petición sin el `state` correcto): se ignora.
    Ignored,
}

/// Interpreta la primera línea de la petición, `GET /oauth?code=…&state=… HTTP/1.1`.
fn parse_return(request_line: &str, expected_state: &str) -> Return {
    let mut parts = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Return::Ignored;
    };
    let Ok(url) = reqwest::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Return::Ignored;
    };
    if url.path() != "/oauth" {
        return Return::Ignored;
    }
    let get = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if get("state").as_deref() != Some(expected_state) {
        return Return::Ignored;
    }
    match (get("code"), get("error")) {
        (Some(code), _) => Return::Code(code),
        (None, Some(error)) => Return::Error(error.chars().take(300).collect()),
        (None, None) => Return::Ignored,
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn reply(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Túnel</title>\
         <body style=\"font-family:system-ui;margin:3em\"><h2>Túnel</h2><p>{}</p>",
        escape_html(message)
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Lee la línea de la petición, con tope de tamaño y de tiempo.
async fn request_line(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    let read = async {
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..n]);
            if let Some(end) = buffer.windows(2).position(|w| w == b"\r\n") {
                return Some(String::from_utf8_lossy(&buffer[..end]).into_owned());
            }
            if buffer.len() > MAX_REQUEST {
                return None;
            }
        }
    };
    tokio::time::timeout(READ_TIMEOUT, read)
        .await
        .ok()
        .flatten()
}

impl OAuthStart {
    /// Espera a que el navegador vuelva (como mucho 5 minutos) y canjea el código.
    pub async fn wait(self) -> Result<OAuthSignIn, SyncError> {
        let code = tokio::time::timeout(BROWSER_TIMEOUT, self.accept())
            .await
            .map_err(|_| SyncError::Provider("no se completó a tiempo en el navegador".into()))??;
        let api = Api::new(&self.server)?;
        let login = api
            .oauth_token(&OAuthTokenRequest {
                code,
                verifier: self.verifier.to_string(),
            })
            .await?;
        Ok(OAuthSignIn {
            server: self.server,
            provider: self.provider,
            login,
        })
    }

    async fn accept(&self) -> Result<String, SyncError> {
        loop {
            let Ok((mut stream, _)) = self.listener.accept().await else {
                continue;
            };
            let Some(line) = request_line(&mut stream).await else {
                continue;
            };
            match parse_return(&line, &self.state) {
                Return::Code(code) => {
                    reply(&mut stream, "200 OK", "Listo. Ya puedes volver a Túnel.").await;
                    return Ok(code);
                }
                Return::Error(error) => {
                    reply(
                        &mut stream,
                        "200 OK",
                        &format!("No se pudo iniciar sesión: {error}"),
                    )
                    .await;
                    return Err(SyncError::Provider(error));
                }
                Return::Ignored => reply(&mut stream, "404 Not Found", "No encontrado.").await,
            }
        }
    }
}

/// Termina de unir este equipo a la cuenta con la contraseña maestra: abre la clave de
/// bóveda de la cuenta o, si es nueva, la crea con el contenido actual de la bóveda.
pub async fn complete(
    sign_in: OAuthSignIn,
    master_password: Zeroizing<String>,
    data: &VaultData,
) -> Result<SyncLocal, SyncError> {
    let api = Api::new(&sign_in.server)?;
    let provider = sign_in.provider;
    let (email, token, vault_key, wrapped) = match sign_in.login {
        OAuthLogin::Existing {
            email,
            token,
            kdf,
            salt,
            vault_key: wrapped,
        } => {
            let salt = B64
                .decode(&salt)
                .map_err(|_| SyncError::Internal("sal no válida".into()))?;
            if !kdf_acceptable(&salt, kdf) {
                return Err(SyncError::WeakKdf);
            }
            let keys = derive(master_password, salt, kdf).await?;
            let vault_key =
                VaultKey::unwrap(&wrapped, &keys).map_err(|_| SyncError::MasterPasswordMismatch)?;
            (email, token, vault_key, wrapped)
        }
        OAuthLogin::New { email, ticket } => {
            let missing = tunel_core::password::problems(&master_password);
            if !missing.is_empty() {
                return Err(SyncError::WeakMasterPassword(
                    tunel_core::password::describe(&missing),
                ));
            }
            let salt: [u8; MIN_SALT_LEN] = rand::random();
            let keys = derive(master_password, salt.to_vec(), ACCOUNT_KDF).await?;
            let vault_key = VaultKey::generate();
            let wrapped = vault_key.wrap(&keys)?;
            let created = api
                .oauth_register(&OAuthRegisterRequest {
                    ticket,
                    kdf: ACCOUNT_KDF,
                    salt: B64.encode(salt),
                    vault_key: wrapped.clone(),
                })
                .await?;
            (email, created.token, vault_key, wrapped)
        }
    };
    let keypair = keypair::try_fetch_or_create(&api, &token, &vault_key).await;
    Ok(SyncLocal {
        server: sign_in.server.base.clone(),
        email,
        // Sin contraseña de cuenta: la sesión solo se renueva pasando por el proveedor.
        auth: Zeroizing::new(String::new()),
        vault_key,
        token: Some(Zeroizing::new(token)),
        state: SyncState::adopt(Uuid::new_v4(), data, now_millis())?,
        keypair,
        teams: Vec::new(),
        invitations: Vec::new(),
        contacts: Default::default(),
        oauth: Some(OAuthAccount {
            provider: provider.id,
            provider_name: provider.name,
            wrapped_vault_key: wrapped,
        }),
    })
}

/// Vuelve a iniciar sesión con el proveedor en una cuenta ya unida (la sesión caducó):
/// solo cambia el token. Falla si quien inició sesión es otra cuenta.
pub fn renew(local: &SyncLocal, sign_in: OAuthSignIn) -> Result<SyncLocal, SyncError> {
    let OAuthLogin::Existing {
        email,
        token,
        vault_key,
        ..
    } = sign_in.login
    else {
        return Err(SyncError::Provider(format!(
            "{} no tiene cuenta en este servidor",
            sign_in.provider.name
        )));
    };
    if !email.eq_ignore_ascii_case(&local.email) {
        return Err(SyncError::Provider(format!(
            "iniciaste sesión como {email}, pero este equipo está unido a {}",
            local.email
        )));
    }
    let oauth = local.oauth.clone().map(|o| OAuthAccount {
        wrapped_vault_key: vault_key,
        ..o
    });
    Ok(SyncLocal {
        token: Some(Zeroizing::new(token)),
        oauth,
        ..local.clone()
    })
}

/// La contraseña maestra cambió: vuelve a envolver la clave de bóveda en el servidor con
/// la nueva. Solo para cuentas de proveedor de identidad.
pub async fn rewrap(
    local: &SyncLocal,
    new_master_password: Zeroizing<String>,
) -> Result<SyncLocal, SyncError> {
    let Some(oauth) = &local.oauth else {
        return Err(SyncError::Internal(
            "la cuenta no es de un proveedor de identidad".into(),
        ));
    };
    let missing = tunel_core::password::problems(&new_master_password);
    if !missing.is_empty() {
        return Err(SyncError::WeakMasterPassword(
            tunel_core::password::describe(&missing),
        ));
    }
    let salt: [u8; MIN_SALT_LEN] = rand::random();
    let keys = derive(new_master_password, salt.to_vec(), ACCOUNT_KDF).await?;
    let wrapped = local.vault_key.wrap(&keys)?;
    let update = VaultKeyUpdate {
        previous: oauth.wrapped_vault_key.clone(),
        kdf: ACCOUNT_KDF,
        salt: B64.encode(salt),
        vault_key: wrapped.clone(),
    };
    let mut session = crate::session::Session::new(local)?;
    crate::session::call!(&mut session, |api, token| api
        .update_vault_key(token, &update))?;
    Ok(SyncLocal {
        token: session.into_token(),
        oauth: Some(OAuthAccount {
            wrapped_vault_key: wrapped,
            ..oauth.clone()
        }),
        ..local.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_browser_return_needs_the_right_path_and_state() {
        let line = |target: &str| format!("GET {target} HTTP/1.1");
        assert_eq!(
            parse_return(&line("/oauth?code=abc&state=s1"), "s1"),
            Return::Code("abc".into())
        );
        assert_eq!(
            parse_return(&line("/oauth?error=sin%20permiso&state=s1"), "s1"),
            Return::Error("sin permiso".into())
        );
        for ignored in [
            line("/oauth?code=abc&state=otro"),
            line("/oauth?code=abc"),
            line("/favicon.ico"),
            line("/oauth?state=s1"),
            "POST /oauth?code=abc&state=s1 HTTP/1.1".to_string(),
            "basura".to_string(),
        ] {
            assert_eq!(parse_return(&ignored, "s1"), Return::Ignored, "{ignored}");
        }
    }

    #[test]
    fn error_pages_escape_html() {
        assert_eq!(escape_html("<script>&"), "&lt;script&gt;&amp;");
    }
}
