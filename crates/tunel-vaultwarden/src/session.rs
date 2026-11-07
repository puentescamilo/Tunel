//! Iniciar sesión y mantenerla: el token de acceso dura poco y se renueva solo con el de
//! refresco.

use crate::VwError;
use crate::api::{Api, Device, ServerUrl};
use crate::crypto::{EncString, MasterKey, SymmetricKey, normalize_email};
use crate::vault::{NewLogin, Vault};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Se renueva el token un poco antes de que caduque.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// El código del segundo factor.
pub enum SecondFactor {
    /// Código de la aplicación de autenticación (TOTP).
    Authenticator(String),
    /// Código que llegó por correo (ver [`Credentials::send_email_code`]).
    Email(String),
}

/// La contraseña maestra ya derivada. Se guarda mientras dura el inicio de sesión para no
/// volver a derivarla si el servidor pide el segundo factor.
pub struct Credentials {
    api: Api,
    email: String,
    password_hash: Zeroizing<String>,
    stretched: SymmetricKey,
}

impl Credentials {
    /// Pide al servidor cómo derivar la clave y la deriva, fuera del hilo que llama porque
    /// Argon2id tarda y usa memoria.
    pub async fn new(server: &ServerUrl, email: &str, password: &str) -> Result<Self, VwError> {
        let api = Api::new(server)?;
        let email = normalize_email(email);
        let kdf = api.prelogin(&email).await?;
        let (owned_email, password) = (email.clone(), Zeroizing::new(password.to_string()));
        let (password_hash, stretched) = tokio::task::spawn_blocking(move || {
            let master = MasterKey::derive(&owned_email, &password, kdf)?;
            Ok::<_, VwError>((master.password_hash(&password), master.stretch()))
        })
        .await
        .map_err(|_| VwError::Unexpected)??;
        Ok(Self {
            api,
            email,
            password_hash,
            stretched,
        })
    }

    /// Manda por correo el código del segundo factor, si la cuenta lo tiene por correo.
    pub async fn send_email_code(&self, device: &Device) -> Result<(), VwError> {
        self.api
            .send_email_code(&self.email, &self.password_hash, device)
            .await
    }

    /// Inicia sesión. Si la cuenta tiene segundo factor y no se da, devuelve
    /// [`VwError::TwoFactorRequired`] con los que admite, y se vuelve a llamar con el código.
    pub async fn sign_in(
        &self,
        device: &Device,
        second: Option<&SecondFactor>,
    ) -> Result<Session, VwError> {
        let (provider, code) = match second {
            Some(SecondFactor::Authenticator(code)) => ("0", code.trim()),
            Some(SecondFactor::Email(code)) => ("1", code.trim()),
            None => ("", ""),
        };
        let mut fields = vec![
            ("grant_type", "password"),
            ("scope", "api offline_access"),
            ("username", self.email.as_str()),
            ("password", self.password_hash.as_str()),
        ];
        if second.is_some() {
            fields.extend([
                ("twoFactorProvider", provider),
                ("twoFactorToken", code),
                ("twoFactorRemember", "0"),
            ]);
        }
        let token = self.api.token(&fields, device, Some(&self.email)).await?;
        let sealed = token.key.as_deref().ok_or(VwError::NoMasterPassword)?;
        let user_key =
            SymmetricKey::from_bytes(&sealed.parse::<EncString>()?.decrypt(&self.stretched)?)?;
        let refresh = token.refresh_token.ok_or(VwError::Unexpected)?;
        Ok(Session {
            api: self.api.clone(),
            device: device.clone(),
            access_token: Zeroizing::new(token.access_token),
            expires_at: Instant::now() + Duration::from_secs(token.expires_in),
            refresh_token: Zeroizing::new(refresh),
            user_key,
        })
    }
}

/// Dónde se crea un elemento nuevo.
pub enum Place {
    Personal,
    Organization {
        organization_id: String,
        collection_ids: Vec<String>,
    },
}

pub struct Session {
    api: Api,
    device: Device,
    access_token: Zeroizing<String>,
    expires_at: Instant,
    refresh_token: Zeroizing<String>,
    user_key: SymmetricKey,
}

impl Session {
    /// Retoma una sesión guardada sin pedir la contraseña: el primer uso renueva el token.
    pub fn restore(
        server: &ServerUrl,
        device: Device,
        refresh_token: &str,
        user_key: SymmetricKey,
    ) -> Result<Self, VwError> {
        Ok(Self {
            api: Api::new(server)?,
            device,
            access_token: Zeroizing::new(String::new()),
            expires_at: Instant::now(),
            refresh_token: Zeroizing::new(refresh_token.to_string()),
            user_key,
        })
    }

    /// Lo que hay que guardar (cifrado) para retomar la sesión con [`Session::restore`].
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub fn user_key(&self) -> &SymmetricKey {
        &self.user_key
    }

    async fn refresh(&mut self) -> Result<(), VwError> {
        let fields = [
            ("grant_type", "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
        ];
        // Un refresco rechazado significa que hay que volver a iniciar sesión.
        let token = match self.api.token(&fields, &self.device, None).await {
            Err(VwError::Rejected(_)) => return Err(VwError::SessionExpired),
            other => other?,
        };
        self.access_token = Zeroizing::new(token.access_token);
        self.expires_at = Instant::now() + Duration::from_secs(token.expires_in);
        if let Some(refresh) = token.refresh_token {
            self.refresh_token = Zeroizing::new(refresh);
        }
        Ok(())
    }

    async fn token(&mut self) -> Result<String, VwError> {
        if Instant::now() + REFRESH_MARGIN >= self.expires_at {
            self.refresh().await?;
        }
        Ok(self.access_token.to_string())
    }

    /// Hace una llamada con el token, y si el servidor lo da por caducado lo renueva y la
    /// repite una vez.
    async fn authorized<T, F, Fut>(&mut self, call: F) -> Result<T, VwError>
    where
        F: Fn(Api, String) -> Fut,
        Fut: Future<Output = Result<T, VwError>>,
    {
        let token = self.token().await?;
        match call(self.api.clone(), token).await {
            Err(VwError::SessionExpired) => {
                self.refresh().await?;
                call(self.api.clone(), self.access_token.to_string()).await
            }
            other => other,
        }
    }

    /// Descarga y descifra la bóveda.
    pub async fn sync(&mut self) -> Result<Vault, VwError> {
        let response = self
            .authorized(|api, token| async move { api.sync(&token).await })
            .await?;
        Vault::open(&response, &self.user_key)
    }

    /// Crea un elemento de usuario y contraseña, cifrado en este equipo. `vault` es la última
    /// sincronización, que tiene las claves de las organizaciones.
    pub async fn create_login(
        &mut self,
        vault: &Vault,
        login: &NewLogin,
        place: &Place,
    ) -> Result<String, VwError> {
        let (organization_id, collection_ids) = match place {
            Place::Personal => (None, Vec::new()),
            Place::Organization {
                organization_id,
                collection_ids,
            } => (Some(organization_id.as_str()), collection_ids.clone()),
        };
        if organization_id.is_some() && collection_ids.is_empty() {
            return Err(VwError::InvalidRequest(
                "elige al menos una colección de la organización",
            ));
        }
        let key = vault
            .key_for(organization_id, &self.user_key)
            .ok_or(VwError::InvalidRequest(
                "no tienes acceso a esa organización",
            ))?;
        let cipher = login.seal(key, organization_id, &vault.user_id);
        self.authorized(|api, token| {
            let (cipher, collection_ids) = (cipher.clone(), collection_ids.clone());
            async move { api.create(&token, &cipher, &collection_ids).await }
        })
        .await
    }

    /// Borra un elemento del todo.
    pub async fn delete_item(&mut self, id: &str) -> Result<(), VwError> {
        self.authorized(|api, token| {
            let id = id.to_string();
            async move { api.delete(&token, &id).await }
        })
        .await
    }
}
