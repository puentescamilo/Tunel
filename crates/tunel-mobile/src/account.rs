//! La cuenta de Túnel en el móvil: unirse con correo y contraseña o con un proveedor
//! (Google, Microsoft) y descargar lo sincronizado.
//!
//! El móvil solo recibe: se une con la bóveda vacía, así que no sube nada, y lo que llega
//! sustituye a lo que había. No crea cuentas: eso se hace desde el escritorio.

use crate::runtime::{capitalize, runtime};
use crate::{TunelError, Vault};
use std::sync::{Arc, Mutex};
use tunel_core::VaultData;
use tunel_core::sync::protocol::AuthProvider;
use tunel_sync::oauth::{self, AppOAuthStart, OAuthSignIn};
use tunel_sync::{ServerUrl, SyncError, check_server_url};
use zeroize::Zeroizing;

fn server_url(server: &str) -> Result<ServerUrl, TunelError> {
    Ok(check_server_url(server.trim())?)
}

/// Un proveedor de identidad del servidor.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Provider {
    pub id: String,
    pub name: String,
}

/// Cómo se puede entrar en un servidor.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignInOptions {
    pub providers: Vec<Provider>,
    /// `false` si el servidor solo admite proveedores.
    pub password_login: bool,
}

/// La cuenta a la que está unido este dispositivo.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountInfo {
    pub server: String,
    pub email: String,
    /// «Google», «Microsoft»…; `None` si se entra con contraseña.
    pub provider_name: Option<String>,
    /// Nombres de los Teams que ya se reciben.
    pub teams: Vec<String>,
}

/// Lo que dejó una sincronización.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncReport {
    pub downloaded: u32,
    /// Teams que no se pudieron recibir esta vez, con el motivo.
    pub team_problems: Vec<String>,
    /// Invitaciones a Teams pendientes: se aceptan desde el escritorio.
    pub invitations: u32,
}

/// Cómo se puede entrar en `server`.
#[uniffi::export]
pub fn sign_in_options(server: String) -> Result<SignInOptions, TunelError> {
    let server = server_url(&server)?;
    let options = runtime().block_on(oauth::providers(&server))?;
    Ok(SignInOptions {
        providers: options
            .providers
            .into_iter()
            .map(|p| Provider {
                id: p.id,
                name: p.name,
            })
            .collect(),
        password_login: options.password_login,
    })
}

/// En qué punto va un inicio de sesión con un proveedor.
enum Stage {
    /// Esperando a que vuelva el navegador del sistema.
    Started(AppOAuthStart),
    /// El servidor ya dijo quién es: falta la contraseña maestra.
    Returned(OAuthSignIn),
    Used,
}

/// Un inicio de sesión con un proveedor: se abre `url()` en el navegador del sistema, la
/// vuelta se pasa a [`ProviderSignIn::returned`] y, con la contraseña maestra, se termina con
/// [`Vault::sign_in_with_provider`].
#[derive(uniffi::Object)]
pub struct ProviderSignIn {
    url: String,
    stage: Mutex<Stage>,
}

#[uniffi::export]
impl ProviderSignIn {
    /// Empieza a iniciar sesión con el proveedor `provider_id` de `server`.
    #[uniffi::constructor]
    pub fn begin(server: String, provider_id: String) -> Result<Arc<Self>, TunelError> {
        let server = server_url(&server)?;
        let providers = runtime().block_on(oauth::providers(&server))?.providers;
        let provider: AuthProvider = providers
            .into_iter()
            .find(|p| p.id == provider_id)
            .ok_or_else(|| TunelError::Sync {
                detail: "Este servidor ya no ofrece ese proveedor".into(),
            })?;
        let start = oauth::begin_app(&server, provider)?;
        Ok(Arc::new(Self {
            url: start.url.clone(),
            stage: Mutex::new(Stage::Started(start)),
        }))
    }

    /// El navegador volvió a `callback`: canjea el código en el momento (caduca pronto) y
    /// devuelve el correo de la cuenta, para pedir su contraseña maestra.
    pub fn returned(&self, callback: String) -> Result<String, TunelError> {
        let mut stage = self.stage.lock().unwrap_or_else(|e| e.into_inner());
        let Stage::Started(start) = std::mem::replace(&mut *stage, Stage::Used) else {
            return Err(already_used());
        };
        let signed = runtime().block_on(start.finish(&callback))?;
        if signed.is_new() {
            return Err(TunelError::NoAccount {
                email: signed.email().to_string(),
            });
        }
        let email = signed.email().to_string();
        *stage = Stage::Returned(signed);
        Ok(email)
    }

    /// Dirección que hay que abrir en el navegador del sistema.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// El esquema de la dirección de vuelta, para el navegador del sistema.
    pub fn callback_scheme(&self) -> String {
        "tunel".into()
    }
}

fn already_used() -> TunelError {
    TunelError::Sync {
        detail: "Este inicio de sesión ya se usó; empieza de nuevo".into(),
    }
}

impl ProviderSignIn {
    /// Lo que devolvió el servidor, para usarlo una sola vez.
    fn take_returned(&self) -> Result<OAuthSignIn, TunelError> {
        let mut stage = self.stage.lock().unwrap_or_else(|e| e.into_inner());
        match std::mem::replace(&mut *stage, Stage::Used) {
            Stage::Returned(signed) => Ok(signed),
            other => {
                *stage = other;
                Err(already_used())
            }
        }
    }

    /// Si la contraseña maestra no es la de la cuenta, se puede volver a intentar sin pasar
    /// otra vez por el navegador.
    fn put_back(&self, signed: OAuthSignIn) {
        *self.stage.lock().unwrap_or_else(|e| e.into_inner()) = Stage::Returned(signed);
    }
}

#[uniffi::export]
impl Vault {
    /// La cuenta a la que está unido este dispositivo, si lo está.
    pub fn account(&self) -> Result<Option<AccountInfo>, TunelError> {
        let local = self.lock().load_sync()?;
        Ok(local.map(|l| AccountInfo {
            server: l.server.clone(),
            email: l.email.clone(),
            provider_name: l.oauth.as_ref().map(|o| o.provider_name.clone()),
            teams: l.teams.iter().map(|t| t.name.clone()).collect(),
        }))
    }

    /// Une este dispositivo a una cuenta con correo y contraseña. No descarga nada todavía:
    /// después hay que llamar a [`Vault::sync`].
    pub fn sign_in_with_password(
        &self,
        server: String,
        email: String,
        password: String,
    ) -> Result<(), TunelError> {
        let server = server_url(&server)?;
        let local = runtime().block_on(tunel_sync::sign_in(
            &server,
            email.trim(),
            Zeroizing::new(password),
            &VaultData::default(),
        ))?;
        Ok(self.lock().save_sync(&local)?)
    }

    /// Termina de iniciar sesión con un proveedor, después de
    /// [`ProviderSignIn::returned`], con la contraseña maestra de la cuenta (la misma que en
    /// el escritorio).
    pub fn sign_in_with_provider(
        &self,
        sign_in: Arc<ProviderSignIn>,
        master_password: String,
    ) -> Result<(), TunelError> {
        let signed = sign_in.take_returned()?;
        let master = Zeroizing::new(master_password);
        // `complete` consume lo que dijo el servidor: se guarda una copia para reintentar.
        let retry = signed.clone();
        let result = runtime().block_on(oauth::complete(signed, master, &VaultData::default()));
        let local = match result {
            Ok(local) => local,
            Err(SyncError::MasterPasswordMismatch) => {
                sign_in.put_back(retry);
                return Err(TunelError::WrongMasterPassword);
            }
            Err(other) => return Err(other.into()),
        };
        Ok(self.lock().save_sync(&local)?)
    }

    /// Descarga lo nuevo de la cuenta y de sus Teams y lo guarda en la bóveda.
    pub fn sync(&self) -> Result<SyncReport, TunelError> {
        let (local, data) = {
            let vault = self.lock();
            let local = vault.load_sync()?.ok_or(TunelError::NotSignedIn)?;
            (local, vault.data.clone())
        };
        // Sin la bóveda bloqueada mientras va la red: la lista sigue respondiendo.
        let outcome = runtime().block_on(tunel_sync::sync_once(&local, &data))?;
        let mut vault = self.lock();
        // Si no se puede guardar la bóveda, tampoco el estado nuevo: se repetirá la descarga.
        vault.commit(outcome.data)?;
        vault.save_sync(&outcome.local)?;
        Ok(SyncReport {
            downloaded: outcome.downloaded as u32,
            team_problems: outcome
                .team_problems
                .iter()
                .map(|p| {
                    let team = outcome.local.team(&p.team).map(|t| t.name.as_str());
                    match team {
                        Some(name) if !name.is_empty() => format!("{name}: {}", p.message),
                        _ => p.message.clone(),
                    }
                })
                .collect(),
            invitations: outcome.local.invitations.len() as u32,
        })
    }

    /// Desvincula el dispositivo de la cuenta y borra lo descargado: en el móvil la bóveda
    /// es una copia de la cuenta.
    pub fn sign_out(&self) -> Result<(), TunelError> {
        let local = self.lock().load_sync()?;
        if let Some(local) = &local {
            // Si no hay red, la sesión caduca sola en el servidor: no impide salir.
            let _ = runtime().block_on(tunel_sync::sign_out(local));
        }
        let mut vault = self.lock();
        vault.delete_sync()?;
        Ok(vault.commit(VaultData::default())?)
    }
}

impl From<SyncError> for TunelError {
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::MasterPasswordMismatch => Self::WrongMasterPassword,
            other => Self::Sync {
                detail: capitalize(&other.to_string()),
            },
        }
    }
}
