//! Iniciar sesión con un proveedor de identidad (Google, Microsoft 365…) desde Ajustes.
//!
//! 1. Con la dirección del servidor escrita, se piden sus proveedores.
//! 2. Al pulsar «Entrar con…», el motor abre el navegador y espera a que vuelva.
//! 3. La persona escribe su contraseña maestra: tiene que ser la de esta bóveda, y con ella
//!    se abre o se crea la cuenta. Termina como «Iniciar sesión» (`AppEvent::SyncLinked`).

use super::{SyncStatus, save};
use crate::app::TunelApp;
use std::time::Duration;
use tunel_core::sync::SyncLocal;
use tunel_core::sync::protocol::AuthProvider;
use tunel_sync::SyncError;
use tunel_sync::oauth::OAuthSignIn;
use zeroize::{Zeroize, Zeroizing};

/// Resultados de las operaciones en segundo plano.
pub enum OAuthEvent {
    Providers {
        server: String,
        result: Result<Vec<AuthProvider>, SyncError>,
    },
    /// Volvió el navegador. `renewing`: era para renovar la sesión de una cuenta ya unida.
    SignedIn {
        renewing: bool,
        result: Result<OAuthSignIn, SyncError>,
    },
    /// Se volvió a envolver la clave en el servidor con la contraseña maestra nueva.
    Rewrapped {
        round: u64,
        password: Zeroizing<String>,
        result: Result<Box<SyncLocal>, SyncError>,
    },
}

/// Estado del inicio de sesión con proveedor en Ajustes.
#[derive(Default)]
pub struct OAuthUi {
    /// Proveedores del servidor con esa dirección.
    pub providers: Option<(String, Vec<AuthProvider>)>,
    /// Dirección cuyos proveedores se están pidiendo.
    loading: Option<String>,
    /// Esperando al navegador, con el nombre del proveedor.
    pub waiting: Option<String>,
    renewing: bool,
    /// Volvió el navegador: falta la contraseña maestra.
    pub signed_in: Option<OAuthSignIn>,
    pub master: String,
}

impl Drop for OAuthUi {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

impl OAuthUi {
    /// Proveedores para la dirección `server`, si ya se conocen.
    pub fn providers_for(&self, server: &str) -> &[AuthProvider] {
        match &self.providers {
            Some((url, list)) if url == server => list,
            _ => &[],
        }
    }

    pub fn cancel(&mut self) {
        self.waiting = None;
        self.signed_in = None;
        self.master.zeroize();
    }
}

/// Pide los proveedores del servidor escrito, si no se pidieron ya para esa dirección.
pub fn refresh_providers(app: &mut TunelApp) {
    let Ok(server) = tunel_sync::check_server_url(&app.sync.form.server) else {
        return;
    };
    let ui = &app.sync.oauth;
    let known = ui
        .providers
        .as_ref()
        .is_some_and(|(url, _)| *url == server.base);
    if known || ui.loading.as_deref() == Some(server.base.as_str()) {
        return;
    }
    app.sync.oauth.loading = Some(server.base.clone());
    app.engine.oauth_providers(server);
}

/// Empieza a iniciar sesión con `provider` en el navegador.
pub fn start(app: &mut TunelApp, provider: AuthProvider) {
    let Ok(server) = tunel_sync::check_server_url(&app.sync.form.server) else {
        return app.notify("Escribe primero la dirección del servidor");
    };
    begin(app, server, provider, false);
}

fn begin(
    app: &mut TunelApp,
    server: tunel_sync::ServerUrl,
    provider: AuthProvider,
    renewing: bool,
) {
    app.sync.oauth.cancel();
    app.sync.oauth.waiting = Some(provider.name.clone());
    app.sync.oauth.renewing = renewing;
    app.engine.oauth_sign_in(server, provider, renewing);
}

/// La sesión de una cuenta de proveedor caducó: vuelve a pasar por el navegador.
pub fn renew(app: &mut TunelApp) {
    let Some(local) = app.sync.local() else {
        return;
    };
    let (Some(oauth), Ok(server)) = (&local.oauth, tunel_sync::check_server_url(&local.server))
    else {
        return;
    };
    let provider = AuthProvider {
        id: oauth.provider.clone(),
        name: oauth.provider_name.clone(),
    };
    begin(app, server, provider, true);
}

/// Con la contraseña maestra escrita, abre o crea la cuenta.
pub fn finish(app: &mut TunelApp) {
    let master = Zeroizing::new(std::mem::take(&mut app.sync.oauth.master));
    let Some(sign_in) = app.sync.oauth.signed_in.take() else {
        return;
    };
    if sign_in.is_new() {
        let missing = tunel_core::password::problems(&master);
        if !missing.is_empty() {
            app.sync.oauth.signed_in = Some(sign_in);
            return app.notify(format!(
                "Tu contraseña maestra no cumple las reglas para cifrar la sincronización. {}. \
                 Cámbiala en Ajustes → Seguridad y vuelve a intentarlo.",
                tunel_core::password::describe(&missing)
            ));
        }
    }
    let (Some(vault), Some(data)) = (app.vault.as_ref(), app.data().cloned()) else {
        return;
    };
    let check = vault.password_check();
    app.sync.status = SyncStatus::Linking;
    let round = app.sync.begin(data.clone());
    app.engine
        .oauth_complete(round, sign_in, master, data, check);
}

/// La contraseña maestra va a cambiar: con una cuenta de proveedor, primero se vuelve a
/// envolver la clave en el servidor. Devuelve `false` si no hace falta (y se puede
/// cambiar ya en este equipo).
pub fn rewrap_before_change(app: &mut TunelApp, password: Zeroizing<String>) -> bool {
    let Some(local) = app.sync.local().filter(|l| l.oauth.is_some()).cloned() else {
        return false;
    };
    if app.sync.busy() {
        app.notify("Espera a que termine la sincronización en curso");
        return true;
    }
    let Some(data) = app.data().cloned() else {
        return true;
    };
    let round = app.sync.begin(data);
    app.engine.oauth_rewrap(round, local, password);
    app.notify("Actualizando la clave de la cuenta en el servidor…");
    true
}

pub fn on_event(app: &mut TunelApp, event: OAuthEvent) {
    match event {
        OAuthEvent::Providers { server, result } => {
            if app.sync.oauth.loading.as_deref() == Some(server.as_str()) {
                app.sync.oauth.loading = None;
            }
            match result {
                Ok(list) => app.sync.oauth.providers = Some((server, list)),
                Err(e) => tracing::info!(error = %e, "no se pudieron pedir los proveedores"),
            }
        }
        OAuthEvent::SignedIn { renewing, result } => on_signed_in(app, renewing, result),
        OAuthEvent::Rewrapped {
            round,
            password,
            result,
        } => on_rewrapped(app, round, password, result),
    }
}

fn on_signed_in(app: &mut TunelApp, renewing: bool, result: Result<OAuthSignIn, SyncError>) {
    // Se canceló mientras tanto.
    if app.sync.oauth.waiting.take().is_none() || renewing != app.sync.oauth.renewing {
        return;
    }
    let sign_in = match result {
        Ok(sign_in) => sign_in,
        Err(e) => return app.notify(e.to_string()),
    };
    if !renewing {
        app.sync.oauth.signed_in = Some(sign_in);
        return;
    }
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    if app.sync.busy() {
        return app.notify("Espera a que termine la sincronización en curso");
    }
    match tunel_sync::oauth::renew(&local, sign_in) {
        Ok(renewed) => {
            app.sync.local = Some(renewed);
            save(app);
            app.sync.sign_in_again = false;
            super::sync_now(app);
            app.notify("Sesión renovada; sincronizando…");
        }
        Err(e) => app.notify(e.to_string()),
    }
}

fn on_rewrapped(
    app: &mut TunelApp,
    round: u64,
    password: Zeroizing<String>,
    result: Result<Box<SyncLocal>, SyncError>,
) {
    if app.sync.finish(round).is_none() {
        return;
    }
    let local = match result {
        Ok(local) => *local,
        Err(e) => {
            return app.notify(format!(
                "No se cambió la contraseña maestra: no se pudo actualizar la cuenta ({e})"
            ));
        }
    };
    // El servidor ya tiene la clave envuelta con la nueva: se guarda antes de cambiar la
    // de este equipo, para poder repetir si lo siguiente falla.
    app.sync.local = Some(local);
    save(app);
    let changed = app
        .vault
        .as_mut()
        .map(|v| v.change_password(&password).map_err(|e| e.to_string()));
    app.notify(match changed {
        Some(Ok(())) => "Contraseña maestra cambiada, también para la sincronización".to_string(),
        Some(Err(e)) => format!(
            "La cuenta ya usa la contraseña nueva, pero no se pudo cambiar en este equipo: {e}. \
             Vuelve a intentarlo con la misma."
        ),
        None => return,
    });
    app.sync.schedule_in(Duration::ZERO);
}
