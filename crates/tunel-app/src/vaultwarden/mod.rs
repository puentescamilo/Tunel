//! Vaultwarden desde la interfaz: conectar la cuenta, sincronizar en segundo plano y dar a
//! las conexiones los secretos de las identidades vinculadas.
//!
//! Es opcional: sin cuenta no hay archivo, ni tareas, ni secretos externos, y Túnel conecta
//! como siempre. Si Vaultwarden falla, se usa la copia local (7 días) y, sin ella, SSH pide la
//! contraseña al conectar.

pub mod import;
pub mod mover;

use crate::app::TunelApp;
use crate::engine::AppEvent;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tunel_core::vault::VaultData;
use tunel_core::vaultwarden::{CACHE_TTL_MS, ExternalSecret, VaultwardenLocal};
use tunel_vaultwarden::{
    Content, Credentials, Device, Item, SecondFactor, Session, SymmetricKey, TwoFactorProvider,
    Vault, VwError, check_server_url,
};
use zeroize::{Zeroize, Zeroizing};

/// Cada cuánto se vuelve a sincronizar con Vaultwarden.
const PERIOD: Duration = Duration::from_secs(30 * 60);
/// Tras un fallo de red se reintenta antes.
const RETRY: Duration = Duration::from_secs(5 * 60);

/// Número de cada tarea; global para no confundir el resultado de una tarea de antes de
/// bloquear con el de la actual.
static NEXT_ROUND: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VwStatus {
    /// Sin cuenta de Vaultwarden en este equipo.
    Off,
    SigningIn,
    /// La cuenta pide el segundo factor.
    NeedsCode(Vec<TwoFactorProvider>),
    Syncing,
    Ready {
        last: SystemTime,
    },
    /// Hay cuenta pero no sesión: hay que volver a escribir la contraseña.
    SignedOut,
    Failed {
        message: String,
    },
}

#[derive(Default)]
pub struct VwForm {
    pub server: String,
    pub email: String,
    pub password: String,
    pub code: String,
    /// El código del segundo factor es el que llegó por correo.
    pub email_code: bool,
}

impl VwForm {
    fn clear_secrets(&mut self) {
        self.password.zeroize();
        self.code.zeroize();
    }
}

impl Drop for VwForm {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

pub enum VwEvent {
    /// Terminó un inicio de sesión. Con segundo factor pendiente vuelven las credenciales
    /// para no derivar otra vez la contraseña.
    SignedIn {
        round: u64,
        result: Result<(Session, Vault), VwError>,
        pending: Option<Credentials>,
    },
    CodeSent {
        round: u64,
        result: Result<(), VwError>,
        credentials: Credentials,
    },
    Synced {
        round: u64,
        session: Session,
        result: Result<Vault, VwError>,
    },
    Moved(mover::Moved),
}

pub struct VaultwardenController {
    local: Option<VaultwardenLocal>,
    /// `None` mientras una tarea la usa o si no hay sesión.
    session: Option<Session>,
    /// La última sincronización, solo en memoria, y cuándo se hizo (ms desde 1970).
    vault: Option<Vault>,
    synced_at_ms: u64,
    /// Credenciales esperando el código del segundo factor.
    pending: Option<Credentials>,
    round: Option<u64>,
    status: VwStatus,
    next: Option<Instant>,
    /// Lo último de lo que se avisó, para no repetirlo en cada sincronización.
    warned: Vec<String>,
    pub form: VwForm,
    /// Ventana «Importar de Vaultwarden» abierta.
    pub import: Option<import::ImportDialog>,
}

impl Default for VaultwardenController {
    fn default() -> Self {
        Self {
            local: None,
            session: None,
            vault: None,
            synced_at_ms: 0,
            pending: None,
            round: None,
            status: VwStatus::Off,
            next: None,
            warned: Vec::new(),
            form: VwForm::default(),
            import: None,
        }
    }
}

impl VaultwardenController {
    pub fn status(&self) -> &VwStatus {
        &self.status
    }

    pub fn busy(&self) -> bool {
        self.round.is_some()
    }

    /// Servidor y correo de la cuenta conectada.
    pub fn account(&self) -> Option<(&str, &str)> {
        self.local
            .as_ref()
            .map(|l| (l.server.as_str(), l.email.as_str()))
    }

    /// La última sincronización, para elegir un elemento al vincular una identidad.
    pub fn vault(&self) -> Option<&Vault> {
        self.vault.as_ref()
    }

    /// Los elementos que se pueden vincular a una identidad, para el editor.
    pub fn choices(&self) -> Choices {
        let mut names: HashMap<String, String> = self
            .local
            .iter()
            .flat_map(|l| &l.cache)
            .map(|c| (c.item_id.clone(), c.secret.name.clone()))
            .collect();
        let items = self.vault.as_ref().map_or_else(Vec::new, |vault| {
            vault
                .items
                .iter()
                .map(|item| {
                    names.insert(item.id.clone(), item.name.clone());
                    ItemChoice {
                        item_id: item.id.clone(),
                        organization_id: item.organization_id.clone(),
                        label: describe(item, vault),
                    }
                })
                .collect()
        });
        let targets = |team: Option<&str>| {
            self.vault.as_ref().map_or_else(Vec::new, |v| {
                mover::destinations(&v.collections, v.personal_vault_disabled, team)
            })
        };
        Choices {
            connected: self.local.is_some(),
            items,
            names,
            move_personal: targets(None),
            move_team: targets(Some("team")),
            busy: self.busy(),
        }
    }

    /// Cuánto falta para la próxima sincronización, para despertar la interfaz.
    pub fn wait(&self) -> Option<Duration> {
        self.next
            .filter(|_| !self.busy())
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    fn begin(&mut self) -> u64 {
        let round = NEXT_ROUND.fetch_add(1, Ordering::Relaxed);
        self.round = Some(round);
        round
    }

    /// `true` si el resultado es de la tarea actual.
    fn finish(&mut self, round: u64) -> bool {
        if self.round == Some(round) {
            self.round = None;
            return true;
        }
        false
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn device(local: &VaultwardenLocal) -> Device {
    Device {
        id: local.device_id.clone(),
        name: format!("Túnel ({})", std::env::consts::OS),
    }
}

/// Un elemento que se puede vincular a una identidad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemChoice {
    pub item_id: String,
    pub organization_id: Option<String>,
    /// Nombre, usuario o tipo, y colección.
    pub label: String,
}

#[derive(Debug, Default)]
pub struct Choices {
    /// Hay una cuenta de Vaultwarden en este equipo.
    pub connected: bool,
    /// Vacío si aún no se ha sincronizado.
    pub items: Vec<ItemChoice>,
    names: HashMap<String, String>,
    /// Adónde se puede mover una contraseña: para identidades personales y de Teams.
    pub move_personal: Vec<mover::Destination>,
    pub move_team: Vec<mover::Destination>,
    /// Hay una tarea de Vaultwarden en curso.
    pub busy: bool,
}

impl Choices {
    /// Nombre de un elemento: de la sincronización o, sin ella, de la copia local.
    pub fn name(&self, item_id: &str) -> Option<&str> {
        self.names.get(item_id).map(String::as_str)
    }

    pub fn move_targets(&self, team: Option<&str>) -> &[mover::Destination] {
        if team.is_some() {
            &self.move_team
        } else {
            &self.move_personal
        }
    }

    /// Los que puede usar una identidad: en un Team solo los de una organización, que cada
    /// miembro descifra con su propia cuenta.
    pub fn for_identity(&self, team: Option<&str>) -> impl Iterator<Item = &ItemChoice> {
        self.items
            .iter()
            .filter(move |c| team.is_none() || c.organization_id.is_some())
    }
}

fn describe(item: &Item, vault: &Vault) -> String {
    let what = match &item.content {
        Content::Login {
            username: Some(username),
            ..
        } if !username.is_empty() => username.clone(),
        Content::Login { .. } => "sin usuario".to_string(),
        Content::SshKey { .. } => "clave SSH".to_string(),
    };
    let place = if item.organization_id.is_none() {
        "personal".to_string()
    } else {
        let collections: Vec<&str> = vault
            .collections
            .iter()
            .filter(|c| item.collection_ids.contains(&c.id))
            .map(|c| c.name.as_str())
            .collect();
        collections.join(", ")
    };
    format!("{} · {what} · {place}", item.name)
}

/// Campo personalizado del elemento con la contraseña *enable* (sin distinguir mayúsculas).
pub const ENABLE_FIELD: &str = "enable";

/// El secreto que usa una conexión, a partir de un elemento descifrado.
pub fn secret_of(item: &Item) -> ExternalSecret {
    let (username, password, private_key) = match &item.content {
        Content::Login {
            username, password, ..
        } => (username.clone(), password.clone(), None),
        Content::SshKey { private_key, .. } => (None, None, Some(private_key.clone())),
    };
    ExternalSecret {
        name: item.name.clone(),
        organization_id: item.organization_id.clone(),
        username,
        password,
        private_key,
        enable: item
            .field(ENABLE_FIELD)
            .map(|f| f.value.clone())
            .filter(|v| !v.is_empty()),
    }
}

/// Ids de los elementos a los que apunta alguna identidad.
fn linked_items(data: &VaultData) -> Vec<String> {
    let mut ids: Vec<String> = data
        .identities
        .iter()
        .filter_map(|i| i.vaultwarden.as_ref().map(|l| l.item_id.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Los secretos de los elementos vinculados, para conectar. Si la última sincronización tiene
/// menos de 7 días, manda ella: lo que ya no está (borrado o sin acceso) no se usa. Si no, la
/// copia local que no haya caducado.
pub fn secrets_for(
    linked: &[String],
    synced: Option<(&Vault, u64)>,
    local: Option<&VaultwardenLocal>,
    now_ms: u64,
) -> HashMap<String, ExternalSecret> {
    let fresh = synced.filter(|(_, at)| now_ms.saturating_sub(*at) < CACHE_TTL_MS);
    linked
        .iter()
        .filter_map(|id| {
            let secret = match fresh {
                Some((vault, _)) => vault.item(id).map(secret_of),
                None => local.and_then(|l| l.cached(id, now_ms)).cloned(),
            };
            secret.map(|secret| (id.clone(), secret))
        })
        .collect()
}

/// Identidades vinculadas cuyo elemento ya no está en Vaultwarden (borrado o sin acceso).
pub fn missing_links(data: &VaultData, vault: &Vault) -> Vec<String> {
    data.identities
        .iter()
        .filter(|i| {
            i.vaultwarden
                .as_ref()
                .is_some_and(|l| vault.item(&l.item_id).is_none())
        })
        .map(|i| i.label.clone())
        .collect()
}

/// Pone en el motor los secretos actuales y guarda la copia de los vinculados.
fn apply(app: &mut TunelApp) {
    let linked = app.data().map(linked_items).unwrap_or_default();
    let controller = &app.vaultwarden;
    let synced = controller
        .vault
        .as_ref()
        .map(|v| (v, controller.synced_at_ms));
    app.engine.external_secrets =
        secrets_for(&linked, synced, controller.local.as_ref(), now_millis());
    let (Some((vault, at)), Some(local)) = (synced, controller.local.as_ref()) else {
        return;
    };
    // La copia lleva la fecha de la sincronización, no la de ahora: editar una identidad no
    // alarga su vida.
    let fresh: Vec<(String, ExternalSecret)> = linked
        .into_iter()
        .filter_map(|id| vault.item(&id).map(|item| (id, secret_of(item))))
        .collect();
    let updated = local.with_cache(fresh, at);
    if Some(&updated) != app.vaultwarden.local.as_ref() {
        app.vaultwarden.local = Some(updated);
        save(app);
    }
}

fn save(app: &mut TunelApp) {
    let (Some(store), Some(local)) = (app.vault.as_ref(), app.vaultwarden.local.as_ref()) else {
        return;
    };
    if let Err(e) = store.save_vaultwarden(local) {
        app.notify(format!("No se pudo guardar la cuenta de Vaultwarden: {e}"));
    }
}

/// Carga la cuenta al desbloquear y, si hay sesión guardada, sincroniza.
pub fn on_unlock(app: &mut TunelApp) {
    app.vaultwarden = VaultwardenController::default();
    app.engine.external_secrets.clear();
    let Some(store) = app.vault.as_ref() else {
        return;
    };
    match store.load_vaultwarden() {
        Ok(Some(local)) => {
            app.vaultwarden.form.server = local.server.clone();
            app.vaultwarden.form.email = local.email.clone();
            app.vaultwarden.status = VwStatus::SignedOut;
            app.vaultwarden.session = restore(&local);
            if app.vaultwarden.session.is_some() {
                app.vaultwarden.next = Some(Instant::now());
            }
            app.vaultwarden.local = Some(local);
            apply(app);
        }
        Ok(None) => {}
        Err(e) => app.notify(format!("No se pudo leer la cuenta de Vaultwarden: {e}")),
    }
}

fn restore(local: &VaultwardenLocal) -> Option<Session> {
    let server = check_server_url(&local.server).ok()?;
    let refresh = local.refresh_token.as_deref()?;
    let key = base64_key(local.user_key.as_deref()?)?;
    Session::restore(&server, device(local), refresh, key).ok()
}

fn base64_key(text: &str) -> Option<SymmetricKey> {
    use base64::Engine;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()?,
    );
    SymmetricKey::from_bytes(&bytes).ok()
}

fn encode_key(key: &SymmetricKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key.to_bytes().as_slice())
}

/// Cada fotograma: lanza la sincronización periódica si toca.
pub fn tick(app: &mut TunelApp) {
    let due = app.vaultwarden.next.is_some_and(|at| Instant::now() >= at);
    if due && !app.vaultwarden.busy() {
        app.vaultwarden.next = None;
        sync_now(app);
    }
}

/// Sincroniza ya, si hay sesión.
pub fn sync_now(app: &mut TunelApp) {
    let Some(mut session) = app.vaultwarden.session.take() else {
        return;
    };
    let round = app.vaultwarden.begin();
    app.vaultwarden.status = VwStatus::Syncing;
    app.engine.background(async move {
        let result = session.sync().await;
        AppEvent::Vaultwarden(Box::new(VwEvent::Synced {
            round,
            session,
            result,
        }))
    });
}

/// Inicia sesión con lo escrito en el formulario, o termina el segundo factor.
pub fn sign_in(app: &mut TunelApp) {
    if app.vaultwarden.busy() {
        return;
    }
    let form = &mut app.vaultwarden.form;
    let second = match form.code.trim() {
        "" => None,
        code if form.email_code => Some(SecondFactor::Email(code.to_string())),
        code => Some(SecondFactor::Authenticator(code.to_string())),
    };
    let pending = app.vaultwarden.pending.take();
    if pending.is_none() && second.is_some() {
        form.code.zeroize();
    }
    let server = match check_server_url(&form.server) {
        Ok(server) => server,
        Err(e) => return app.notify(e.to_string()),
    };
    if pending.is_none() && (form.email.trim().is_empty() || form.password.is_empty()) {
        return app.notify("Escribe el correo y la contraseña maestra de Vaultwarden");
    }
    let (email, password) = (
        form.email.trim().to_string(),
        Zeroizing::new(form.password.clone()),
    );
    form.clear_secrets();
    let previous = app.vaultwarden.local.clone();
    let same_account = previous
        .as_ref()
        .is_some_and(|l| l.server == server.as_str() && l.email == email);
    let mut local = match previous {
        Some(previous) if same_account => previous,
        // Otra cuenta: nada de la anterior (sesión, copia) sigue en uso. El dispositivo es el
        // mismo equipo.
        previous => {
            let mut new = VaultwardenLocal::default();
            new.device_id = previous
                .map(|p| p.device_id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            app.vaultwarden.vault = None;
            app.engine.external_secrets.clear();
            new
        }
    };
    local.server = server.as_str().to_string();
    local.email = email.clone();
    let device = device(&local);
    let round = app.vaultwarden.begin();
    app.vaultwarden.local = Some(local);
    app.vaultwarden.status = VwStatus::SigningIn;
    app.engine.background(async move {
        let credentials = match pending {
            Some(credentials) => credentials,
            None => match Credentials::new(&server, &email, &password).await {
                Ok(credentials) => credentials,
                Err(e) => {
                    return AppEvent::Vaultwarden(Box::new(VwEvent::SignedIn {
                        round,
                        result: Err(e),
                        pending: None,
                    }));
                }
            },
        };
        let result = async {
            let mut session = credentials.sign_in(&device, second.as_ref()).await?;
            let vault = session.sync().await?;
            Ok((session, vault))
        }
        .await;
        let pending = matches!(result, Err(VwError::TwoFactorRequired(_))).then_some(credentials);
        AppEvent::Vaultwarden(Box::new(VwEvent::SignedIn {
            round,
            result,
            pending,
        }))
    });
}

/// Pide que llegue por correo el código del segundo factor.
pub fn send_email_code(app: &mut TunelApp) {
    if app.vaultwarden.busy() {
        return;
    }
    let (Some(credentials), Some(local)) = (
        app.vaultwarden.pending.take(),
        app.vaultwarden.local.as_ref(),
    ) else {
        return;
    };
    let device = device(local);
    let round = app.vaultwarden.begin();
    app.vaultwarden.form.email_code = true;
    app.engine.background(async move {
        let result = credentials.send_email_code(&device).await;
        AppEvent::Vaultwarden(Box::new(VwEvent::CodeSent {
            round,
            result,
            credentials,
        }))
    });
}

/// Olvida la cuenta en este equipo. Las identidades siguen vinculadas y piden la contraseña
/// al conectar hasta que se vuelva a conectar.
pub fn disconnect(app: &mut TunelApp) {
    let server = app.vaultwarden.form.server.clone();
    app.vaultwarden = VaultwardenController::default();
    app.vaultwarden.form.server = server;
    app.engine.external_secrets.clear();
    if let Some(store) = app.vault.as_ref()
        && let Err(e) = store.delete_vaultwarden()
    {
        app.notify(format!("No se pudo borrar la cuenta de Vaultwarden: {e}"));
    }
}

/// Tras guardar la bóveda: si cambió qué elementos están vinculados, se actualiza la copia.
pub fn after_commit(app: &mut TunelApp, old: &VaultData, new: &VaultData) {
    if app.vaultwarden.local.is_some() && linked_items(old) != linked_items(new) {
        apply(app);
    }
}

pub fn on_event(app: &mut TunelApp, event: VwEvent) {
    match event {
        VwEvent::Moved(moved) => mover::on_moved(app, moved),
        VwEvent::SignedIn {
            round,
            result,
            pending,
        } => {
            if !app.vaultwarden.finish(round) {
                return;
            }
            match result {
                Ok((session, vault)) => {
                    app.vaultwarden.form.code.zeroize();
                    app.vaultwarden.form.email_code = false;
                    signed_in(app, session, vault);
                }
                Err(VwError::TwoFactorRequired(providers)) => {
                    app.vaultwarden.pending = pending;
                    app.vaultwarden.status = VwStatus::NeedsCode(providers);
                }
                Err(e) => failed_sign_in(app, &e),
            }
        }
        VwEvent::CodeSent {
            round,
            result,
            credentials,
        } => {
            if !app.vaultwarden.finish(round) {
                return;
            }
            app.vaultwarden.pending = Some(credentials);
            app.notify(match result {
                Ok(()) => "Vaultwarden mandó el código a tu correo".to_string(),
                Err(e) => format!("No se pudo mandar el código: {e}"),
            });
        }
        VwEvent::Synced {
            round,
            session,
            result,
        } => {
            if !app.vaultwarden.finish(round) {
                return;
            }
            match result {
                Ok(vault) => synced(app, session, vault),
                Err(VwError::SessionExpired) => {
                    // Sin sesión no se sabe si siguen teniendo acceso: solo la copia, con su
                    // fecha.
                    app.vaultwarden.vault = None;
                    app.vaultwarden.local = app.vaultwarden.local.as_ref().map(|l| l.signed_out());
                    apply(app);
                    save(app);
                    app.vaultwarden.status = VwStatus::SignedOut;
                    app.notify(
                        "La sesión de Vaultwarden caducó: vuelve a iniciarla en Ajustes. \
                         Mientras tanto se usa la copia local de las credenciales",
                    );
                }
                Err(e) => {
                    app.vaultwarden.session = Some(session);
                    app.vaultwarden.next = Some(Instant::now() + RETRY);
                    app.vaultwarden.status = VwStatus::Failed {
                        message: e.to_string(),
                    };
                }
            }
        }
    }
}

/// Vuelve a como estaba antes de intentar iniciar sesión: con la cuenta guardada si la había
/// o sin cuenta. Nunca borra lo que hay en disco.
fn back_to_saved(app: &mut TunelApp) {
    app.vaultwarden.pending = None;
    app.vaultwarden.form.clear_secrets();
    let saved = app
        .vault
        .as_ref()
        .and_then(|store| store.load_vaultwarden().ok().flatten());
    app.vaultwarden.status = if saved.is_some() {
        VwStatus::SignedOut
    } else {
        VwStatus::Off
    };
    app.vaultwarden.local = saved;
}

/// «Cancelar» en el segundo factor.
pub fn cancel_sign_in(app: &mut TunelApp) {
    if !app.vaultwarden.busy() {
        back_to_saved(app);
    }
}

fn failed_sign_in(app: &mut TunelApp, error: &VwError) {
    back_to_saved(app);
    app.notify(format!("No se pudo iniciar sesión en Vaultwarden: {error}"));
}

fn signed_in(app: &mut TunelApp, session: Session, vault: Vault) {
    if let Some(local) = app.vaultwarden.local.as_mut() {
        local.user_key = Some(encode_key(session.user_key()));
    }
    synced(app, session, vault);
}

fn synced(app: &mut TunelApp, session: Session, vault: Vault) {
    if let Some(local) = app.vaultwarden.local.as_mut() {
        local.refresh_token = Some(session.refresh_token().to_string());
    }
    let missing = app
        .data()
        .map(|data| missing_links(data, &vault))
        .unwrap_or_default();
    let mut warnings = Vec::new();
    if !vault.unreadable.is_empty() {
        warnings.push(format!(
            "Túnel no pudo leer {} elemento(s) de Vaultwarden",
            vault.unreadable.len()
        ));
    }
    if !missing.is_empty() {
        warnings.push(format!(
            "Credencial no disponible en Vaultwarden: {}. Al conectar se pedirá la contraseña",
            missing.join(", ")
        ));
    }
    if warnings != app.vaultwarden.warned {
        for warning in &warnings {
            app.notify(warning.clone());
        }
        app.vaultwarden.warned = warnings;
    }
    app.vaultwarden.vault = Some(vault);
    app.vaultwarden.synced_at_ms = now_millis();
    app.vaultwarden.session = Some(session);
    app.vaultwarden.status = VwStatus::Ready {
        last: SystemTime::now(),
    };
    app.vaultwarden.next = Some(Instant::now() + PERIOD);
    save(app);
    apply(app);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::{Identity, VaultwardenLink};

    fn linked(label: &str, item: &str) -> Identity {
        let mut identity = Identity::new(label, "admin");
        identity.vaultwarden = Some(VaultwardenLink {
            item_id: item.into(),
            organization_id: None,
        });
        identity
    }

    fn secret(name: &str) -> ExternalSecret {
        ExternalSecret {
            name: name.into(),
            organization_id: None,
            username: None,
            password: Some(format!("{name}-pw")),
            private_key: None,
            enable: None,
        }
    }

    #[test]
    fn the_enable_password_comes_from_the_hidden_enable_field() {
        let item = |fields: Vec<tunel_vaultwarden::Field>| Item {
            id: "sw".into(),
            organization_id: Some("org".into()),
            collection_ids: Vec::new(),
            name: "SW-Core".into(),
            notes: None,
            fields,
            content: Content::Login {
                username: Some("admin".into()),
                password: Some("cisco".into()),
                uris: Vec::new(),
            },
            view_password: true,
        };
        let field = |name: &str, value: &str| tunel_vaultwarden::Field {
            name: name.into(),
            value: value.into(),
            hidden: true,
        };
        let with = secret_of(&item(vec![field("Enable", "en4ble")]));
        assert_eq!(with.enable.as_deref(), Some("en4ble"));
        assert_eq!(with.password.as_deref(), Some("cisco"));
        assert!(secret_of(&item(vec![field("enable", "")])).enable.is_none());
        assert!(secret_of(&item(vec![field("otro", "x")])).enable.is_none());
    }

    #[test]
    fn without_vaultwarden_there_are_no_external_secrets() {
        assert!(secrets_for(&["x".into()], None, None, now_millis()).is_empty());
    }

    #[test]
    fn the_local_copy_is_used_until_it_expires_and_only_for_linked_items() {
        let cache = vec![("sw".into(), secret("sw")), ("otro".into(), secret("otro"))];
        let local = VaultwardenLocal::default().with_cache(cache, 0);
        let linked = ["sw".to_string()];
        let secrets = secrets_for(&linked, None, Some(&local), 1);
        assert_eq!(secrets.len(), 1, "solo los vinculados");
        assert_eq!(secrets["sw"].password.as_deref(), Some("sw-pw"));
        assert!(secrets_for(&linked, None, Some(&local), CACHE_TTL_MS).is_empty());
    }

    #[test]
    fn a_team_identity_only_offers_organization_items() {
        let choice = |id: &str, org: Option<&str>| ItemChoice {
            item_id: id.into(),
            organization_id: org.map(str::to_string),
            label: id.into(),
        };
        let choices = Choices {
            connected: true,
            items: vec![choice("mio", None), choice("switch", Some("org"))],
            ..Choices::default()
        };
        let ids = |team| -> Vec<String> {
            choices
                .for_identity(team)
                .map(|c| c.item_id.clone())
                .collect()
        };
        assert_eq!(ids(None), ["mio", "switch"]);
        assert_eq!(ids(Some("acme")), ["switch"]);
    }

    #[test]
    fn only_linked_items_are_kept_and_each_once() {
        let data = VaultData::default()
            .with_identity(linked("a", "x"))
            .with_identity(linked("b", "x"))
            .with_identity(Identity::new("local", "ana").with_password("p"));
        assert_eq!(linked_items(&data), ["x"]);
    }
}
