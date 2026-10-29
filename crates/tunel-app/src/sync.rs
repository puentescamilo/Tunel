//! Sincronización de la bóveda desde la interfaz: cuándo sincronizar, qué hacer con el
//! resultado y el formulario para unir el equipo a una cuenta.
//!
//! La bóveda local manda: se puede trabajar sin conexión y los cambios esperan en la cola
//! hasta que el servidor responde. Las rondas corren en segundo plano sobre una copia; lo
//! que se edite mientras tanto se vuelve a aplicar encima del resultado.

use crate::app::TunelApp;
use crate::engine::LinkAccount;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tunel_core::store::MIN_PASSWORD_LEN;
use tunel_core::sync::{SyncLocal, record};
use tunel_core::vault::VaultData;
use tunel_sync::{SyncError, SyncOutcome};
use zeroize::{Zeroize, Zeroizing};

/// Espera tras un cambio local antes de subirlo, para agrupar ediciones seguidas.
const DEBOUNCE: Duration = Duration::from_secs(2);
/// Cada cuánto se comprueba si otros equipos subieron cambios.
const PERIOD: Duration = Duration::from_secs(5 * 60);
/// Primer reintento tras un fallo pasajero; se dobla hasta `MAX_BACKOFF`.
const FIRST_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// Mínimo para la contraseña de una cuenta nueva: con el servidor comprometido se podría
/// intentar adivinar sin límite, así que se pide más que para la bóveda local.
const MIN_ACCOUNT_PASSWORD_LEN: usize = 12;

/// Número de cada tarea en segundo plano. Es global para que no se repita aunque se
/// bloquee la bóveda y se cree un controlador nuevo: así el resultado de una tarea vieja
/// nunca se confunde con el de la actual.
static NEXT_ROUND: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// El equipo no está unido a ninguna cuenta.
    Off,
    /// Creando la cuenta o iniciando sesión.
    Linking,
    Idle {
        last: Option<SystemTime>,
    },
    Running,
    Failed {
        message: String,
        retrying: bool,
    },
}

/// Campos del formulario de la cuenta.
#[derive(Default)]
pub struct AccountForm {
    pub server: String,
    pub email: String,
    pub password: String,
    pub confirm: String,
}

impl AccountForm {
    fn clear_secrets(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }
}

impl Drop for AccountForm {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

/// Tarea de sincronización en curso: su número y la bóveda con la que empezó.
struct Running {
    round: u64,
    snapshot: VaultData,
}

pub struct SyncController {
    local: Option<SyncLocal>,
    running: Option<Running>,
    status: SyncStatus,
    next: Option<Instant>,
    backoff: Duration,
    pub form: AccountForm,
}

impl Default for SyncController {
    fn default() -> Self {
        Self {
            local: None,
            running: None,
            status: SyncStatus::Off,
            next: None,
            backoff: FIRST_BACKOFF,
            form: AccountForm::default(),
        }
    }
}

impl SyncController {
    pub fn status(&self) -> &SyncStatus {
        &self.status
    }

    pub fn account(&self) -> Option<(&str, &str)> {
        self.local
            .as_ref()
            .map(|l| (l.server.as_str(), l.email.as_str()))
    }

    pub fn pending(&self) -> usize {
        self.local.as_ref().map_or(0, |l| l.state.pending.len())
    }

    pub fn busy(&self) -> bool {
        self.running.is_some()
    }

    /// Empieza una tarea y devuelve su número.
    fn begin(&mut self, snapshot: VaultData) -> u64 {
        let round = NEXT_ROUND.fetch_add(1, Ordering::Relaxed);
        self.running = Some(Running { round, snapshot });
        round
    }

    /// Termina la tarea `round` y devuelve su bóveda inicial; `None` si el resultado es de
    /// una tarea que ya no es la actual (por ejemplo, de antes de bloquear la bóveda).
    fn finish(&mut self, round: u64) -> Option<VaultData> {
        match &self.running {
            Some(running) if running.round == round => self.running.take().map(|r| r.snapshot),
            _ => None,
        }
    }

    /// Cuánto falta para la próxima ronda, para pedir a la interfaz que despierte.
    pub fn wait(&self) -> Option<Duration> {
        self.next
            .filter(|_| self.local.is_some() && !self.busy())
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    fn schedule_in(&mut self, delay: Duration) {
        let at = Instant::now() + delay;
        self.next = Some(self.next.map_or(at, |current| current.min(at)));
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Vuelve a aplicar sobre `result` lo que cambió en la bóveda de `snapshot` a `current`
/// mientras la tarea estaba en segundo plano. Esos cambios quedan pendientes de subir con
/// una marca nueva, así que ganan a lo que llegó del servidor.
fn rebase(
    snapshot: &VaultData,
    current: &VaultData,
    result: &VaultData,
    local: SyncLocal,
) -> Result<(VaultData, SyncLocal), serde_json::Error> {
    let edits = record::diff(snapshot, current)?;
    let merged = VaultData {
        settings: current.settings.clone(),
        ..record::apply(result, &edits)?
    };
    let state = local.state.record_local(result, &merged, now_millis())?;
    Ok((merged, SyncLocal { state, ..local }))
}

/// Carga la configuración al desbloquear la bóveda y programa una ronda.
pub fn on_unlock(app: &mut TunelApp) {
    app.sync = SyncController::default();
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    match vault.load_sync() {
        Ok(Some(local)) => {
            app.sync.local = Some(local);
            app.sync.status = SyncStatus::Idle { last: None };
            app.sync.schedule_in(Duration::ZERO);
        }
        Ok(None) => {}
        Err(e) => app.notify(format!(
            "No se pudo leer la configuración de sincronización: {e}"
        )),
    }
}

fn save(app: &mut TunelApp) {
    let (Some(vault), Some(local)) = (app.vault.as_ref(), app.sync.local.as_ref()) else {
        return;
    };
    if let Err(e) = vault.save_sync(local) {
        app.notify(format!(
            "No se pudo guardar el estado de la sincronización: {e}"
        ));
    }
}

/// Anota en la cola un cambio local recién guardado y programa la subida.
pub fn after_commit(app: &mut TunelApp, old: &VaultData, new: &VaultData) {
    let Some(local) = app.sync.local.as_mut() else {
        return;
    };
    match local.state.record_local(old, new, now_millis()) {
        Ok(state) if state != local.state => {
            local.state = state;
            save(app);
            app.sync.schedule_in(DEBOUNCE);
        }
        Ok(_) => {}
        Err(e) => app.notify(format!(
            "No se pudo anotar el cambio para sincronizarlo: {e}"
        )),
    }
}

/// Lanza una ronda si toca.
pub fn tick(app: &mut TunelApp) {
    let due = app.sync.next.is_some_and(|at| at <= Instant::now());
    if !due || app.sync.busy() {
        return;
    }
    let (Some(local), Some(data)) = (app.sync.local.clone(), app.data().cloned()) else {
        return;
    };
    app.sync.next = None;
    app.sync.status = SyncStatus::Running;
    let round = app.sync.begin(data.clone());
    app.engine.sync(round, local, data);
}

pub fn sync_now(app: &mut TunelApp) {
    app.sync.backoff = FIRST_BACKOFF;
    app.sync.schedule_in(Duration::ZERO);
}

fn describe(error: &SyncError) -> String {
    match error {
        SyncError::Unauthorized => {
            "El servidor ya no acepta la clave de esta cuenta (¿se cambió la contraseña en otro \
             equipo?). Desvincula el equipo y vuelve a iniciar sesión."
                .into()
        }
        SyncError::Integrity(_) | SyncError::Crypto(_) => format!(
            "{error}. No se aplicó nada: la bóveda local está intacta. Si el problema sigue, \
             comprueba el servidor; desvincular y volver a iniciar sesión vuelve a subir la \
             bóveda de este equipo."
        ),
        other => other.to_string(),
    }
}

pub fn on_finished(app: &mut TunelApp, round: u64, result: Result<Box<SyncOutcome>, SyncError>) {
    let Some(snapshot) = app.sync.finish(round) else {
        return;
    };
    match result {
        Ok(outcome) => apply_outcome(app, &snapshot, *outcome),
        Err(e) => {
            tracing::warn!(error = %e, "la sincronización falló");
            fail(app, describe(&e), e.is_transient());
        }
    }
}

/// Marca la ronda como fallida y, si es pasajero, la reintenta más tarde.
fn fail(app: &mut TunelApp, message: String, retrying: bool) {
    app.sync.status = SyncStatus::Failed { message, retrying };
    if retrying {
        let delay = app.sync.backoff;
        app.sync.backoff = (delay * 2).min(MAX_BACKOFF);
        app.sync.schedule_in(delay);
    }
}

fn apply_outcome(app: &mut TunelApp, snapshot: &VaultData, outcome: SyncOutcome) {
    let Some(current) = app.data().cloned() else {
        return;
    };
    let (data, local) = match rebase(snapshot, &current, &outcome.data, outcome.local) {
        Ok(rebased) => rebased,
        Err(e) => {
            return fail(
                app,
                format!("No se pudo combinar lo sincronizado: {e}"),
                false,
            );
        }
    };
    // Si la bóveda no se puede guardar, tampoco se adopta el estado nuevo: diría que los
    // registros ya están aplicados y no se volverían a descargar.
    if data != current
        && let Err(e) = app.commit_synced(data)
    {
        return fail(
            app,
            format!("No se pudo guardar la bóveda sincronizada: {e}"),
            true,
        );
    }
    let has_pending = !local.state.pending.is_empty();
    app.sync.local = Some(local);
    save(app);
    if !outcome.rejected.is_empty() {
        app.notify(format!(
            "Sincronización: se apartaron {} elementos que esta versión de Túnel no reconoce",
            outcome.rejected.len()
        ));
    }
    app.sync.status = SyncStatus::Idle {
        last: Some(SystemTime::now()),
    };
    app.sync.backoff = FIRST_BACKOFF;
    app.sync
        .schedule_in(if has_pending { DEBOUNCE } else { PERIOD });
}

/// Comprueba el formulario y une el equipo a una cuenta en segundo plano.
pub fn link(app: &mut TunelApp, how: LinkAccount) {
    let form = &app.sync.form;
    let check = || -> Result<tunel_sync::ServerUrl, String> {
        let server = tunel_sync::check_server_url(&form.server).map_err(|e| e.to_string())?;
        if !form.email.contains('@') {
            return Err("Escribe el correo de la cuenta".into());
        }
        let minimum = match how {
            LinkAccount::Create => MIN_ACCOUNT_PASSWORD_LEN,
            LinkAccount::SignIn => MIN_PASSWORD_LEN,
        };
        if form.password.chars().count() < minimum {
            return Err(format!(
                "La contraseña de la cuenta debe tener al menos {minimum} caracteres"
            ));
        }
        if matches!(how, LinkAccount::Create) && form.password != form.confirm {
            return Err("Las contraseñas no coinciden".into());
        }
        Ok(server)
    };
    let server = match check() {
        Ok(server) => server,
        Err(message) => return app.notify(message),
    };
    let Some(data) = app.data().cloned() else {
        return;
    };
    let password = Zeroizing::new(form.password.clone());
    let email = form.email.trim().to_string();
    app.sync.form.clear_secrets();
    app.sync.status = SyncStatus::Linking;
    let round = app.sync.begin(data.clone());
    app.engine
        .link_account(round, how, server, email, password, data);
}

pub fn on_linked(app: &mut TunelApp, round: u64, result: Result<Box<SyncLocal>, SyncError>) {
    let Some(snapshot) = app.sync.finish(round) else {
        return;
    };
    let local = match result {
        Ok(local) => *local,
        Err(e) => {
            app.sync.status = SyncStatus::Off;
            app.notify(describe(&e));
            return;
        }
    };
    let Some(current) = app.data().cloned() else {
        app.sync.status = SyncStatus::Off;
        return;
    };
    // Lo editado mientras se derivaban las claves también tiene que subir.
    match local.state.record_local(&snapshot, &current, now_millis()) {
        Ok(state) => app.sync.local = Some(SyncLocal { state, ..local }),
        Err(e) => {
            app.sync.status = SyncStatus::Off;
            return app.notify(format!("No se pudo preparar la sincronización: {e}"));
        }
    }
    save(app);
    app.sync.status = SyncStatus::Idle { last: None };
    app.sync.schedule_in(Duration::ZERO);
    app.notify("Equipo unido a la cuenta; sincronizando…");
}

/// Desvincula el equipo de la cuenta. La bóveda local se queda como está.
pub fn unlink(app: &mut TunelApp) {
    if app.sync.busy() {
        return app.notify("Espera a que termine la sincronización en curso");
    }
    let Some(local) = app.sync.local.take() else {
        return;
    };
    app.engine.sign_out(local);
    if let Some(vault) = app.vault.as_ref()
        && let Err(e) = vault.delete_sync()
    {
        app.notify(format!(
            "No se pudo borrar la configuración de sincronización: {e}"
        ));
    }
    app.sync = SyncController::default();
    app.notify("Equipo desvinculado de la cuenta; la bóveda local no cambia");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::model::Host;
    use tunel_core::sync::{SyncState, VaultKey};
    use uuid::Uuid;

    fn local(data: &VaultData) -> SyncLocal {
        SyncLocal {
            server: "https://tunel.ejemplo.com".into(),
            email: "ana@ejemplo.com".into(),
            auth: Zeroizing::new(String::new()),
            vault_key: VaultKey::generate(),
            token: None,
            state: SyncState::adopt(Uuid::from_u128(1), data, 1).unwrap(),
        }
    }

    #[test]
    fn edits_made_during_a_sync_are_kept_and_queued() {
        let snapshot = VaultData::default().with_host(Host::new("web", "1.1.1.1"));
        // Durante la ronda el usuario añade un host...
        let current = snapshot.with_host(Host::new("nuevo", "2.2.2.2"));
        // ...y del servidor llega otro.
        let result = snapshot.with_host(Host::new("remoto", "3.3.3.3"));
        let synced = SyncLocal {
            state: SyncState::new(Uuid::from_u128(1)),
            ..local(&snapshot)
        };
        let (data, local) = rebase(&snapshot, &current, &result, synced).unwrap();
        let mut labels: Vec<&str> = data.hosts.iter().map(|h| h.label.as_str()).collect();
        labels.sort_unstable();
        assert_eq!(labels, ["nuevo", "remoto", "web"]);
        assert_eq!(local.state.pending.len(), 1);
    }

    #[test]
    fn results_of_an_older_task_are_ignored() {
        let mut controller = SyncController::default();
        let old = controller.begin(VaultData::default());
        // Se bloquea la bóveda y empieza otra tarea con un controlador nuevo.
        let mut controller = SyncController::default();
        let current = controller.begin(VaultData::default());
        assert!(controller.finish(old).is_none());
        assert!(controller.busy());
        assert!(controller.finish(current).is_some());
        assert!(!controller.busy());
    }

    #[test]
    fn without_edits_the_result_is_used_as_is() {
        let snapshot = VaultData::default().with_host(Host::new("web", "1.1.1.1"));
        let result = snapshot.with_host(Host::new("remoto", "3.3.3.3"));
        let synced = SyncLocal {
            state: SyncState::new(Uuid::from_u128(1)),
            ..local(&snapshot)
        };
        let (data, local) = rebase(&snapshot, &snapshot, &result, synced).unwrap();
        assert_eq!(data, result);
        assert!(local.state.pending.is_empty());
    }
}
