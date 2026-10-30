//! Sesiones compartidas desde la interfaz: compartir una pestaña de terminal con un Team,
//! ver las sesiones en vivo de los Teams y mirarlas.
//!
//! Las operaciones con el servidor corren en el motor y vuelven como [`LiveEvent`]. No
//! pasan por el controlador de sincronización: no cambian la bóveda ni la configuración,
//! salvo el token de sesión, que se renueva solo si hace falta.

use crate::app::{Tab, TunelApp};
use crate::session::TerminalSession;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};
use tunel_core::io::SessionIo;
use tunel_core::sync::protocol::ConnId;
use tunel_core::sync::{KeyProblem, PublicKey, SyncLocal};
use tunel_sync::SyncError;
use tunel_sync::live::{LiveHost, LiveListing, LiveViewer};
use tunel_sync::teams::KeyStatus;

/// Cada cuánto se vuelven a pedir las sesiones en vivo mientras se ven los hosts.
pub const REFRESH: Duration = Duration::from_secs(20);
/// Mientras hay sesiones compartidas abiertas, la interfaz se repinta al menos con esta
/// frecuencia para atender llegadas y peticiones de control.
pub const POLL: Duration = Duration::from_millis(250);

/// Quien está mirando una terminal que se comparte.
pub struct Watcher {
    pub email: String,
    pub control: bool,
}

/// Una terminal propia que se comparte.
pub struct Share {
    pub host: LiveHost,
    pub team_name: String,
    /// Época de la clave del Team con la que se cifró el anuncio.
    pub epoch: u64,
    pub viewers: BTreeMap<ConnId, Watcher>,
    /// Peticiones de control sin responder, por orden de llegada.
    pub requests: Vec<ConnId>,
    /// Se está buscando la clave de esta persona para darle el control.
    pub looking_up: Option<ConnId>,
    /// Hay que comparar la huella de esta persona antes de darle el control.
    pub confirm: Option<(ConnId, String, PublicKey)>,
}

impl Share {
    pub fn forget(&mut self, conn: ConnId) {
        self.viewers.remove(&conn);
        self.requests.retain(|c| *c != conn);
        if self.confirm.as_ref().is_some_and(|(c, _, _)| *c == conn) {
            self.confirm = None;
        }
        if self.looking_up == Some(conn) {
            self.looking_up = None;
        }
    }
}

/// La sesión de otra persona que se está mirando.
pub struct Watching {
    pub viewer: LiveViewer,
    pub owner: String,
    pub team_name: String,
    pub control: bool,
    /// Se pidió el control y no hubo respuesta todavía.
    pub requested: bool,
    /// Huella de quien comparte si nunca se confirmó su clave.
    pub unverified: Option<String>,
}

pub enum Live {
    Host(Box<Share>),
    Viewer(Box<Watching>),
}

/// Resultados de las operaciones en segundo plano.
pub enum LiveEvent {
    Shared {
        tab: u64,
        team: String,
        epoch: u64,
        result: Result<LiveHost, SyncError>,
    },
    Listed {
        team: String,
        result: Result<Vec<LiveListing>, SyncError>,
    },
    Watching {
        listing: Box<LiveListing>,
        result: Result<(LiveViewer, SessionIo), SyncError>,
    },
    /// Clave de quien pidió el control, según el servidor.
    Key {
        tab: u64,
        conn: ConnId,
        email: String,
        result: Result<PublicKey, SyncError>,
    },
}

/// Corre la operación en el motor.
pub async fn share(local: SyncLocal, team: String, title: String) -> Result<LiveHost, SyncError> {
    tunel_sync::live::share(&local, &team, &title)
        .await
        .map(|(_, host)| host)
}

pub async fn list(local: SyncLocal, team: String) -> Result<Vec<LiveListing>, SyncError> {
    tunel_sync::live::live_sessions(&local, &team)
        .await
        .map(|(_, listings)| listings)
}

pub async fn watch(
    local: SyncLocal,
    listing: LiveListing,
) -> Result<(LiveViewer, SessionIo), SyncError> {
    tunel_sync::live::watch(&local, &listing)
        .await
        .map(|(_, viewer, io)| (viewer, io))
}

pub async fn lookup(local: SyncLocal, email: String) -> Result<PublicKey, SyncError> {
    tunel_sync::teams::lookup_key(&local, &email)
        .await
        .map(|(_, key)| key)
}

/// Sesiones en vivo de los Teams, para la franja de la vista de hosts.
#[derive(Default)]
pub struct LiveUi {
    pub sessions: BTreeMap<String, Vec<LiveListing>>,
    refreshed: Option<Instant>,
    loading: usize,
    /// Pidiendo mirar esta sesión.
    pub opening: Option<String>,
    /// Automatización para capturas y pruebas manuales (`TUNEL_DEV_LIVE`).
    pub dev: Option<String>,
}

impl LiveUi {
    /// Todas las sesiones en vivo de otras personas.
    pub fn listings(&self) -> impl Iterator<Item = &LiveListing> {
        self.sessions.values().flatten()
    }
}

fn team_name(app: &TunelApp, team: &str) -> String {
    app.sync
        .local()
        .and_then(|l| l.team(team))
        .map_or_else(|| "Team".to_string(), |t| t.name.clone())
}

fn terminal(app: &mut TunelApp, tab: u64) -> Option<&mut TerminalSession> {
    app.tabs.iter_mut().find_map(|t| match t {
        Tab::Terminal(session) if session.key == tab => Some(session.as_mut()),
        _ => None,
    })
}

fn share_of(app: &mut TunelApp, tab: u64) -> Option<&mut Share> {
    match terminal(app, tab)?.live.as_mut()? {
        Live::Host(share) => Some(share),
        Live::Viewer(_) => None,
    }
}

/// Empieza a compartir la pestaña `tab` con el Team `team`.
pub fn start_sharing(app: &mut TunelApp, tab: u64, team: String) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    let Some(epoch) = local.team(&team).map(|t| t.epoch) else {
        return;
    };
    let Some(session) = terminal(app, tab) else {
        return;
    };
    let title = session.title.clone();
    app.engine.live_share(tab, local, team, epoch, title);
}

pub fn stop_sharing(app: &mut TunelApp, tab: u64) {
    if let Some(session) = terminal(app, tab)
        && matches!(session.live, Some(Live::Host(_)))
    {
        session.live = None;
        app.notify("Se dejó de compartir la terminal");
    }
}

/// Vuelve a pedir las sesiones en vivo si toca.
pub fn refresh_if_due(app: &mut TunelApp) {
    let due = app.live.refreshed.is_none_or(|at| at.elapsed() >= REFRESH);
    if due && app.live.loading == 0 {
        refresh(app);
    }
}

pub fn refresh(app: &mut TunelApp) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    if local.keypair.is_none() {
        return;
    }
    app.live.refreshed = Some(Instant::now());
    app.live
        .sessions
        .retain(|team, _| local.team(team).is_some());
    for team in &local.teams {
        app.live.loading += 1;
        app.engine.live_list(local.clone(), team.id.clone());
    }
}

pub fn start_watching(app: &mut TunelApp, listing: LiveListing) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    app.live.opening = Some(listing.id.clone());
    app.engine.live_watch(local, listing);
}

/// Busca la clave de quien pidió el control para dárselo.
pub fn grant(app: &mut TunelApp, tab: u64, conn: ConnId) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    let Some(share) = share_of(app, tab) else {
        return;
    };
    let Some(email) = share.viewers.get(&conn).map(|v| v.email.clone()) else {
        return;
    };
    share.requests.retain(|c| *c != conn);
    share.looking_up = Some(conn);
    app.engine.live_lookup(tab, conn, email, local);
}

/// La persona comparó la huella: se fija la clave y se da el control.
pub fn confirm_grant(app: &mut TunelApp, tab: u64) {
    let Some((conn, email, key)) = share_of(app, tab).and_then(|s| s.confirm.take()) else {
        return;
    };
    crate::sync::teams::trust_key(app, &email, key, false);
    let trusted = app
        .sync
        .local()
        .is_some_and(|l| l.check_key(&email, key).is_ok());
    if trusted && let Some(share) = share_of(app, tab) {
        give(share, conn, key);
    }
}

fn give(share: &mut Share, conn: ConnId, key: PublicKey) {
    if let Some(viewer) = share.viewers.get_mut(&conn) {
        viewer.control = true;
        share.host.grant(conn, key);
    }
}

pub fn on_event(app: &mut TunelApp, event: LiveEvent) {
    match event {
        LiveEvent::Shared {
            tab,
            team,
            epoch,
            result,
        } => on_shared(app, tab, team, epoch, result),
        LiveEvent::Listed { team, result } => {
            app.live.loading = app.live.loading.saturating_sub(1);
            match result {
                Ok(listings) => {
                    let own = app
                        .sync
                        .local()
                        .map(|l| l.email.clone())
                        .unwrap_or_default();
                    let first = listings.iter().find(|l| l.owner != own).cloned();
                    app.live.sessions.insert(team, listings);
                    if let Some(listing) = first
                        && app.live.dev.as_deref() == Some("mirar")
                    {
                        app.live.dev = Some("pedir".into());
                        start_watching(app, listing);
                    }
                }
                // Un servidor sin sesiones compartidas responde 404: no hay nada que mostrar.
                Err(SyncError::NotFound(_)) => {
                    app.live.sessions.remove(&team);
                }
                Err(e) => tracing::info!(error = %e, "no se pudieron listar las sesiones en vivo"),
            }
        }
        LiveEvent::Watching { listing, result } => on_watching(app, *listing, result),
        LiveEvent::Key {
            tab,
            conn,
            email,
            result,
        } => on_key(app, tab, conn, email, result),
    }
}

fn on_shared(
    app: &mut TunelApp,
    tab: u64,
    team: String,
    epoch: u64,
    result: Result<LiveHost, SyncError>,
) {
    let host = match result {
        Ok(host) => host,
        Err(e) => {
            return app.notify(format!(
                "No se pudo compartir la terminal: {}",
                describe(&e)
            ));
        }
    };
    let team_name = team_name(app, &team);
    // Si la pestaña se cerró mientras tanto, la sesión termina al soltar `host`.
    let Some(session) = terminal(app, tab) else {
        return;
    };
    session.live = Some(Live::Host(Box::new(Share {
        host,
        team_name: team_name.clone(),
        epoch,
        viewers: BTreeMap::new(),
        requests: Vec::new(),
        looking_up: None,
        confirm: None,
    })));
    app.notify(format!(
        "Compartiendo con «{team_name}»: sus miembros la ven en Hosts → En vivo"
    ));
}

fn on_watching(
    app: &mut TunelApp,
    listing: LiveListing,
    result: Result<(LiveViewer, SessionIo), SyncError>,
) {
    app.live.opening = None;
    let (viewer, io) = match result {
        Ok(opened) => opened,
        Err(e) => {
            // Puede que ya haya terminado: la lista se pone al día.
            refresh(app);
            return app.notify(format!("No se pudo abrir la sesión: {}", describe(&e)));
        }
    };
    let io = app.engine.wake(io);
    let scrollback = app.data().map_or(10_000, |d| d.settings.scrollback_lines);
    let title = listing.title.clone().unwrap_or_else(|| "Sesión".into());
    let mut session = TerminalSession::new(
        format!(
            "{title} · {}",
            listing.owner.split('@').next().unwrap_or(&listing.owner)
        ),
        None,
        crate::app::DEFAULT_COLS,
        crate::app::DEFAULT_ROWS,
        scrollback,
        io,
    );
    session.live = Some(Live::Viewer(Box::new(Watching {
        viewer,
        owner: listing.owner.clone(),
        team_name: team_name(app, &listing.team),
        control: false,
        requested: false,
        unverified: matches!(listing.owner_key, Some(KeyStatus::New))
            .then(|| listing.owner_fingerprint())
            .flatten(),
    })));
    if app.live.dev.as_deref() == Some("pedir")
        && let Some(Live::Viewer(watching)) = session.live.as_mut()
    {
        watching.viewer.request_control();
        watching.requested = true;
        app.live.dev = Some("escribir".into());
    }
    app.open_tab(Tab::Terminal(Box::new(session)));
}

fn on_key(
    app: &mut TunelApp,
    tab: u64,
    conn: ConnId,
    email: String,
    result: Result<PublicKey, SyncError>,
) {
    let local = app.sync.local().cloned();
    let Some(share) = share_of(app, tab) else {
        return;
    };
    share.looking_up = None;
    if !share.viewers.contains_key(&conn) {
        return;
    }
    let key = match result {
        Ok(key) => key,
        Err(e) => {
            return app.notify(format!(
                "No se pudo dar el control a {email}: {}",
                describe(&e)
            ));
        }
    };
    let checked = local.map(|l| l.check_key(&email, key));
    match checked {
        Some(Ok(())) => give(share, conn, key),
        Some(Err(KeyProblem::Unconfirmed(_))) => share.confirm = Some((conn, email, key)),
        Some(Err(problem @ KeyProblem::Changed(_))) => {
            app.notify(format!("No se da el control: {problem}"));
        }
        None => {}
    }
}

/// Mantiene al día las sesiones que se comparten: si cambió la clave del Team, el
/// anuncio se vuelve a cifrar para que los miembros puedan seguir abriéndolo.
pub fn tick(app: &mut TunelApp) {
    let epochs: HashMap<String, (u64, tunel_core::sync::VaultKey)> = app
        .sync
        .local()
        .map(|l| {
            l.teams
                .iter()
                .map(|t| (t.id.clone(), (t.epoch, t.key.clone())))
                .collect()
        })
        .unwrap_or_default();
    let mut notices = Vec::new();
    for tab in &mut app.tabs {
        let Tab::Terminal(session) = tab else {
            continue;
        };
        notices.extend(session.take_notices());
        if let Some(Live::Host(share)) = session.live.as_mut()
            && let Some((epoch, key)) = epochs.get(&share.host.team)
            && *epoch != share.epoch
        {
            share.epoch = *epoch;
            share.host.reannounce(key.clone(), *epoch);
        }
    }
    for notice in notices {
        app.notify(notice);
    }
    if app.live.dev.as_deref() == Some("compartir")
        && let Some(team) = epochs.keys().next().cloned()
        && let Some(tab) = app.tabs.iter().find_map(|t| match t {
            Tab::Terminal(s) if s.is_alive() => Some(s.key),
            _ => None,
        })
    {
        app.live.dev = Some("dar".into());
        start_sharing(app, tab, team);
    }
    dev_control(app);
}

/// `TUNEL_DEV_LIVE`: quien comparte da el control a la primera petición y quien mira
/// escribe en cuanto lo recibe.
fn dev_control(app: &mut TunelApp) {
    match app.live.dev.as_deref() {
        Some("dar") => {
            let request = app.tabs.iter().find_map(|t| match t {
                Tab::Terminal(s) => match &s.live {
                    Some(Live::Host(share)) => share.requests.first().map(|c| (s.key, *c)),
                    _ => None,
                },
                _ => None,
            });
            if let Some((tab, conn)) = request {
                app.live.dev = None;
                grant(app, tab, conn);
            }
        }
        Some("escribir") => {
            let ready = app.tabs.iter().find_map(|t| match t {
                Tab::Terminal(s) => match &s.live {
                    Some(Live::Viewer(w)) if w.control => Some(s.key),
                    _ => None,
                },
                _ => None,
            });
            if let Some(tab) = ready
                && let Some(session) = terminal(app, tab)
            {
                session.send(b"echo hola desde bob\r".to_vec());
                app.live.dev = None;
            }
        }
        _ => {}
    }
}

/// Hay alguna sesión compartida abierta.
pub fn active(app: &TunelApp) -> bool {
    app.tabs
        .iter()
        .any(|t| matches!(t, Tab::Terminal(s) if s.live.is_some()))
}

fn describe(error: &SyncError) -> String {
    match error {
        SyncError::NotFound(_) => {
            "el servidor no la encuentra (puede que haya terminado o que el servidor no admita \
             sesiones compartidas)"
                .into()
        }
        SyncError::StaleKey => {
            "se anunció con otra clave del Team; sincroniza y vuelve a intentarlo".into()
        }
        SyncError::Key(KeyProblem::Changed(email)) => format!(
            "la clave de {email} no es la que conocías; puede que otra persona se haga pasar por ella"
        ),
        other => other.to_string(),
    }
}
