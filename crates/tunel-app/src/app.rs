//! Estado de la aplicación y disposición general de la ventana.

use crate::editor::Editor;
use crate::engine::{AppEvent, Engine};
use crate::lock::LockScreen;
use crate::prompts::Prompts;
use crate::session::{SessionStatus, TerminalSession};
use crate::views;
use crate::views::sftp::SftpTab;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tunel_core::{ForwardId, HostId, UnlockedVault, VaultData};
use tunel_ssh::forward::ActiveForward;
use tunel_term::palette::{self, Theme};

const NOTICE_TTL: Duration = Duration::from_secs(6);
pub const DEFAULT_COLS: u16 = 100;
pub const DEFAULT_ROWS: u16 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Hosts,
    Keychain,
    Forwarding,
    Snippets,
    KnownHosts,
    Settings,
}

impl Section {
    pub const ALL: [Section; 6] = [
        Section::Hosts,
        Section::Keychain,
        Section::Forwarding,
        Section::Snippets,
        Section::KnownHosts,
        Section::Settings,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Section::Hosts => "Hosts",
            Section::Keychain => "Llavero",
            Section::Forwarding => "Túneles",
            Section::Snippets => "Snippets",
            Section::KnownHosts => "Known hosts",
            Section::Settings => "Ajustes",
        }
    }

    pub fn icon(self) -> &'static str {
        use crate::ui::icons;
        match self {
            Section::Hosts => icons::SERVERS,
            Section::Keychain => icons::KEY,
            Section::Forwarding => icons::TUNNEL,
            Section::Snippets => icons::CODE,
            Section::KnownHosts => icons::SHIELD,
            Section::Settings => icons::GEAR,
        }
    }
}

pub enum Tab {
    Terminal(Box<TerminalSession>),
    Sftp(Box<SftpTab>),
}

/// Estado resumido de una pestaña, para su indicador de color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabState {
    Connecting,
    Live,
    Ended,
    Failed,
}

impl Tab {
    pub fn title(&self) -> &str {
        match self {
            Tab::Terminal(t) => &t.title,
            Tab::Sftp(s) => &s.title,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Tab::Terminal(t) if t.live.is_some() => crate::ui::icons::BROADCAST,
            Tab::Terminal(_) => crate::ui::icons::TERMINAL,
            Tab::Sftp(_) => crate::ui::icons::FOLDER_OPEN,
        }
    }

    pub fn state(&self) -> TabState {
        match self {
            Tab::Terminal(t) => match t.status {
                SessionStatus::Connecting => TabState::Connecting,
                SessionStatus::Connected => TabState::Live,
                SessionStatus::Closed(_) => TabState::Ended,
                SessionStatus::Failed(_) => TabState::Failed,
            },
            Tab::Sftp(s) => s.state(),
        }
    }
}

pub struct TunelApp {
    pub engine: Engine,
    pub lock: LockScreen,
    pub vault: Option<UnlockedVault>,
    pub section: Section,
    pub tabs: Vec<Tab>,
    /// `None` muestra la sección del menú lateral en lugar de una pestaña.
    pub active: Option<usize>,
    /// Segunda pestaña mostrada a la derecha (vista dividida).
    pub split: Option<usize>,
    pub search: String,
    /// Grupo abierto en la vista de hosts (`None` = raíz).
    pub host_group: Option<tunel_core::GroupId>,
    pub editor: Option<Editor>,
    pub prompts: Prompts,
    pub forwards: HashMap<ForwardId, ActiveForward>,
    pub forward_errors: HashMap<ForwardId, String>,
    pub password_change: crate::views::settings::PasswordChange,
    pub quick_connect: Option<crate::quick_connect::QuickConnect>,
    pub notices: Vec<(Instant, String)>,
    pub sync: crate::sync::SyncController,
    pub updates: crate::updates::UpdateChecker,
    pub live: crate::live::LiveUi,
}

impl TunelApp {
    pub fn new(cc: &eframe::CreationContext<'_>, vault_path: PathBuf) -> anyhow::Result<Self> {
        #[cfg_attr(not(debug_assertions), allow(unused_mut))]
        let mut app = Self::build(cc, vault_path)?;
        #[cfg(debug_assertions)]
        app.apply_dev_overrides(&cc.egui_ctx);
        Ok(app)
    }

    /// Solo en depuración: `TUNEL_DEV_PASSWORD` desbloquea, `TUNEL_DEV_SECTION` elige la sección
    /// y `TUNEL_DEV_LOCAL=1` abre una terminal local. Sirve para capturas y pruebas manuales.
    #[cfg(debug_assertions)]
    fn apply_dev_overrides(&mut self, ctx: &egui::Context) {
        let Some(password) = std::env::var("TUNEL_DEV_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty())
        else {
            return;
        };
        match UnlockedVault::unlock(self.lock.path().to_path_buf(), &password) {
            Ok(vault) => self.vault = Some(vault),
            Err(e) => return self.notify(format!("TUNEL_DEV_PASSWORD: {e}")),
        }
        crate::sync::on_unlock(self);
        // `TUNEL_DEV_SYNC=crear|servidor|correo|contraseña` (o `entrar|…`) une el equipo
        // a una cuenta al arrancar, para probar la sincronización sin rellenar el formulario.
        if let Ok(spec) = std::env::var("TUNEL_DEV_SYNC")
            && let [how, server, email, password] = spec.splitn(4, '|').collect::<Vec<_>>()[..]
        {
            self.sync.form.server = server.into();
            self.sync.form.email = email.into();
            self.sync.form.password = password.into();
            self.sync.form.confirm = password.into();
            let how = if how == "crear" {
                crate::engine::LinkAccount::Create
            } else {
                crate::engine::LinkAccount::SignIn
            };
            crate::sync::link(self, how);
        }
        self.apply_theme(ctx);
        self.section = match std::env::var("TUNEL_DEV_SECTION").as_deref() {
            Ok("keychain") => Section::Keychain,
            Ok("forwarding") => Section::Forwarding,
            Ok("snippets") => Section::Snippets,
            Ok("known_hosts") => Section::KnownHosts,
            Ok("settings") => Section::Settings,
            _ => Section::Hosts,
        };
        if std::env::var("TUNEL_DEV_LOCAL").as_deref() == Ok("1") {
            self.open_local();
            if let Ok(command) = std::env::var("TUNEL_DEV_RUN") {
                self.send_to_terminals(&format!("{command}\n"), false);
            }
        }
        // `TUNEL_DEV_LIVE=compartir` comparte la primera terminal con el primer Team;
        // `mirar` abre la primera sesión en vivo de otra persona y pide el control.
        self.live.dev = std::env::var("TUNEL_DEV_LIVE").ok();
        // `TUNEL_DEV_TEAM=1` despliega el primer Team en Ajustes con sus miembros.
        if std::env::var("TUNEL_DEV_TEAM").as_deref() == Ok("1")
            && let Some(team) = self
                .sync
                .local()
                .and_then(|l| l.teams.first())
                .map(|t| t.id.clone())
        {
            self.sync.teams.open = Some(team.clone());
            crate::sync::teams::start(self, crate::sync::teams::TeamOp::Members { team });
        }
        if let Ok(name) = std::env::var("TUNEL_DEV_GROUP") {
            self.host_group = self
                .data()
                .and_then(|d| d.groups.iter().find(|g| g.name == name))
                .map(|g| g.id);
        }
        if let Ok(kind) = std::env::var("TUNEL_DEV_PROMPT")
            && kind == "llave"
        {
            self.prompts.push(tunel_ssh::Interaction::TouchSecurityKey {
                host: "bastion.ejemplo.com".into(),
                finished: std::sync::Arc::default(),
            });
        } else if let Ok(kind) = std::env::var("TUNEL_DEV_PROMPT") {
            let (reply, _) = tokio::sync::oneshot::channel();
            let status = if kind == "cambio" {
                tunel_core::HostKeyStatus::Mismatch {
                    expected: "ssh-ed25519 SHA256:Zl7mJ0dQ2b8kq5f3m0YtLq4nX1bJr6vV9cWuA2sEo0k"
                        .into(),
                }
            } else {
                tunel_core::HostKeyStatus::Unknown
            };
            self.prompts.push(tunel_ssh::Interaction::HostKey {
                host: "bastion.ejemplo.com".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM".into(),
                status,
                reply,
            });
        }
        if let Ok(name) = std::env::var("TUNEL_DEV_EDIT") {
            let host = self
                .data()
                .and_then(|d| d.hosts.iter().find(|h| h.label == name))
                .cloned();
            self.editor = host.map(Editor::host);
        }
        if let Ok(query) = std::env::var("TUNEL_DEV_QUICK") {
            self.quick_connect = Some(crate::quick_connect::QuickConnect::with_query(query));
        }
        if let Ok(style) = std::env::var("TUNEL_DEV_CURSOR")
            && let Some(data) = self.data().cloned()
        {
            let cursor_style = match style.as_str() {
                "barra" => tunel_core::theme::CursorStyle::Bar,
                "subrayado" => tunel_core::theme::CursorStyle::Underline,
                _ => tunel_core::theme::CursorStyle::Block,
            };
            self.commit(data.with_settings(tunel_core::Settings {
                cursor_style,
                ..data.settings.clone()
            }));
        }
        if let Ok(theme) = std::env::var("TUNEL_DEV_THEME")
            && let Some(data) = self.data().cloned()
        {
            let settings = tunel_core::Settings {
                theme,
                ..data.settings.clone()
            };
            self.commit(data.with_settings(settings));
            self.apply_theme(ctx);
        }
    }

    fn build(cc: &eframe::CreationContext<'_>, vault_path: PathBuf) -> anyhow::Result<Self> {
        Ok(Self {
            engine: Engine::new(cc.egui_ctx.clone())?,
            lock: LockScreen::new(vault_path),
            vault: None,
            section: Section::Hosts,
            tabs: Vec::new(),
            active: None,
            split: None,
            search: String::new(),
            host_group: None,
            editor: None,
            prompts: Prompts::default(),
            forwards: HashMap::new(),
            forward_errors: HashMap::new(),
            password_change: Default::default(),
            quick_connect: None,
            notices: Vec::new(),
            sync: Default::default(),
            updates: Default::default(),
            live: Default::default(),
        })
    }

    pub fn data(&self) -> Option<&VaultData> {
        self.vault.as_ref().map(|v| &v.data)
    }

    /// Tema de terminal de un host: el suyo, el heredado de su grupo o el general de ajustes.
    pub fn terminal_theme(&self, host: Option<HostId>) -> Theme {
        let Some(data) = self.data() else {
            return palette::default_theme().clone();
        };
        let id = host.map_or(data.settings.theme.as_str(), |h| data.terminal_theme_id(h));
        palette::find(id, &data.settings.custom_themes).clone()
    }

    /// Aplica a la interfaz la paleta del modo elegido (o la que pide el tema de la terminal).
    pub fn apply_theme(&self, ctx: &egui::Context) {
        let mode = self.data().map(|d| d.settings.ui_theme).unwrap_or_default();
        let dark_terminal = self.terminal_theme(None).is_dark();
        crate::ui::theme::apply(ctx, crate::ui::theme::for_mode(mode, dark_terminal));
    }

    /// Guarda una nueva versión de la bóveda, la anota para sincronizarla y avisa si falla.
    pub fn commit(&mut self, data: VaultData) {
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        let old = vault.data.clone();
        match vault.commit(data.clone()) {
            Ok(()) => crate::sync::after_commit(self, &old, &data),
            Err(e) => self.notify(format!("No se pudo guardar la bóveda: {e}")),
        }
    }

    /// Guarda lo que llegó por sincronización, sin volver a anotarlo como cambio local.
    pub fn commit_synced(&mut self, data: VaultData) -> Result<(), tunel_core::StoreError> {
        match self.vault.as_mut() {
            Some(vault) => vault.commit(data),
            None => Ok(()),
        }
    }

    pub fn notify(&mut self, message: impl Into<String>) {
        let message = message.into();
        tracing::info!(%message);
        self.notices.push((Instant::now(), message));
    }

    pub fn lock_vault(&mut self) {
        self.engine.cancel_all();
        self.prompts.clear();
        self.tabs.clear();
        self.active = None;
        self.split = None;
        self.forwards.clear();
        self.editor = None;
        self.sync = Default::default();
        self.live = Default::default();
        self.vault = None;
    }

    pub fn open_host(&mut self, host: HostId) {
        let Some(data) = self.data().cloned() else {
            return;
        };
        self.open_host_in(&data, host);
    }

    /// Abre `host` usando `data`, que puede incluir hosts temporales que no están en la bóveda.
    pub fn open_host_in(&mut self, data: &VaultData, host: HostId) {
        match self
            .engine
            .open_host(data, host, DEFAULT_COLS, DEFAULT_ROWS)
        {
            Ok(session) => self.push_tab(Tab::Terminal(Box::new(session))),
            Err(e) => self.notify(format!("No se pudo abrir la sesión: {e:#}")),
        }
    }

    pub fn open_local(&mut self) {
        let scrollback = self
            .data()
            .map(|d| d.settings.scrollback_lines)
            .unwrap_or(10_000);
        match self
            .engine
            .open_local(DEFAULT_COLS, DEFAULT_ROWS, scrollback)
        {
            Ok(session) => self.push_tab(Tab::Terminal(Box::new(session))),
            Err(e) => self.notify(format!("No se pudo abrir la terminal local: {e:#}")),
        }
    }

    pub fn open_sftp(&mut self, host: HostId) {
        let Some(data) = self.data().cloned() else {
            return;
        };
        let title = data
            .host(host)
            .map(|h| h.display_name().to_string())
            .unwrap_or_default();
        match self.engine.open_sftp(&data, host) {
            Ok(id) => self.push_tab(Tab::Sftp(Box::new(SftpTab::new(id, title)))),
            Err(e) => self.notify(format!("No se pudo abrir SFTP: {e:#}")),
        }
    }

    pub fn open_tab(&mut self, tab: Tab) {
        self.push_tab(tab);
    }

    fn push_tab(&mut self, tab: Tab) {
        self.tabs.push(tab);
        self.active = Some(self.tabs.len() - 1);
    }

    pub fn close_tab(&mut self, index: usize) {
        if index >= self.tabs.len() {
            return;
        }
        self.tabs.remove(index);
        let fix = |slot: Option<usize>| match slot {
            Some(i) if i == index => None,
            Some(i) if i > index => Some(i - 1),
            other => other,
        };
        self.split = fix(self.split);
        self.active = fix(self.active).or_else(|| self.tabs.len().checked_sub(1));
        if self.split == self.active {
            self.split = None;
        }
    }

    /// Envía texto a la terminal activa o a todas.
    pub fn send_to_terminals(&mut self, text: &str, all: bool) {
        let bytes = text.replace('\n', "\r").into_bytes();
        let active = self.active;
        let mut sent = 0;
        for (i, tab) in self.tabs.iter().enumerate() {
            if let Tab::Terminal(t) = tab
                && (all || Some(i) == active)
                && t.is_alive()
            {
                t.send(bytes.clone());
                sent += 1;
            }
        }
        if sent == 0 {
            self.notify("No hay ninguna terminal activa a la que enviar el snippet");
        }
    }

    fn process_background(&mut self) {
        while let Ok(interaction) = self.engine.interactions.try_recv() {
            self.prompts.push(interaction);
        }
        while let Ok(event) = self.engine.events.try_recv() {
            match event {
                // Un túnel que termina de abrirse con la bóveda bloqueada se cierra al soltarlo.
                AppEvent::ForwardStarted { .. } if self.vault.is_none() => {}
                AppEvent::ForwardStarted { id, active } => {
                    self.forward_errors.remove(&id);
                    self.notify(format!("Túnel activo: {}", active.rule.describe()));
                    self.forwards.insert(id, active);
                }
                AppEvent::ForwardFailed { id, error } => {
                    self.notify(format!("El túnel falló: {error}"));
                    self.forward_errors.insert(id, error);
                }
                AppEvent::SyncFinished { round, result } => {
                    crate::sync::on_finished(self, round, result)
                }
                AppEvent::SyncLinked { round, result } => {
                    crate::sync::on_linked(self, round, result)
                }
                AppEvent::TeamDone { round, result } => {
                    crate::sync::teams::on_done(self, round, result)
                }
                AppEvent::Live(event) => crate::live::on_event(self, event),
                sftp_event => views::sftp::apply_event(self, sftp_event),
            }
        }
        crate::sync::tick(self);
        let engine = &self.engine;
        if let Some(update) = self.updates.tick(|| engine.check_updates()) {
            self.notify(format!(
                "Hay una versión nueva de Túnel: {}",
                update.version
            ));
        }
        for tab in &mut self.tabs {
            if let Tab::Terminal(session) = tab {
                session.pump();
            }
        }
        crate::live::tick(self);
        self.notices.retain(|(at, _)| at.elapsed() < NOTICE_TTL);
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let (new_tab, close_tab, palette) = ctx.input_mut(|i| {
            let cmd = egui::Modifiers::COMMAND | egui::Modifiers::SHIFT;
            (
                i.consume_shortcut(&egui::KeyboardShortcut::new(cmd, egui::Key::T)),
                i.consume_shortcut(&egui::KeyboardShortcut::new(cmd, egui::Key::W)),
                i.consume_shortcut(&egui::KeyboardShortcut::new(cmd, egui::Key::K)),
            )
        });
        if new_tab {
            self.open_local();
        }
        if palette {
            self.quick_connect = Some(Default::default());
        }
        if close_tab && let Some(i) = self.active {
            self.close_tab(i);
        }
    }

    fn show_tab(&mut self, ui: &mut egui::Ui, index: usize) {
        let host = match &self.tabs[index] {
            Tab::Terminal(session) => session.host,
            Tab::Sftp(_) => None,
        };
        let theme = self.terminal_theme(host);
        let settings = self.data().map(|d| d.settings.clone()).unwrap_or_default();
        let mut close = false;
        let mut reconnect = None;
        let mut live_action = None;
        let mut tab_key = 0;
        match &mut self.tabs[index] {
            Tab::Terminal(session) => {
                tab_key = session.key;
                if session.live.is_some() {
                    live_action = views::live::bar(ui, session);
                }
                if let Some(message) = status_message(&session.status) {
                    let failed = matches!(session.status, SessionStatus::Failed(_));
                    let action =
                        crate::chrome::session_banner(ui, &message, failed, session.host.is_some());
                    match action {
                        Some(crate::chrome::BannerAction::Reconnect) => {
                            reconnect = session.host;
                            close = true;
                        }
                        Some(crate::chrome::BannerAction::Close) => close = true,
                        None => {}
                    }
                }
                crate::terminal_view::show(ui, session, &theme, &settings);
            }
            Tab::Sftp(_) => views::sftp::show(self, ui, index),
        }
        match live_action {
            Some(views::live::BarAction::Grant(conn)) => crate::live::grant(self, tab_key, conn),
            Some(views::live::BarAction::Confirm) => crate::live::confirm_grant(self, tab_key),
            Some(views::live::BarAction::Stop) => crate::live::stop_sharing(self, tab_key),
            None => {}
        }
        if close {
            self.close_tab(index);
        }
        if let Some(host) = reconnect {
            self.open_host(host);
        }
    }

    fn show_section(&mut self, ui: &mut egui::Ui) {
        match self.section {
            Section::Hosts => views::hosts::show(self, ui),
            Section::Keychain => views::keychain::show(self, ui),
            Section::Forwarding => views::forwards::show(self, ui),
            Section::Snippets => views::snippets::show(self, ui),
            Section::KnownHosts => views::known_hosts::show(self, ui),
            Section::Settings => views::settings::show(self, ui),
        }
    }
}

/// Mensaje para sesiones terminadas o fallidas; `None` mientras siguen activas.
fn status_message(status: &SessionStatus) -> Option<String> {
    match status {
        SessionStatus::Connecting | SessionStatus::Connected => None,
        SessionStatus::Failed(error) => Some(error.clone()),
        SessionStatus::Closed(Some(code)) => Some(format!("Sesión terminada (código {code})")),
        SessionStatus::Closed(None) => Some("Sesión terminada".into()),
    }
}

impl eframe::App for TunelApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.vault.is_none() {
            if let Some(vault) = self.lock.show(ui) {
                self.vault = Some(vault);
                crate::sync::on_unlock(self);
                self.apply_theme(&ctx);
            }
            return;
        }
        self.process_background();
        let wait = self.updates.wait();
        let wait = if crate::live::active(self) {
            wait.min(crate::live::POLL)
        } else {
            wait
        };
        ctx.request_repaint_after(self.sync.wait().map_or(wait, |w| w.min(wait)));
        self.handle_shortcuts(&ctx);

        crate::chrome::sidebar(self, ui);
        crate::chrome::tab_bar(self, ui);
        let in_terminal = self.active.is_some();
        let margin = if in_terminal {
            egui::Margin::ZERO
        } else {
            egui::Margin::symmetric(28, 20)
        };
        let frame = egui::Frame::central_panel(ui.style()).inner_margin(margin);
        egui::CentralPanel::default()
            .frame(frame)
            .show(ui, |ui| match (self.active, self.split) {
                (Some(active), Some(split)) if split < self.tabs.len() => {
                    ui.columns(2, |cols| {
                        self.show_tab(&mut cols[0], active);
                        if split < self.tabs.len() {
                            self.show_tab(&mut cols[1], split);
                        }
                    });
                }
                (Some(active), _) if active < self.tabs.len() => self.show_tab(ui, active),
                _ => self.show_section(ui),
            });

        crate::editor::show(self, &ctx);
        crate::prompts::show(self, &ctx);
        crate::quick_connect::show(self, &ctx);
        crate::chrome::notices(self, &ctx);
    }
}
