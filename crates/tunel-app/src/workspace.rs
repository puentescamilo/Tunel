//! Volver a las pestañas de la última vez. Se guardan cifradas junto a la bóveda cada vez
//! que cambian, y al desbloquear vuelven en espera: cada una se conecta cuando se
//! selecciona, no todas a la vez.

use crate::app::{DEFAULT_COLS, DEFAULT_ROWS, Tab, TunelApp};
use crate::views::sftp::SftpTab;
use tunel_core::workspace::{MAX_SAVED_TABS, SavedTab, SavedTabKind, Workspace};

/// Lo que habría que guardar ahora: las pestañas que se pueden volver a abrir. Las
/// sesiones que se miran de otra persona no.
pub fn current(app: &TunelApp) -> Workspace {
    let mut active = None;
    let mut tabs = Vec::new();
    for (i, tab) in app.tabs.iter().enumerate() {
        let Some(saved) = tab.saved() else {
            continue;
        };
        if tabs.len() == MAX_SAVED_TABS {
            break;
        }
        if app.active == Some(i) {
            active = Some(tabs.len());
        }
        tabs.push(saved);
    }
    Workspace { tabs, active }
}

fn enabled(app: &TunelApp) -> bool {
    app.data().is_some_and(|d| d.settings.restore_tabs)
}

/// Al desbloquear: vuelven las pestañas guardadas, en espera, y se conecta la que estaba
/// seleccionada.
pub fn restore(app: &mut TunelApp) {
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    if !enabled(app) {
        let _ = vault.delete_workspace();
        app.saved_workspace = None;
        return;
    }
    let saved = match vault.load_workspace() {
        Ok(saved) => saved.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, "no se pudieron leer las pestañas guardadas");
            Workspace::default()
        }
    };
    let Some(data) = app.data() else {
        return;
    };
    let restored = saved.restorable(data);
    app.tabs = restored
        .tabs
        .iter()
        .cloned()
        .map(|t| Tab::Pending(Box::new(t)))
        .collect();
    app.active = restored.active;
    app.layout = None;
    app.detached.clear();
    app.saved_workspace = Some(restored);
}

/// En cada fotograma: conecta las pestañas en espera que están a la vista y guarda las
/// pestañas si cambiaron.
pub fn tick(app: &mut TunelApp) {
    let tabs = app.tabs.len();
    for index in app.visible_tabs() {
        if matches!(app.tabs.get(index), Some(Tab::Pending(_))) {
            connect(app, index);
        }
        // Si falló y se cerró, los demás índices ya no valen hasta el próximo fotograma.
        if app.tabs.len() != tabs {
            break;
        }
    }
    save_if_changed(app);
}

fn save_if_changed(app: &mut TunelApp) {
    if !enabled(app) {
        if app.saved_workspace.take().is_some()
            && let Some(vault) = app.vault.as_ref()
        {
            let _ = vault.delete_workspace();
        }
        return;
    }
    let now = current(app);
    if app.saved_workspace.as_ref() == Some(&now) {
        return;
    }
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    match vault.save_workspace(&now) {
        Ok(()) => app.saved_workspace = Some(now),
        Err(e) => {
            // Se recuerda igualmente para no reintentar en cada fotograma.
            tracing::warn!(error = %e, "no se pudieron guardar las pestañas");
            app.saved_workspace = Some(now);
        }
    }
}

/// Conecta la pestaña en espera `index` en su sitio, con su nombre.
fn connect(app: &mut TunelApp, index: usize) {
    let Some(Tab::Pending(saved)) = app.tabs.get(index) else {
        return;
    };
    let saved: SavedTab = (**saved).clone();
    match open(app, &saved.kind) {
        Ok(mut tab) => {
            tab.set_title(saved.title);
            app.tabs[index] = tab;
        }
        Err(e) => {
            app.notify(format!(
                "No se pudo volver a abrir «{}»: {e:#}",
                saved.title
            ));
            app.close_tab(index);
        }
    }
}

fn open(app: &mut TunelApp, kind: &SavedTabKind) -> anyhow::Result<Tab> {
    let data = app
        .data()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("la bóveda está bloqueada"))?;
    Ok(match kind {
        SavedTabKind::Host { host } => {
            Tab::Terminal(Box::new(app.host_session(&data, *host, None)?))
        }
        SavedTabKind::Local => Tab::Terminal(Box::new(app.engine.open_local(
            DEFAULT_COLS,
            DEFAULT_ROWS,
            data.settings.scrollback_lines,
        )?)),
        SavedTabKind::Sftp { host } => {
            let id = app.engine.open_sftp(&data, *host)?;
            Tab::Sftp(Box::new(SftpTab::new(id, *host, String::new())))
        }
    })
}
