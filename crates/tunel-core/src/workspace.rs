//! Pestañas abiertas de este equipo, para volver a ellas al abrir Túnel. No se
//! sincronizan: cada equipo tiene las suyas.

use crate::model::HostId;
use crate::vault::VaultData;
use serde::{Deserialize, Serialize};

/// Pestañas que se guardan como mucho; las demás se descartan.
pub const MAX_SAVED_TABS: usize = 50;

/// Qué abría una pestaña.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SavedTabKind {
    /// Una terminal con un host de la bóveda.
    Host { host: HostId },
    /// La terminal local de este equipo.
    Local,
    /// El explorador SFTP de un host.
    Sftp { host: HostId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedTab {
    #[serde(flatten)]
    pub kind: SavedTabKind,
    /// Nombre de la pestaña, el del host o el que le dio el usuario.
    pub title: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Workspace {
    pub tabs: Vec<SavedTab>,
    /// Pestaña seleccionada; `None` muestra la bóveda.
    pub active: Option<usize>,
}

impl Workspace {
    /// Lo que se puede volver a abrir con `data`: sin las pestañas de hosts que ya no
    /// existen y con la seleccionada ajustada a las que quedan.
    pub fn restorable(&self, data: &VaultData) -> Workspace {
        let exists = |tab: &SavedTab| match &tab.kind {
            SavedTabKind::Host { host } | SavedTabKind::Sftp { host } => data.host(*host).is_some(),
            SavedTabKind::Local => true,
        };
        let mut active = None;
        let mut tabs = Vec::new();
        for (i, tab) in self.tabs.iter().enumerate().take(MAX_SAVED_TABS) {
            if !exists(tab) {
                continue;
            }
            if self.active == Some(i) {
                active = Some(tabs.len());
            }
            tabs.push(tab.clone());
        }
        Workspace { tabs, active }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Host;

    #[test]
    fn tabs_of_deleted_hosts_are_dropped_and_the_selection_follows() {
        let kept = Host::new("web", "10.0.0.1");
        let gone = Host::new("db", "10.0.0.2");
        let data = VaultData::default().with_host(kept.clone());
        let tab = |kind, title: &str| SavedTab {
            kind,
            title: title.into(),
        };
        let saved = Workspace {
            tabs: vec![
                tab(SavedTabKind::Host { host: gone.id }, "db"),
                tab(SavedTabKind::Local, "Local"),
                tab(SavedTabKind::Sftp { host: kept.id }, "web"),
            ],
            active: Some(2),
        };
        let restored = saved.restorable(&data);
        assert_eq!(restored.tabs.len(), 2);
        assert_eq!(restored.tabs[1].title, "web");
        assert_eq!(restored.active, Some(1));

        let selected_gone = Workspace {
            active: Some(0),
            ..saved
        };
        assert_eq!(selected_gone.restorable(&data).active, None);
    }

    #[test]
    fn old_or_partial_files_still_load() {
        let empty: Workspace = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, Workspace::default());
        let local: Workspace =
            serde_json::from_str(r#"{"tabs":[{"kind":"local","title":"Local"}]}"#).unwrap();
        assert_eq!(local.tabs[0].kind, SavedTabKind::Local);
    }
}
