//! Registro de auditoría de un Team, en su ficha de Ajustes → Teams. Solo lo ven los admins.

use crate::app::TunelApp;
use crate::ui::{self, icons};
use chrono::{Local, TimeZone};
use egui::RichText;
use tunel_core::sync::TeamLocal;
use tunel_sync::audit::{AuditEntry, AuditLog, Trust};

/// El registro de un Team tal como se ha ido cargando.
pub struct AuditView {
    team: String,
    entries: Vec<AuditEntry>,
    more: bool,
    loading: bool,
    error: Option<String>,
}

impl AuditView {
    fn loading(team: &str) -> Self {
        Self {
            team: team.to_string(),
            entries: Vec::new(),
            more: false,
            loading: true,
            error: None,
        }
    }

    /// Añade una página: la primera sustituye lo que hubiera, las siguientes van detrás.
    fn absorb(&mut self, more: bool, result: Result<AuditLog, String>) {
        self.loading = false;
        match result {
            Ok(log) => {
                if !more {
                    self.entries.clear();
                }
                let known: Vec<u64> = self.entries.iter().map(|e| e.id).collect();
                self.entries
                    .extend(log.entries.into_iter().filter(|e| !known.contains(&e.id)));
                self.more = log.more;
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}

fn load(app: &mut TunelApp, team: &str, before: Option<u64>) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    match app.sync.teams.audit.as_mut() {
        Some(view) if view.team == team => view.loading = true,
        _ => app.sync.teams.audit = Some(AuditView::loading(team)),
    }
    app.engine.load_audit(local, team.to_string(), before);
}

pub fn on_loaded(app: &mut TunelApp, team: String, more: bool, result: Result<AuditLog, String>) {
    if let Some(view) = app.sync.teams.audit.as_mut()
        && view.team == team
    {
        view.absorb(more, result);
    }
}

/// Fecha y hora locales de `millis`.
fn when(millis: u64) -> String {
    i64::try_from(millis)
        .ok()
        .and_then(|m| Local.timestamp_millis_opt(m).single())
        .map_or_else(|| "—".into(), |t| t.format("%d/%m/%Y %H:%M").to_string())
}

/// Lo que se muestra de una entrada y si hay que avisar de algo.
fn describe(entry: &AuditEntry) -> (String, Option<&'static str>) {
    let action = entry.action.as_ref().map_or_else(
        || "(cifrada con una clave que este equipo no tiene)".into(),
        |a| a.describe(),
    );
    let warning = match entry.trust {
        Trust::Verified | Trust::Unreadable => None,
        Trust::Unknown => Some("sin comprobar: no se conoce la clave de esa cuenta"),
        Trust::Forged => Some("firma no válida: puede ser falsa"),
    };
    (format!("{} {action}", entry.actor), warning)
}

pub fn section(app: &mut TunelApp, ui: &mut egui::Ui, team: &TeamLocal) {
    let p = ui::pal(ui);
    let open = app
        .sync
        .teams
        .audit
        .as_ref()
        .is_some_and(|v| v.team == team.id);
    ui.horizontal(|ui| {
        ui::section_label(ui, "Registro de actividad");
        let label = if open { "Actualizar" } else { "Ver registro" };
        if ui::secondary_button(ui, &ui::with_icon(icons::REFRESH, label))
            .on_hover_text("Quién se conectó, vio contraseñas o entró y salió del Team")
            .clicked()
        {
            load(app, &team.id, None);
        }
    });
    let Some(view) = app.sync.teams.audit.as_ref().filter(|v| v.team == team.id) else {
        return;
    };
    if let Some(error) = &view.error {
        ui.colored_label(p.danger, format!("No se pudo cargar el registro: {error}"));
    }
    if view.entries.is_empty() && !view.loading && view.error.is_none() {
        ui.label(RichText::new("Todavía no hay actividad registrada.").color(p.muted));
    }
    let mut load_more = None;
    egui::ScrollArea::vertical()
        .id_salt(("registro", &team.id))
        .max_height(260.0)
        .show(ui, |ui| {
            for entry in &view.entries {
                let (text, warning) = describe(entry);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(when(entry.at))
                            .monospace()
                            .size(12.0)
                            .color(p.muted),
                    );
                    ui.label(text);
                    if let Some(warning) = warning {
                        ui.label(
                            RichText::new(format!("{} {warning}", icons::WARNING))
                                .size(12.0)
                                .color(p.warning),
                        );
                    }
                });
            }
            if view.more && !view.loading && ui.link("Cargar más").clicked() {
                load_more = view.entries.last().map(|e| e.id);
            }
        });
    if view.loading {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new().size(12.0));
            ui.label(RichText::new("Cargando…").size(12.0).color(p.muted));
        });
    }
    if let Some(before) = load_more {
        load(app, &team.id, Some(before));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::sync::audit::AuditAction;

    fn entry(id: u64, trust: Trust) -> AuditEntry {
        AuditEntry {
            id,
            at: 0,
            actor: "ana@ejemplo.com".into(),
            action: Some(AuditAction::Connected { host: "web".into() }),
            trust,
        }
    }

    fn page(ids: &[u64], more: bool) -> Result<AuditLog, String> {
        Ok(AuditLog {
            entries: ids.iter().map(|id| entry(*id, Trust::Verified)).collect(),
            more,
        })
    }

    #[test]
    fn pages_are_appended_and_a_refresh_starts_over() {
        let mut view = AuditView::loading("t");
        view.absorb(false, page(&[9, 8], true));
        view.absorb(true, page(&[8, 7], false));
        let ids: Vec<u64> = view.entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, [9, 8, 7]);
        assert!(!view.more);
        view.absorb(false, page(&[10], false));
        assert_eq!(view.entries.len(), 1);
        view.absorb(true, Err("sin red".into()));
        assert_eq!(view.error.as_deref(), Some("sin red"));
        assert_eq!(view.entries.len(), 1, "un fallo no borra lo cargado");
    }

    #[test]
    fn doubtful_entries_carry_a_warning() {
        let (text, warning) = describe(&entry(1, Trust::Verified));
        assert_eq!(text, "ana@ejemplo.com se conectó a «web»");
        assert_eq!(warning, None);
        assert!(describe(&entry(1, Trust::Forged)).1.is_some());
        assert!(describe(&entry(1, Trust::Unknown)).1.is_some());
        let unreadable = AuditEntry {
            action: None,
            ..entry(1, Trust::Unreadable)
        };
        assert!(
            describe(&unreadable)
                .0
                .contains("clave que este equipo no tiene")
        );
    }
}
