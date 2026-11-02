//! Grabación de sesiones en la interfaz: el aviso en la terminal que se graba, la barra
//! del reproductor y, en la ficha del Team, el interruptor y la lista para los admins.

use crate::app::{Tab, TunelApp};
use crate::playback::{SPEEDS, clock};
use crate::session::TerminalSession;
use crate::sync::teams::{TeamOp, start};
use crate::ui::{self, icons};
use chrono::{Local, TimeZone};
use egui::RichText;
use std::path::PathBuf;
use tunel_core::sync::TeamLocal;
use tunel_core::sync::protocol::RecordingSummary;
use tunel_core::sync::recording::to_asciicast;
use tunel_sync::audit::Trust;
use tunel_sync::recording::{self, Recording};

/// Las grabaciones de un Team tal como llegaron.
pub struct RecordingsView {
    team: String,
    list: Vec<RecordingSummary>,
    loading: bool,
    error: Option<String>,
    /// Grabación cuyo borrado espera confirmación.
    confirm_delete: Option<String>,
}

/// Aviso fijo sobre una terminal que se está grabando.
pub fn banner(ui: &mut egui::Ui, team_name: &str) {
    let p = ui::pal(ui);
    egui::Frame::new()
        .fill(p.danger.gamma_multiply(0.10))
        .inner_margin(egui::Margin::symmetric(14, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::EYE)
                        .font(ui::icon_font(14.0))
                        .color(p.danger),
                );
                ui.label(
                    RichText::new(format!(
                        "Esta sesión se graba para el Team «{team_name}»: sus admins podrán verla"
                    ))
                    .size(12.0),
                );
            });
        });
}

fn trust_warning(trust: Trust) -> Option<&'static str> {
    match trust {
        Trust::Verified | Trust::Unreadable => None,
        Trust::Unknown => Some("no se conoce la clave de quien la grabó para comprobarla"),
        Trust::Forged | Trust::NotAdmin => Some("la firma no es de quien dice haberla grabado"),
    }
}

/// Barra de la pestaña que reproduce una grabación.
pub fn player_bar(ui: &mut egui::Ui, session: &mut TerminalSession) {
    let p = ui::pal(ui);
    let mut skip = false;
    let Some(playback) = session.playback.as_mut() else {
        return;
    };
    egui::Frame::new()
        .fill(p.accent.gamma_multiply(0.10))
        .inner_margin(egui::Margin::symmetric(14, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let label = if playback.finished() {
                    "Terminada"
                } else if playback.paused {
                    "Seguir"
                } else {
                    "Pausa"
                };
                if ui
                    .add_enabled(!playback.finished(), egui::Button::new(label))
                    .clicked()
                {
                    playback.toggle_pause();
                }
                for speed in SPEEDS {
                    if ui
                        .selectable_label(playback.speed == speed, format!("×{speed}"))
                        .clicked()
                    {
                        playback.speed = speed;
                    }
                }
                ui.label(
                    RichText::new(format!(
                        "{} / {}",
                        clock(playback.position_ms().min(playback.duration_ms)),
                        clock(playback.duration_ms)
                    ))
                    .monospace(),
                );
                if !playback.finished() && ui.button("Ir al final").clicked() {
                    skip = true;
                }
            });
            let info = &playback.info;
            let mut warnings: Vec<String> = Vec::new();
            if let Some(problem) = &info.problem {
                warnings.push(format!("Se reproduce hasta donde se pudo: {problem}"));
            } else if !info.complete {
                warnings.push("La grabación no llegó entera o la sesión sigue abierta".into());
            }
            warnings.extend(trust_warning(info.trust).map(str::to_string));
            for warning in warnings {
                ui.label(
                    RichText::new(format!("{} {warning}", icons::WARNING))
                        .size(12.0)
                        .color(p.warning),
                );
            }
        });
    if skip {
        session.skip_to_end();
    }
}

fn when(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|s| Local.timestamp_opt(s, 0).single())
        .map_or_else(|| "—".into(), |t| t.format("%d/%m/%Y %H:%M").to_string())
}

fn size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{} KiB", bytes / 1024),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

fn load(app: &mut TunelApp, team: &str) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    match app.sync.teams.recordings.as_mut() {
        Some(view) if view.team == team => view.loading = true,
        _ => {
            app.sync.teams.recordings = Some(RecordingsView {
                team: team.to_string(),
                list: Vec::new(),
                loading: true,
                error: None,
                confirm_delete: None,
            })
        }
    }
    let team = team.to_string();
    app.engine.recordings_task(async move {
        let result = recording::list(&local, &team)
            .await
            .map_err(|e| e.to_string());
        crate::engine::AppEvent::RecordingsLoaded { team, result }
    });
}

pub fn on_loaded(app: &mut TunelApp, team: String, result: Result<Vec<RecordingSummary>, String>) {
    if let Some(view) = app.sync.teams.recordings.as_mut()
        && view.team == team
    {
        view.loading = false;
        match result {
            Ok(list) => {
                view.list = list;
                view.error = None;
            }
            Err(e) => view.error = Some(e),
        }
    }
}

/// Descarga y abre una grabación, para reproducirla o, con `export`, guardarla.
fn open(app: &mut TunelApp, team: &str, summary: &RecordingSummary, export: Option<PathBuf>) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    let (team, id, author) = (team.to_string(), summary.id.clone(), summary.author.clone());
    app.notify("Descargando la grabación…");
    app.engine.recordings_task(async move {
        let result = recording::open(&local, &team, &id, &author)
            .await
            .map(Box::new)
            .map_err(|e| e.to_string());
        let title = result
            .as_ref()
            .ok()
            .and_then(|r| r.header.as_ref())
            .map_or_else(|| "Grabación".to_string(), |h| format!("▶ {}", h.host));
        crate::engine::AppEvent::RecordingOpened {
            title,
            export,
            result,
        }
    });
}

pub fn on_opened(
    app: &mut TunelApp,
    title: String,
    export: Option<PathBuf>,
    result: Result<Box<Recording>, String>,
) {
    let recording = match result {
        Ok(recording) => recording,
        Err(e) => return app.notify(format!("No se pudo abrir la grabación: {e}")),
    };
    let Some(path) = export else {
        let session = TerminalSession::replay(title, &recording);
        return app.push_tab(Tab::Terminal(Box::new(session)));
    };
    let Some(header) = recording.header.as_ref() else {
        return app.notify("La grabación está vacía o no se pudo leer");
    };
    match std::fs::write(&path, to_asciicast(header, &recording.events)) {
        Ok(()) => app.notify(format!("Grabación guardada en {}", path.display())),
        Err(e) => app.notify(format!("No se pudo guardar la grabación: {e}")),
    }
}

fn delete(app: &mut TunelApp, team: &str, id: &str) {
    let Some(local) = app.sync.local().cloned() else {
        return;
    };
    let (team, id) = (team.to_string(), id.to_string());
    app.engine.recordings_task(async move {
        let result = match recording::delete(&local, &team, &id).await {
            Ok(()) => recording::list(&local, &team).await,
            Err(e) => Err(e),
        }
        .map_err(|e| e.to_string());
        crate::engine::AppEvent::RecordingsLoaded { team, result }
    });
}

/// Interruptor y lista de grabaciones en la ficha de un Team; solo para admins.
pub fn section(app: &mut TunelApp, ui: &mut egui::Ui, team: &TeamLocal, busy: bool) {
    let p = ui::pal(ui);
    let on = team.roster.as_ref().is_some_and(|r| r.record_sessions);
    ui.horizontal(|ui| {
        ui::section_label(ui, "Grabación de sesiones");
        let mut wanted = on;
        let toggle = ui
            .add_enabled(!busy, egui::Checkbox::new(&mut wanted, "Grabar"))
            .on_hover_text(
                "Graba lo que muestran las terminales con los hosts del Team, no lo que se \
                 teclea. Quien se conecta lo ve avisado en su terminal.",
            );
        if toggle.changed() {
            let id = team.id.clone();
            start(
                app,
                TeamOp::SetRecording {
                    team: id,
                    on: wanted,
                },
            );
        }
        if ui::secondary_button(ui, &ui::with_icon(icons::REFRESH, "Ver grabaciones")).clicked() {
            load(app, &team.id);
        }
    });
    let Some(view) = app
        .sync
        .teams
        .recordings
        .as_ref()
        .filter(|v| v.team == team.id)
    else {
        return;
    };
    if let Some(error) = &view.error {
        ui.colored_label(p.danger, format!("No se pudieron cargar: {error}"));
    }
    if view.loading {
        ui.add(egui::Spinner::new().size(12.0));
    } else if view.list.is_empty() && view.error.is_none() {
        ui.label(RichText::new("No hay grabaciones.").color(p.muted));
    }
    let confirm = view.confirm_delete.clone();
    let list = view.list.clone();
    let mut action: Option<(&'static str, RecordingSummary)> = None;
    egui::ScrollArea::vertical()
        .id_salt(("grabaciones", &team.id))
        .max_height(220.0)
        .show(ui, |ui| {
            for item in &list {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(when(item.started_at))
                            .monospace()
                            .size(12.0)
                            .color(p.muted),
                    );
                    ui.label(&item.author);
                    let state = if item.finished {
                        ""
                    } else {
                        " · sin terminar"
                    };
                    ui.label(
                        RichText::new(format!(
                            "{} · {}{state}",
                            clock(item.updated_at.saturating_sub(item.started_at) * 1000),
                            size(item.bytes)
                        ))
                        .size(12.0)
                        .color(p.muted),
                    );
                    if confirm.as_deref() == Some(item.id.as_str()) {
                        if ui::danger_button(ui, "Sí, borrar").clicked() {
                            action = Some(("borrar", item.clone()));
                        }
                        if ui::secondary_button(ui, "Cancelar").clicked() {
                            action = Some(("cancelar", item.clone()));
                        }
                        return;
                    }
                    if ui::secondary_button(ui, &ui::with_icon(icons::PLAY, "Ver")).clicked() {
                        action = Some(("ver", item.clone()));
                    }
                    if ui::icon_button(ui, icons::DOWNLOAD, "Guardar como .cast (asciinema)")
                        .clicked()
                    {
                        action = Some(("exportar", item.clone()));
                    }
                    if ui::icon_button(ui, icons::TRASH, "Borrar").clicked() {
                        action = Some(("confirmar", item.clone()));
                    }
                });
            }
        });
    let Some((what, item)) = action else {
        return;
    };
    let set_confirm = |app: &mut TunelApp, id: Option<String>| {
        if let Some(view) = app.sync.teams.recordings.as_mut() {
            view.confirm_delete = id;
        }
    };
    match what {
        "ver" => open(app, &team.id, &item, None),
        "exportar" => {
            let file = rfd::FileDialog::new()
                .set_file_name(format!("grabacion-{}.cast", &item.id[..8]))
                .add_filter("asciinema", &["cast"])
                .save_file();
            if let Some(path) = file {
                open(app, &team.id, &item, Some(path));
            }
        }
        "confirmar" => set_confirm(app, Some(item.id.clone())),
        "cancelar" => set_confirm(app, None),
        "borrar" => {
            set_confirm(app, None);
            delete(app, &team.id, &item.id);
        }
        _ => {}
    }
}
