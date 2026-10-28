//! Pestaña SFTP de doble panel: archivos locales a la izquierda y remotos a la derecha.

use crate::app::{Tab, TunelApp};
use crate::engine::AppEvent;
use crate::ui::{self, icons};
use egui::{Align2, CornerRadius, FontId, Rect, RichText, Sense, Vec2};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tunel_ssh::SshConnection;
use tunel_ssh::sftp::{RemoteEntry, SftpClient, join_remote, local_target};

pub struct SftpTab {
    pub id: u64,
    pub title: String,
    connection: Option<Arc<SshConnection>>,
    client: Option<Arc<SftpClient>>,
    remote_path: String,
    remote_entries: Vec<RemoteEntry>,
    local_path: PathBuf,
    status: String,
    error: Option<String>,
    new_folder: String,
    rename: Option<(String, String)>,
}

impl SftpTab {
    pub fn new(id: u64, title: String) -> Self {
        let local_path = directories::BaseDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            id,
            title,
            connection: None,
            client: None,
            remote_path: String::new(),
            remote_entries: Vec::new(),
            local_path,
            status: "Conectando…".into(),
            error: None,
            new_folder: String::new(),
            rename: None,
        }
    }
}

impl SftpTab {
    pub fn state(&self) -> crate::app::TabState {
        use crate::app::TabState;
        match (&self.client, &self.error) {
            (None, Some(_)) => TabState::Failed,
            (None, None) => TabState::Connecting,
            (Some(_), _) => TabState::Live,
        }
    }
}

impl Drop for SftpTab {
    fn drop(&mut self) {
        self.client = None;
        self.connection = None;
    }
}

fn tab_mut(app: &mut TunelApp, id: u64) -> Option<&mut SftpTab> {
    app.tabs.iter_mut().find_map(|t| match t {
        Tab::Sftp(s) if s.id == id => Some(s.as_mut()),
        _ => None,
    })
}

pub fn apply_event(app: &mut TunelApp, event: AppEvent) {
    match event {
        AppEvent::SftpReady {
            tab,
            connection,
            client,
            home,
        } => {
            if let Some(t) = tab_mut(app, tab) {
                t.connection = Some(connection);
                t.client = Some(client.clone());
                t.status = "Conectado".into();
                app.engine.sftp_list(tab, client, home);
            }
        }
        AppEvent::SftpListing { tab, path, entries } => {
            if let Some(t) = tab_mut(app, tab) {
                t.remote_path = path;
                t.remote_entries = entries;
                t.error = None;
            }
        }
        AppEvent::SftpProgress { tab, label, bytes } => {
            if let Some(t) = tab_mut(app, tab) {
                t.status = format!("{label}: {}", human_size(bytes));
            }
        }
        AppEvent::SftpDone { tab, message } => {
            if let Some(t) = tab_mut(app, tab) {
                t.status = message;
            }
        }
        AppEvent::SftpFailed { tab, error } => {
            if let Some(t) = tab_mut(app, tab) {
                t.status = "Error".into();
                t.error = Some(error);
            }
        }
        _ => {}
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

struct LocalEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

fn read_local(dir: &Path) -> Vec<LocalEntry> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries: Vec<LocalEntry> = read
        .filter_map(Result::ok)
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            Some(LocalEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: meta.len(),
            })
        })
        .filter(|e| !e.name.starts_with('.'))
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    entries
}

enum Op {
    RemoteOpen(String),
    Refresh,
    Download(RemoteEntry),
    Upload(PathBuf),
    Delete(RemoteEntry),
    Mkdir(String),
    Rename(String, String),
}

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui, index: usize) {
    let Some(Tab::Sftp(tab)) = app.tabs.get_mut(index) else {
        return;
    };
    let p = ui::pal(ui);
    let mut ops = Vec::new();
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::FOLDER_OPEN)
                        .font(ui::icon_font(18.0))
                        .color(p.accent),
                );
                ui.label(RichText::new(&tab.title).size(16.0).strong());
                ui.label(RichText::new(&tab.status).color(p.muted));
            });
            if let Some(error) = &tab.error {
                ui.label(RichText::new(format!("{}  {error}", icons::WARNING)).color(p.danger));
            }
            ui.add_space(8.0);
            ui.columns(2, |cols| {
                local_pane(&mut cols[0], tab, &mut ops);
                remote_pane(&mut cols[1], tab, &mut ops);
            });
        });
    let (id, path) = (tab.id, tab.remote_path.clone());
    let Some(client) = tab.client.clone() else {
        return;
    };
    for op in ops {
        run_op(app, id, client.clone(), &path, op);
    }
}

const ROW_HEIGHT: f32 = 30.0;

/// Fila de archivo: icono, nombre, tamaño y una acción visible al pasar el ratón.
/// Devuelve (respuesta de la fila, clic en la acción).
fn file_row(
    ui: &mut egui::Ui,
    icon: &str,
    name: &str,
    size: Option<u64>,
    action: Option<(&str, &str)>,
) -> (egui::Response, bool) {
    let p = ui::pal(ui);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_HEIGHT), Sense::click());
    let hovered = response.hovered() || response.context_menu_opened();
    if hovered {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(6), p.surface_hover);
    }
    let color = if icon == icons::FOLDER {
        p.accent
    } else {
        p.muted
    };
    ui.painter().text(
        rect.left_center() + Vec2::new(10.0, 0.0),
        Align2::LEFT_CENTER,
        icon,
        ui::icon_font(16.0),
        color,
    );
    ui.painter().text(
        rect.left_center() + Vec2::new(34.0, 0.0),
        Align2::LEFT_CENTER,
        name,
        FontId::proportional(13.5),
        p.text,
    );
    let mut right = rect.right() - 10.0;
    let mut clicked = false;
    if let (true, Some((action_icon, tooltip))) = (hovered, action) {
        let button = Rect::from_center_size(
            egui::pos2(rect.right() - 18.0, rect.center().y),
            Vec2::splat(24.0),
        );
        let r = ui.interact(button, response.id.with("accion"), Sense::click());
        ui.painter().rect_filled(
            button,
            CornerRadius::same(5),
            if r.hovered() { p.accent } else { p.accent_soft },
        );
        let fg = if r.hovered() { p.accent_text } else { p.accent };
        ui.painter().text(
            button.center(),
            Align2::CENTER_CENTER,
            action_icon,
            ui::icon_font(13.0),
            fg,
        );
        clicked = r.on_hover_text(tooltip).clicked();
        right = button.left() - 8.0;
    }
    if let Some(size) = size {
        ui.painter().text(
            egui::pos2(right, rect.center().y),
            Align2::RIGHT_CENTER,
            human_size(size),
            FontId::proportional(12.0),
            p.muted,
        );
    }
    (response, clicked)
}

/// Marco de un panel con barra de herramientas y lista desplazable.
fn pane(
    ui: &mut egui::Ui,
    title: &str,
    path: &str,
    toolbar: impl FnOnce(&mut egui::Ui),
    list: impl FnOnce(&mut egui::Ui),
) {
    let p = ui::pal(ui);
    ui::card_frame(ui, false)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_min_height(ui.available_height());
            ui.horizontal(|ui| {
                ui.label(RichText::new(title).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), toolbar);
            });
            ui.label(RichText::new(path).monospace().size(12.0).color(p.muted));
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt(title)
                .auto_shrink([false, false])
                .show(ui, list);
        });
}

fn local_pane(ui: &mut egui::Ui, tab: &mut SftpTab, ops: &mut Vec<Op>) {
    let path = tab.local_path.display().to_string();
    let mut go_up = false;
    let mut open = None;
    pane(
        ui,
        "Este equipo",
        &path,
        |ui| go_up = ui::icon_button(ui, icons::ARROW_UP, "Carpeta superior").clicked(),
        |ui| {
            for entry in read_local(&tab.local_path) {
                let icon = if entry.is_dir {
                    icons::FOLDER
                } else {
                    icons::FILE
                };
                let size = (!entry.is_dir).then_some(entry.size);
                let action =
                    (!entry.is_dir).then_some((icons::UPLOAD, "Subir a la carpeta del servidor"));
                let (row, upload) = file_row(ui, icon, &entry.name, size, action);
                if upload {
                    ops.push(Op::Upload(tab.local_path.join(&entry.name)));
                }
                if row.double_clicked() && entry.is_dir {
                    open = Some(entry.name.clone());
                }
            }
        },
    );
    if go_up && let Some(parent) = tab.local_path.parent() {
        tab.local_path = parent.to_path_buf();
    }
    if let Some(name) = open {
        tab.local_path = tab.local_path.join(name);
    }
}

fn remote_pane(ui: &mut egui::Ui, tab: &mut SftpTab, ops: &mut Vec<Op>) {
    let path = tab.remote_path.clone();
    let new_folder = &mut tab.new_folder;
    let rename = &mut tab.rename;
    let entries = &tab.remote_entries;
    let mut toolbar_ops = Vec::new();
    pane(
        ui,
        "Servidor",
        &path,
        |ui| {
            if ui::icon_button(ui, icons::REFRESH, "Actualizar").clicked() {
                toolbar_ops.push(Op::Refresh);
            }
            if ui::icon_button(ui, icons::ARROW_UP, "Carpeta superior").clicked() {
                toolbar_ops.push(Op::RemoteOpen(join_remote(&path, "..")));
            }
            let create = ui::icon_button(ui, icons::PLUS, "Crear carpeta").clicked();
            let field = ui.add(
                egui::TextEdit::singleline(new_folder)
                    .hint_text("Nueva carpeta")
                    .desired_width(120.0),
            );
            let submitted = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (create || submitted) && !new_folder.trim().is_empty() {
                toolbar_ops.push(Op::Mkdir(join_remote(&path, new_folder.trim())));
                new_folder.clear();
            }
        },
        |ui| {
            if let Some((from, to)) = rename.as_mut() {
                let mut done = None;
                ui.horizontal(|ui| {
                    ui.label("Renombrar a");
                    let field = ui.text_edit_singleline(to);
                    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui::primary_button(ui, "Aplicar").clicked() || enter {
                        done = Some(Some((from.clone(), to.clone())));
                    }
                    if ui::icon_button(ui, icons::CLOSE, "Cancelar").clicked() {
                        done = Some(None);
                    }
                });
                if let Some(result) = done {
                    if let Some((from, to)) = result {
                        ops.push(Op::Rename(
                            join_remote(&path, &from),
                            join_remote(&path, &to),
                        ));
                    }
                    *rename = None;
                }
            }
            if entries.is_empty() {
                ui::empty_state(
                    ui,
                    icons::FOLDER_OPEN,
                    "Carpeta vacía",
                    "Sube archivos desde el panel de la izquierda.",
                );
            }
            for entry in entries {
                let icon = if entry.is_dir {
                    icons::FOLDER
                } else if entry.is_symlink {
                    icons::LINK
                } else {
                    icons::FILE
                };
                let size = (!entry.is_dir).then_some(entry.size);
                let action =
                    (!entry.is_dir).then_some((icons::DOWNLOAD, "Descargar a la carpeta local"));
                let (row, download) = file_row(ui, icon, &entry.name, size, action);
                if download {
                    ops.push(Op::Download(entry.clone()));
                }
                if row.double_clicked() && entry.is_dir {
                    ops.push(Op::RemoteOpen(join_remote(&path, &entry.name)));
                }
                row.context_menu(|ui| {
                    if !entry.is_dir
                        && ui
                            .button(ui::with_icon(icons::DOWNLOAD, "Descargar"))
                            .clicked()
                    {
                        ops.push(Op::Download(entry.clone()));
                        ui.close();
                    }
                    if ui
                        .button(ui::with_icon(icons::PENCIL, "Renombrar"))
                        .clicked()
                    {
                        *rename = Some((entry.name.clone(), entry.name.clone()));
                        ui.close();
                    }
                    if ui.button(ui::with_icon(icons::TRASH, "Eliminar")).clicked() {
                        ops.push(Op::Delete(entry.clone()));
                        ui.close();
                    }
                });
            }
        },
    );
    ops.extend(toolbar_ops);
}

fn run_op(app: &mut TunelApp, id: u64, client: Arc<SftpClient>, path: &str, op: Op) {
    let local_dir = tab_mut(app, id)
        .map(|t| t.local_path.clone())
        .unwrap_or_default();
    let engine = &app.engine;
    let refresh = path.to_string();
    match op {
        Op::RemoteOpen(target) => engine.sftp_list(id, client, target),
        Op::Refresh => engine.sftp_list(id, client, refresh),
        Op::Mkdir(target) => engine.sftp_run(
            id,
            client,
            refresh,
            "Crear carpeta".into(),
            move |c, _| async move { c.mkdir(&target).await },
        ),
        Op::Rename(from, to) => engine.sftp_run(
            id,
            client,
            refresh,
            "Renombrar".into(),
            move |c, _| async move { c.rename(&from, &to).await },
        ),
        Op::Delete(entry) => {
            let target = join_remote(path, &entry.name);
            engine.sftp_run(
                id,
                client,
                refresh,
                format!("Eliminar {}", entry.name),
                move |c, _| async move { c.remove(&target, entry.is_dir).await },
            );
        }
        Op::Download(entry) => {
            let remote = join_remote(path, &entry.name);
            let target = local_target(&local_dir, &entry.name);
            let label = format!("Descargar {}", entry.name);
            let progress_label = label.clone();
            engine.sftp_run(id, client, refresh, label, move |c, events| async move {
                c.download(&remote, &target?, |bytes| {
                    let _ = events.send(AppEvent::SftpProgress {
                        tab: id,
                        label: progress_label.clone(),
                        bytes,
                    });
                })
                .await
                .map(|_| ())
            });
        }
        Op::Upload(local) => {
            let name = local
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let remote = join_remote(path, &name);
            let label = format!("Subir {name}");
            let progress_label = label.clone();
            engine.sftp_run(id, client, refresh, label, move |c, events| async move {
                c.upload(&local, &remote, |bytes| {
                    let _ = events.send(AppEvent::SftpProgress {
                        tab: id,
                        label: progress_label.clone(),
                        bytes,
                    });
                })
                .await
                .map(|_| ())
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_uses_binary_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }
}
