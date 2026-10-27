//! Hosts: grupos como carpetas y hosts como tarjetas en cuadrícula.

use crate::app::TunelApp;
use crate::editor::Editor;
use crate::ui::{self, icons};
use egui::{Align2, CornerRadius, FontId, Rect, RichText, Sense, Stroke, Vec2};
use std::sync::Arc;
use tunel_core::{Group, GroupId, Host, HostId, Protocol, VaultData};

const CARD_WIDTH: f32 = 270.0;
const CARD_HEIGHT: f32 = 66.0;
const GROUP_HEIGHT: f32 = 58.0;
const GAP: f32 = 12.0;

enum Action {
    Connect(HostId),
    Sftp(HostId),
    Edit(Host),
    Duplicate(Host),
    Delete(HostId),
    OpenGroup(GroupId),
    EditGroup(Group),
    DeleteGroup(GroupId),
    NewHost,
}

fn protocol_icon(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::Ssh => icons::TERMINAL,
        Protocol::Mosh { .. } => icons::WIFI,
        Protocol::Telnet => icons::GLOBE,
        Protocol::Serial { .. } => icons::USB,
    }
}

fn subtitle(data: &VaultData, host: &Host) -> String {
    let user = data
        .resolve(host.id)
        .ok()
        .and_then(|r| r.identity)
        .map(|i| format!("{}@", i.username))
        .unwrap_or_default();
    match host.protocol() {
        Protocol::Serial { device, baud_rate } => format!("serie · {device} · {baud_rate}"),
        other => format!("{} · {user}{}", other.label().to_lowercase(), host.address),
    }
}

fn columns(width: f32, item: f32) -> usize {
    ((width + GAP) / (item + GAP)).floor().max(1.0) as usize
}

/// Cuadrícula de celdas del mismo tamaño que se adapta al ancho disponible.
fn grid<T>(ui: &mut egui::Ui, items: &[T], height: f32, mut cell: impl FnMut(&mut egui::Ui, &T)) {
    let cols = columns(ui.available_width(), CARD_WIDTH);
    let width = (ui.available_width() - GAP * (cols as f32 - 1.0)) / cols as f32;
    for row in items.chunks(cols) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            for item in row {
                ui.allocate_ui(Vec2::new(width, height), |ui| cell(ui, item));
            }
        });
        ui.add_space(GAP - ui.spacing().item_spacing.y);
    }
}

/// Una línea de texto recortada con "…" para que quepa en `width`.
fn elided(
    ui: &egui::Ui,
    text: &str,
    font: FontId,
    color: egui::Color32,
    width: f32,
) -> Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap = egui::text::TextWrapping {
        max_width: width.max(10.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    ui.painter().layout_job(job)
}

fn host_menu(ui: &mut egui::Ui, host: &Host, actions: &mut Vec<Action>) {
    if ui.button(ui::with_icon(icons::PLAY, "Conectar")).clicked() {
        actions.push(Action::Connect(host.id));
    }
    let has_sftp = matches!(host.protocol(), Protocol::Ssh | Protocol::Mosh { .. });
    if has_sftp
        && ui
            .button(ui::with_icon(icons::FOLDER_OPEN, "Abrir SFTP"))
            .clicked()
    {
        actions.push(Action::Sftp(host.id));
    }
    ui.separator();
    if ui.button(ui::with_icon(icons::PENCIL, "Editar")).clicked() {
        actions.push(Action::Edit(host.clone()));
    }
    if ui.button(ui::with_icon(icons::COPY, "Duplicar")).clicked() {
        actions.push(Action::Duplicate(host.clone()));
    }
    if ui.button(ui::with_icon(icons::TRASH, "Eliminar")).clicked() {
        actions.push(Action::Delete(host.id));
    }
}

fn host_card(ui: &mut egui::Ui, data: &VaultData, host: &Host, actions: &mut Vec<Action>) {
    let p = ui::pal(ui);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), CARD_HEIGHT), Sense::click());
    let hovered = response.hovered() || response.context_menu_opened();
    let painter = ui.painter();
    painter.rect_filled(
        rect,
        CornerRadius::same(10),
        if hovered { p.surface_hover } else { p.surface },
    );
    let stroke = if hovered {
        p.accent.gamma_multiply(0.5)
    } else {
        p.border
    };
    painter.rect_stroke(
        rect,
        CornerRadius::same(10),
        Stroke::new(1.0, stroke),
        egui::StrokeKind::Inside,
    );

    let avatar = Rect::from_min_size(rect.left_top() + Vec2::new(12.0, 13.0), Vec2::splat(40.0));
    ui::avatar(
        ui,
        avatar,
        protocol_icon(&host.protocol()),
        ui::theme::avatar_color(host.display_name()),
    );
    let text_left = avatar.right() + 12.0;
    let text_width = rect.right() - text_left - if hovered { 76.0 } else { 12.0 };
    let title = elided(
        ui,
        host.display_name(),
        FontId::proportional(14.5),
        p.text,
        text_width,
    );
    ui.painter()
        .galley(egui::pos2(text_left, rect.top() + 14.0), title, p.text);
    let sub = elided(
        ui,
        &subtitle(data, host),
        FontId::proportional(12.0),
        p.muted,
        text_width,
    );
    ui.painter()
        .galley(egui::pos2(text_left, rect.top() + 36.0), sub, p.muted);

    if hovered {
        let play = Rect::from_center_size(
            egui::pos2(rect.right() - 54.0, rect.center().y),
            Vec2::splat(28.0),
        );
        let more = Rect::from_center_size(
            egui::pos2(rect.right() - 22.0, rect.center().y),
            Vec2::splat(28.0),
        );
        let play_r = ui.interact(play, response.id.with("conectar"), Sense::click());
        let more_r = ui.interact(more, response.id.with("mas"), Sense::click());
        let (play_bg, play_fg) = if play_r.hovered() {
            (p.accent, p.accent_text)
        } else {
            (p.accent_soft, p.accent)
        };
        ui.painter()
            .rect_filled(play, CornerRadius::same(6), play_bg);
        ui.painter().text(
            play.center(),
            Align2::CENTER_CENTER,
            icons::PLAY,
            ui::icon_font(14.0),
            play_fg,
        );
        if more_r.hovered() {
            ui.painter()
                .rect_filled(more, CornerRadius::same(6), p.border);
        }
        ui.painter().text(
            more.center(),
            Align2::CENTER_CENTER,
            icons::MORE,
            ui::icon_font(16.0),
            p.muted,
        );
        if play_r.on_hover_text("Conectar").clicked() {
            actions.push(Action::Connect(host.id));
        }
        egui::Popup::menu(&more_r).show(|ui| host_menu(ui, host, actions));
    }
    if response.double_clicked() {
        actions.push(Action::Connect(host.id));
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .context_menu(|ui| host_menu(ui, host, actions));
}

fn group_card(ui: &mut egui::Ui, group: &Group, count: usize, actions: &mut Vec<Action>) {
    let p = ui::pal(ui);
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), GROUP_HEIGHT),
        Sense::click(),
    );
    let painter = ui.painter();
    painter.rect_filled(
        rect,
        CornerRadius::same(10),
        if response.hovered() {
            p.surface_hover
        } else {
            p.surface
        },
    );
    painter.rect_stroke(
        rect,
        CornerRadius::same(10),
        Stroke::new(1.0, p.border),
        egui::StrokeKind::Inside,
    );
    let avatar = Rect::from_min_size(rect.left_top() + Vec2::new(12.0, 11.0), Vec2::splat(36.0));
    ui::avatar(ui, avatar, icons::FOLDER, p.muted);
    let text_left = avatar.right() + 12.0;
    let name = elided(
        ui,
        &group.name,
        FontId::proportional(14.5),
        p.text,
        rect.right() - text_left - 30.0,
    );
    ui.painter()
        .galley(egui::pos2(text_left, rect.top() + 12.0), name, p.text);
    let hosts = if count == 1 {
        "1 host".to_string()
    } else {
        format!("{count} hosts")
    };
    ui.painter().text(
        egui::pos2(text_left, rect.top() + 32.0),
        Align2::LEFT_TOP,
        hosts,
        FontId::proportional(12.0),
        p.muted,
    );
    ui.painter().text(
        rect.right_center() - Vec2::new(14.0, 0.0),
        Align2::RIGHT_CENTER,
        icons::CARET_RIGHT,
        ui::icon_font(14.0),
        p.muted,
    );
    if response.clicked() {
        actions.push(Action::OpenGroup(group.id));
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .context_menu(|ui| {
            if ui
                .button(ui::with_icon(icons::PENCIL, "Editar grupo"))
                .clicked()
            {
                actions.push(Action::EditGroup(group.clone()));
            }
            if ui
                .button(ui::with_icon(
                    icons::TRASH,
                    "Eliminar grupo (sus hosts se conservan)",
                ))
                .clicked()
            {
                actions.push(Action::DeleteGroup(group.id));
            }
        });
}

/// Grupos que cuelgan directamente de `parent`, ordenados por nombre.
fn child_groups(data: &VaultData, parent: Option<GroupId>) -> Vec<&Group> {
    let mut groups: Vec<&Group> = data.groups.iter().filter(|g| g.parent == parent).collect();
    groups.sort_by_key(|g| g.name.to_lowercase());
    groups
}

/// Grupos desde la raíz hasta `current` (protegido contra ciclos).
fn group_path(data: &VaultData, current: GroupId) -> Vec<&Group> {
    let mut chain: Vec<&Group> = Vec::new();
    let mut cursor = data.group(current);
    while let Some(group) = cursor {
        if chain.iter().any(|g| g.id == group.id) {
            break;
        }
        chain.push(group);
        cursor = group.parent.and_then(|id| data.group(id));
    }
    chain.reverse();
    chain
}

fn breadcrumb(ui: &mut egui::Ui, data: &VaultData, current: GroupId) -> Option<Option<GroupId>> {
    let p = ui::pal(ui);
    let mut target = None;
    ui.horizontal(|ui| {
        if ui
            .link(RichText::new("Todos los hosts").color(p.muted))
            .clicked()
        {
            target = Some(None);
        }
        for group in group_path(data, current) {
            ui.label(
                RichText::new(icons::CARET_RIGHT)
                    .font(ui::icon_font(12.0))
                    .color(p.muted),
            );
            if group.id == current {
                ui.label(RichText::new(&group.name).strong());
            } else if ui.link(&group.name).clicked() {
                target = Some(Some(group.id));
            }
        }
    });
    ui.add_space(6.0);
    target
}

/// Hosts visibles: todos los que coinciden al buscar; si no, los del grupo actual
/// (en la raíz también los que apuntan a un grupo que ya no existe).
fn visible_hosts<'a>(data: &'a VaultData, query: &str, group: Option<GroupId>) -> Vec<&'a Host> {
    let searching = !query.trim().is_empty();
    data.search_hosts(query)
        .into_iter()
        .filter(|h| {
            searching
                || h.group == group
                || (group.is_none() && h.group.is_some_and(|g| data.group(g).is_none()))
        })
        .collect()
}

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let mut actions = Vec::new();
    let mut navigate = None;
    if app.host_group.is_some_and(|g| data.group(g).is_none()) {
        app.host_group = None;
    }
    let subtitle = format!("{} hosts · {} grupos", data.hosts.len(), data.groups.len());
    ui::page_header(ui, "Hosts", &subtitle, |ui| {
        if ui::primary_button(ui, &ui::with_icon(icons::PLUS, "Host")).clicked() {
            actions.push(Action::NewHost);
        }
        if ui::secondary_button(ui, &ui::with_icon(icons::FOLDER, "Grupo")).clicked() {
            app.editor = Some(Editor::Group(Group {
                parent: app.host_group,
                ..Group::new("Nuevo grupo")
            }));
        }
    });
    ui::search_box(
        ui,
        &mut app.search,
        "Buscar por nombre, dirección o etiqueta",
        f32::INFINITY,
    );
    ui.add_space(14.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if data.hosts.is_empty() && data.groups.is_empty() {
                ui::empty_state(
                    ui,
                    icons::SERVERS,
                    "Aún no tienes hosts",
                    "Crea uno con «Host» o importa tu ~/.ssh/config desde Ajustes.",
                );
                return;
            }
            let searching = !app.search.trim().is_empty();
            if let (Some(group), false) = (app.host_group, searching) {
                navigate = breadcrumb(ui, &data, group);
            }
            if !searching {
                let groups = child_groups(&data, app.host_group);
                if !groups.is_empty() {
                    ui::section_label(ui, "Grupos");
                    grid(ui, &groups, GROUP_HEIGHT, |ui, group| {
                        let count = data
                            .hosts
                            .iter()
                            .filter(|h| h.group == Some(group.id))
                            .count();
                        group_card(ui, group, count, &mut actions);
                    });
                    ui.add_space(8.0);
                }
            }
            let hosts = visible_hosts(&data, &app.search, app.host_group);
            if !hosts.is_empty() {
                ui::section_label(ui, if searching { "Resultados" } else { "Hosts" });
                grid(ui, &hosts, CARD_HEIGHT, |ui, host| {
                    host_card(ui, &data, host, &mut actions)
                });
            } else if searching {
                ui::empty_state(
                    ui,
                    icons::SEARCH,
                    "Sin resultados",
                    "Ningún host coincide con la búsqueda.",
                );
            }
        });

    if let Some(target) = navigate {
        app.host_group = target;
    }
    for action in actions {
        match action {
            Action::Connect(id) => app.open_host(id),
            Action::Sftp(id) => app.open_sftp(id),
            Action::Edit(host) => app.editor = Some(Editor::host(host)),
            Action::NewHost => {
                app.editor = Some(Editor::host(Host {
                    group: app.host_group,
                    ..Host::new("", "")
                }))
            }
            Action::Duplicate(host) => {
                let copy = Host {
                    id: HostId::new(),
                    label: format!("{} (copia)", host.display_name()),
                    ..host
                };
                app.editor = Some(Editor::host(copy));
            }
            Action::Delete(id) => app.commit(data.without_host(id)),
            Action::OpenGroup(id) => {
                app.host_group = Some(id);
                app.search.clear();
            }
            Action::EditGroup(group) => app.editor = Some(Editor::Group(group)),
            Action::DeleteGroup(id) => app.commit(data.without_group(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_fit_cards_into_width() {
        assert_eq!(columns(200.0, CARD_WIDTH), 1);
        assert_eq!(columns(2.0 * CARD_WIDTH + GAP, CARD_WIDTH), 2);
        assert_eq!(columns(3.0 * CARD_WIDTH + 2.0 * GAP - 1.0, CARD_WIDTH), 2);
    }

    #[test]
    fn subtitle_shows_protocol_user_and_address() {
        let identity = tunel_core::Identity::new("ana", "ana");
        let host = Host {
            identity: Some(identity.id),
            ..Host::new("web", "10.0.0.1")
        };
        let data = VaultData::default()
            .with_identity(identity)
            .with_host(host.clone());
        assert_eq!(subtitle(&data, &host), "ssh · ana@10.0.0.1");
    }

    #[test]
    fn visible_hosts_follow_group_navigation_and_search() {
        let group = Group::new("Prod");
        let inside = Host {
            group: Some(group.id),
            ..Host::new("dentro", "a")
        };
        let orphan = Host {
            group: Some(GroupId::new()),
            ..Host::new("huerfano", "b")
        };
        let root = Host::new("raiz", "c");
        let data = VaultData::default()
            .with_group(group.clone())
            .with_host(inside)
            .with_host(orphan)
            .with_host(root);
        let names = |hosts: Vec<&Host>| {
            hosts
                .into_iter()
                .map(|h| h.label.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(visible_hosts(&data, "", None)),
            vec!["huerfano", "raiz"]
        );
        assert_eq!(
            names(visible_hosts(&data, "", Some(group.id))),
            vec!["dentro"]
        );
        assert_eq!(names(visible_hosts(&data, "dentro", None)), vec!["dentro"]);
    }

    #[test]
    fn group_path_runs_from_root_and_survives_cycles() {
        let a = Group::new("a");
        let b = Group {
            parent: Some(a.id),
            ..Group::new("b")
        };
        let data = VaultData::default()
            .with_group(a.clone())
            .with_group(b.clone());
        let names: Vec<&str> = group_path(&data, b.id)
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(names, vec!["a", "b"]);
        let looped = data.with_group(Group {
            parent: Some(b.id),
            ..a
        });
        assert_eq!(group_path(&looped, b.id).len(), 2);
    }
}
