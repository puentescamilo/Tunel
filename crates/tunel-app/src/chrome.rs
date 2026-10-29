//! Marco de la ventana: menú lateral, barra de pestañas y avisos.

use crate::app::{Section, TabState, TunelApp};
use crate::ui::{self, icons};
use crate::updates::{Update, UpdateStatus, current_version};
use egui::{Align2, Color32, CornerRadius, FontId, Rect, RichText, Sense, Stroke, Vec2};

const SIDEBAR_WIDTH: f32 = 220.0;
/// Ancho del menú compacto que se usa mientras hay una sesión en pantalla.
const RAIL_WIDTH: f32 = 60.0;
const TAB_BAR_HEIGHT: f32 = 42.0;
const TAB_WIDTH: f32 = 180.0;
const TAB_TITLE_CHARS: usize = 20;

fn shortcut(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⌘{key}")
    } else {
        format!("Ctrl+{key}")
    }
}

fn logo(ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
        ui.painter()
            .rect_filled(rect, CornerRadius::same(8), p.accent);
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            icons::TERMINAL,
            ui::icon_font(17.0),
            p.accent_text,
        );
        ui.add_space(2.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(RichText::new("Túnel").size(16.0).strong());
            ui.label(RichText::new("Cliente SSH").size(11.0).color(p.muted));
        });
    });
}

/// Menú compacto de iconos: deja casi todo el ancho a la terminal.
fn rail(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let frame = egui::Frame::new()
        .fill(p.sidebar)
        .inner_margin(egui::Margin::symmetric(8, 12));
    egui::Panel::left("menu-compacto")
        .exact_size(RAIL_WIDTH)
        .resizable(false)
        .frame(frame)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            if ui::rail_item(
                ui,
                icons::LIGHTNING,
                &format!("Conexión rápida ({})", shortcut("K")),
                false,
            )
            .clicked()
            {
                app.quick_connect = Some(Default::default());
            }
            ui.add_space(8.0);
            for section in Section::ALL {
                if ui::rail_item(ui, section.icon(), section.label(), false).clicked() {
                    app.section = section;
                    app.active = None;
                }
            }
            ui.add_space(8.0);
            if ui::rail_item(
                ui,
                icons::DESKTOP,
                &format!("Terminal local ({})", shortcut("T")),
                false,
            )
            .clicked()
            {
                app.open_local();
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                if ui::rail_item(ui, icons::LOCK, "Bloquear bóveda", false).clicked() {
                    app.lock_vault();
                }
                if let Some(update) = app.updates.available().cloned() {
                    let tooltip = format!("Versión {} disponible: descargar", update.version);
                    let response = ui::rail_item(ui, icons::DOWNLOAD, &tooltip, false);
                    ui::status_dot(
                        ui,
                        response.rect.center() + Vec2::new(10.0, -10.0),
                        p.accent,
                    );
                    if response.clicked() {
                        download(app, ui.ctx(), &update);
                    }
                }
            });
        });
}

pub fn sidebar(app: &mut TunelApp, ui: &mut egui::Ui) {
    if app.active.is_some() {
        return rail(app, ui);
    }
    let p = ui::pal(ui);
    let counts = app.data().map(|d| {
        [
            d.hosts.len(),
            d.identities.len() + d.keys.len(),
            d.forwards.len(),
            d.snippets.len(),
            d.known_hosts.len(),
            0,
        ]
    });
    let frame = egui::Frame::new()
        .fill(p.sidebar)
        .inner_margin(egui::Margin::symmetric(12, 14));
    egui::Panel::left("menu")
        .exact_size(SIDEBAR_WIDTH)
        .resizable(false)
        .frame(frame)
        .show(ui, |ui| {
            egui::Panel::bottom("menu-pie")
                .frame(egui::Frame::NONE)
                .resizable(false)
                .show_separator_line(false)
                .show(ui, |ui| sidebar_footer(app, ui));
            logo(ui);
            ui.add_space(18.0);
            let width = ui.available_width();
            if ui::secondary_button_sized(
                ui,
                &ui::with_icon(
                    icons::LIGHTNING,
                    &format!("Conexión rápida   {}", shortcut("K")),
                ),
                width,
            )
            .on_hover_text("Busca un host o escribe usuario@servidor")
            .clicked()
            {
                app.quick_connect = Some(Default::default());
            }
            ui.add_space(12.0);
            ui::section_label(ui, "Bóveda");
            for (i, section) in Section::ALL.into_iter().enumerate() {
                let selected = app.active.is_none() && app.section == section;
                let badge = counts.map(|c| c[i]);
                if ui::nav_item(ui, section.icon(), section.label(), selected, badge).clicked() {
                    app.section = section;
                    app.active = None;
                }
            }
            ui.add_space(12.0);
            ui::section_label(ui, "Este equipo");
            if ui::nav_item(ui, icons::DESKTOP, "Terminal local", false, None)
                .on_hover_text(shortcut("T"))
                .clicked()
            {
                app.open_local();
            }
        });
}

/// Pie del menú: aviso de versión nueva, versión instalada y bloqueo de la bóveda.
fn sidebar_footer(app: &mut TunelApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    if let Some(update) = app.updates.available().cloned() {
        update_card(app, ui, &update);
        ui.add_space(8.0);
    }
    version_row(app, ui);
    if ui::nav_item(ui, icons::LOCK, "Bloquear bóveda", false, None).clicked() {
        app.lock_vault();
    }
}

fn update_card(app: &mut TunelApp, ui: &mut egui::Ui, update: &Update) {
    let p = ui::pal(ui);
    ui::card_frame(ui, true).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(icons::ARROW_UP)
                    .font(ui::icon_font(15.0))
                    .color(p.accent),
            );
            ui.label(RichText::new(format!("Versión {} disponible", update.version)).strong());
        });
        ui.label(
            RichText::new(format!("Tienes la {}", current_version()))
                .size(12.0)
                .color(p.muted),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui::primary_button(ui, &ui::with_icon(icons::DOWNLOAD, "Descargar"))
                .on_hover_text("Descarga el instalador para este equipo")
                .clicked()
            {
                download(app, ui.ctx(), update);
            }
            if ui
                .link(RichText::new("Novedades").size(12.0).color(p.accent))
                .clicked()
            {
                ui.ctx().open_url(egui::OpenUrl::new_tab(&update.notes_url));
            }
        });
    });
}

/// Abre la descarga en el navegador: el usuario ejecuta el instalador por su cuenta.
fn download(app: &mut TunelApp, ctx: &egui::Context, update: &Update) {
    ctx.open_url(egui::OpenUrl::new_tab(&update.download_url));
    app.notify("Abre el instalador descargado para actualizar Túnel");
}

/// Versión instalada y estado de la última comprobación; un clic vuelve a comprobar.
fn version_row(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let (status, color) = match &app.updates.status {
        UpdateStatus::NotChecked | UpdateStatus::Available(_) => ("", p.muted),
        UpdateStatus::Checking => ("Buscando…", p.muted),
        UpdateStatus::UpToDate => ("Al día", p.success),
        UpdateStatus::Failed(_) => ("Sin comprobar", p.muted),
    };
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 24.0), Sense::click());
    let painter = ui.painter();
    if response.hovered() {
        painter.rect_filled(rect, CornerRadius::same(6), p.surface_hover);
    }
    painter.text(
        rect.left_center() + Vec2::new(14.0, 0.0),
        Align2::LEFT_CENTER,
        format!("Túnel {}", current_version()),
        FontId::proportional(12.0),
        p.muted,
    );
    painter.text(
        rect.right_center() - Vec2::new(10.0, 0.0),
        Align2::RIGHT_CENTER,
        status,
        FontId::proportional(12.0),
        color,
    );
    let hover = match &app.updates.status {
        UpdateStatus::Failed(error) => {
            format!("No se pudo comprobar: {error}\nClic para reintentar")
        }
        _ => "Buscar actualizaciones".to_string(),
    };
    if response
        .on_hover_text(hover)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
    {
        let engine = &app.engine;
        app.updates.check_now(|| engine.check_updates());
    }
}

fn state_color(p: &ui::Palette, state: TabState) -> Color32 {
    match state {
        TabState::Connecting => p.warning,
        TabState::Live => p.success,
        TabState::Ended => p.muted,
        TabState::Failed => p.danger,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    }
}

enum TabAction {
    Select(Option<usize>),
    Close(usize),
    ToggleSplit(usize),
}

/// Dibuja una pestaña; devuelve (clic en la pestaña, clic en cerrar).
fn tab(
    ui: &mut egui::Ui,
    icon: &str,
    title: &str,
    selected: bool,
    dot: Option<Color32>,
    closable: bool,
) -> (egui::Response, bool) {
    let p = ui::pal(ui);
    let width = if closable { TAB_WIDTH } else { 96.0 };
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width, TAB_BAR_HEIGHT - 10.0), Sense::click());
    let hovered = response.hovered();
    let fill = if selected {
        p.bg
    } else if hovered {
        p.surface_hover
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, CornerRadius::same(7), fill);
    if selected {
        ui.painter().rect_stroke(
            rect,
            CornerRadius::same(7),
            Stroke::new(1.0, p.border),
            egui::StrokeKind::Inside,
        );
    }
    let fg = if selected { p.text } else { p.muted };
    let mut x = rect.left() + 12.0;
    ui.painter().text(
        egui::pos2(x, rect.center().y),
        Align2::LEFT_CENTER,
        icon,
        ui::icon_font(15.0),
        fg,
    );
    x += 22.0;
    if let Some(color) = dot {
        ui::status_dot(ui, egui::pos2(x + 2.0, rect.center().y), color);
        x += 12.0;
    }
    ui.painter().text(
        egui::pos2(x, rect.center().y),
        Align2::LEFT_CENTER,
        truncate(title, TAB_TITLE_CHARS),
        FontId::proportional(13.0),
        fg,
    );
    let mut close_clicked = false;
    if closable && (hovered || selected) {
        let close_rect = Rect::from_center_size(
            egui::pos2(rect.right() - 16.0, rect.center().y),
            Vec2::splat(20.0),
        );
        let close = ui.interact(close_rect, response.id.with("cerrar"), Sense::click());
        if close.hovered() {
            ui.painter()
                .rect_filled(close_rect, CornerRadius::same(5), p.surface_hover);
        }
        ui.painter().text(
            close_rect.center(),
            Align2::CENTER_CENTER,
            icons::CLOSE,
            ui::icon_font(12.0),
            fg,
        );
        close_clicked = close.clicked();
    }
    (
        response.on_hover_cursor(egui::CursorIcon::PointingHand),
        close_clicked,
    )
}

pub fn tab_bar(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let frame = egui::Frame::new()
        .fill(p.sidebar)
        .inner_margin(egui::Margin {
            left: 8,
            right: 8,
            top: 5,
            bottom: 5,
        })
        .stroke(Stroke::new(1.0, p.border));
    let mut action = None;
    egui::Panel::top("pestañas")
        .exact_size(TAB_BAR_HEIGHT)
        .frame(frame)
        .show(ui, |ui| {
            egui::ScrollArea::horizontal()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                .show(ui, |ui| {
                    ui.horizontal_centered(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let home_selected = app.active.is_none();
                        if tab(ui, icons::SERVERS, "Bóveda", home_selected, None, false)
                            .0
                            .clicked()
                        {
                            action = Some(TabAction::Select(None));
                        }
                        for (i, t) in app.tabs.iter().enumerate() {
                            let selected = app.active == Some(i) || app.split == Some(i);
                            let (response, close) = tab(
                                ui,
                                t.icon(),
                                t.title(),
                                selected,
                                Some(state_color(&p, t.state())),
                                true,
                            );
                            if close {
                                action = Some(TabAction::Close(i));
                            } else if response.clicked() {
                                action = Some(TabAction::Select(Some(i)));
                            } else if response.middle_clicked() {
                                action = Some(TabAction::Close(i));
                            }
                            response.context_menu(|ui| {
                                let label = if app.split == Some(i) {
                                    "Quitar de la vista dividida"
                                } else {
                                    "Abrir en vista dividida"
                                };
                                if ui.button(ui::with_icon(icons::COLUMNS, label)).clicked() {
                                    action = Some(TabAction::ToggleSplit(i));
                                    ui.close();
                                }
                                if ui
                                    .button(ui::with_icon(icons::CLOSE, "Cerrar pestaña"))
                                    .clicked()
                                {
                                    action = Some(TabAction::Close(i));
                                    ui.close();
                                }
                            });
                        }
                        if ui::icon_button(
                            ui,
                            icons::PLUS,
                            &format!("Nueva conexión ({})", shortcut("K")),
                        )
                        .clicked()
                        {
                            app.quick_connect = Some(Default::default());
                        }
                    });
                });
        });
    match action {
        Some(TabAction::Select(index)) => app.active = index,
        Some(TabAction::Close(i)) => app.close_tab(i),
        Some(TabAction::ToggleSplit(i)) => {
            app.split = if app.split == Some(i) || app.active == Some(i) {
                None
            } else {
                Some(i)
            };
        }
        None => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerAction {
    Reconnect,
    Close,
}

/// Franja sobre una terminal terminada o fallida, con acciones.
pub fn session_banner(
    ui: &mut egui::Ui,
    message: &str,
    failed: bool,
    can_reconnect: bool,
) -> Option<BannerAction> {
    let p = ui::pal(ui);
    let color = if failed { p.danger } else { p.muted };
    let mut action = None;
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .inner_margin(egui::Margin::symmetric(14, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let icon = if failed { icons::WARNING } else { icons::STOP };
                ui.label(RichText::new(icon).font(ui::icon_font(16.0)).color(color));
                ui.label(RichText::new(message).color(p.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui::secondary_button(ui, "Cerrar").clicked() {
                        action = Some(BannerAction::Close);
                    }
                    if can_reconnect
                        && ui::primary_button(ui, &ui::with_icon(icons::REFRESH, "Reconectar"))
                            .clicked()
                    {
                        action = Some(BannerAction::Reconnect);
                    }
                });
            });
        });
    action
}

pub fn notices(app: &TunelApp, ctx: &egui::Context) {
    if app.notices.is_empty() {
        return;
    }
    let p = ui::theme::palette(ctx);
    egui::Area::new(egui::Id::unique("avisos"))
        .anchor(Align2::RIGHT_BOTTOM, [-16.0, -16.0])
        .show(ctx, |ui| {
            for (_, message) in &app.notices {
                egui::Frame::popup(ui.style())
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .show(ui, |ui| {
                        ui.set_max_width(380.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(icons::CHECK)
                                    .font(ui::icon_font(15.0))
                                    .color(p.accent),
                            );
                            ui.label(message);
                        });
                    });
            }
        });
    ctx.request_repaint_after(std::time::Duration::from_secs(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_short_titles_and_ellipsizes_long_ones() {
        assert_eq!(truncate("web", 5), "web");
        assert_eq!(truncate("servidor-largo", 6), "servi…");
        assert_eq!(truncate("ñandú-ñandú", 4), "ñan…");
    }
}
