//! Barra de pestañas: la seleccionada toma el fondo de su terminal, como si fuera parte de
//! ella, y las demás se atenúan.

use crate::app::{Tab, TabState, TunelApp};
use crate::chrome::shortcut;
use crate::ui::{self, icons};
use egui::{Align2, Color32, CornerRadius, FontId, Rect, Sense, Stroke, Vec2};
use tunel_core::theme::Rgb;

const TAB_BAR_HEIGHT: f32 = 42.0;
/// Hueco sobre las pestañas: por abajo tocan la terminal.
const TAB_TOP_GAP: f32 = 6.0;
const TAB_WIDTH: f32 = 180.0;
const HOME_TAB_WIDTH: f32 = 96.0;
const TAB_TITLE_CHARS: usize = 20;
const TAB_RADIUS: u8 = 7;
const BORDER_WIDTH: f32 = 2.0;
/// Opacidad del contenido de las pestañas no seleccionadas.
const INACTIVE_OPACITY: f32 = 0.6;
const MAX_TAB_NAME: usize = 60;

/// Texto sobre fondos oscuros y claros.
const LIGHT_TEXT: Color32 = Color32::from_rgb(0xf2, 0xf4, 0xf8);
const DARK_TEXT: Color32 = Color32::from_rgb(0x1b, 0x21, 0x30);
/// Borde automático sobre fondo claro.
const LIGHT_BG_BORDER: Color32 = Color32::from_rgb(0x8a, 0x93, 0xa6);

/// Colores con que se pinta la pestaña seleccionada.
#[derive(Debug, Clone, Copy, PartialEq)]
struct SelectedLook {
    fill: Color32,
    text: Color32,
    border: Color32,
}

/// Luminancia relativa (WCAG) de un color.
fn luminance(color: Color32) -> f32 {
    let channel = |v: u8| {
        let v = f32::from(v) / 255.0;
        if v <= 0.039_28 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
}

/// La pestaña seleccionada sobre el fondo `background`: texto e icono claros u oscuros
/// según el fondo, y el borde elegido en ajustes o, en automático, blanco o gris.
fn selected_look(background: Color32, custom_border: Option<Rgb>) -> SelectedLook {
    let dark = luminance(background) < 0.18;
    let border = match custom_border {
        Some([r, g, b]) => Color32::from_rgb(r, g, b),
        None if dark => Color32::WHITE,
        None => LIGHT_BG_BORDER,
    };
    SelectedLook {
        fill: background,
        text: if dark { LIGHT_TEXT } else { DARK_TEXT },
        border,
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

/// Punto de estado con sombra, para que no se pierda sobre fondos claros.
fn shadowed_dot(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    painter.circle_filled(
        center + Vec2::new(0.0, 0.5),
        5.5,
        Color32::from_black_alpha(70),
    );
    painter.circle_filled(center, 4.0, color);
    painter.circle_stroke(center, 4.0, Stroke::new(0.5, Color32::from_black_alpha(60)));
}

enum TabAction {
    Select(Option<usize>),
    Close(usize),
    ToggleSplit(usize),
    Share { tab: u64, team: String },
    StopSharing(u64),
    Reconnect(usize),
    Duplicate(usize),
    Rename(usize),
}

/// Contenido de una pestaña.
struct TabSpec<'a> {
    icon: &'a str,
    title: &'a str,
    /// `Some` si está seleccionada.
    selected: Option<SelectedLook>,
    dot: Option<Color32>,
    closable: bool,
}

/// Dibuja una pestaña; devuelve (clic en la pestaña, clic en cerrar).
fn tab(ui: &mut egui::Ui, spec: TabSpec) -> (egui::Response, bool) {
    let p = ui::pal(ui);
    let width = if spec.closable {
        TAB_WIDTH
    } else {
        HOME_TAB_WIDTH
    };
    let (rect, response) = ui.allocate_exact_size(
        // Todo el alto que deja el panel, para que el borde inferior no quede recortado.
        Vec2::new(width, ui.available_height()),
        Sense::click(),
    );
    let hovered = response.hovered();
    let painter = ui.painter();
    let corners = CornerRadius {
        nw: TAB_RADIUS,
        ne: TAB_RADIUS,
        sw: 0,
        se: 0,
    };
    let (fg, dot_opacity) = match spec.selected {
        Some(look) => {
            painter.rect_filled(rect, corners, look.fill);
            let border = Rect::from_min_max(
                egui::pos2(rect.left(), rect.bottom() - BORDER_WIDTH),
                rect.right_bottom(),
            );
            painter.rect_filled(border, CornerRadius::ZERO, look.border);
            (look.text, 1.0)
        }
        None if hovered => {
            painter.rect_filled(rect, corners, p.surface_hover);
            (p.muted, 1.0)
        }
        None => (p.muted.gamma_multiply(INACTIVE_OPACITY), INACTIVE_OPACITY),
    };
    let center_y = rect.center().y - BORDER_WIDTH / 2.0;
    let mut x = rect.left() + 12.0;
    painter.text(
        egui::pos2(x, center_y),
        Align2::LEFT_CENTER,
        spec.icon,
        ui::icon_font(15.0),
        fg,
    );
    x += 22.0;
    if let Some(color) = spec.dot {
        shadowed_dot(
            painter,
            egui::pos2(x + 2.0, center_y),
            color.gamma_multiply(dot_opacity),
        );
        x += 12.0;
    }
    painter.text(
        egui::pos2(x, center_y),
        Align2::LEFT_CENTER,
        truncate(spec.title, TAB_TITLE_CHARS),
        FontId::proportional(13.0),
        fg,
    );
    let mut close_clicked = false;
    if spec.closable && (hovered || spec.selected.is_some()) {
        let close_rect =
            Rect::from_center_size(egui::pos2(rect.right() - 16.0, center_y), Vec2::splat(20.0));
        let close = ui.interact(close_rect, response.id.with("cerrar"), Sense::click());
        if close.hovered() {
            ui.painter()
                .rect_filled(close_rect, CornerRadius::same(5), fg.gamma_multiply(0.15));
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
        response
            .on_hover_text(spec.title)
            .on_hover_cursor(egui::CursorIcon::PointingHand),
        close_clicked,
    )
}

/// Fondo de la pestaña `t` seleccionada: el de su terminal, o el de la interfaz para SFTP.
fn tab_background(app: &TunelApp, p: &ui::Palette, t: &Tab) -> Color32 {
    match t {
        Tab::Terminal(session) => {
            let [r, g, b] = app.terminal_theme(session.host).background;
            Color32::from_rgb(r, g, b)
        }
        Tab::Sftp(_) => p.bg,
    }
}

/// Teams con los que se puede compartir una terminal: identificador y nombre.
fn shareable_teams(app: &TunelApp) -> Vec<(String, String)> {
    let ready = app.sync.local().is_some_and(|l| l.keypair.is_some());
    if ready {
        crate::sync::teams::names(app)
    } else {
        Vec::new()
    }
}

/// «Compartir con…» en el menú de una pestaña de terminal.
fn share_menu(
    ui: &mut egui::Ui,
    tab: &Tab,
    teams: &[(String, String)],
    action: &mut Option<TabAction>,
) {
    let Tab::Terminal(session) = tab else {
        return;
    };
    match &session.live {
        Some(crate::live::Live::Host(_)) => {
            if ui
                .button(ui::with_icon(icons::STOP, "Dejar de compartir"))
                .clicked()
            {
                *action = Some(TabAction::StopSharing(session.key));
                ui.close();
            }
        }
        Some(crate::live::Live::Viewer(_)) => {}
        None if session.is_alive() && !teams.is_empty() => {
            ui.menu_button(ui::with_icon(icons::BROADCAST, "Compartir con"), |ui| {
                for (id, name) in teams {
                    if ui.button(name).clicked() {
                        *action = Some(TabAction::Share {
                            tab: session.key,
                            team: id.clone(),
                        });
                        ui.close();
                    }
                }
            });
        }
        None => {}
    }
}

/// Menú de clic derecho de la pestaña `i`.
fn context_menu(
    ui: &mut egui::Ui,
    app: &TunelApp,
    i: usize,
    teams: &[(String, String)],
    action: &mut Option<TabAction>,
) {
    let mut item = |ui: &mut egui::Ui, icon: &str, label: &str, chosen: TabAction| {
        if ui.button(ui::with_icon(icon, label)).clicked() {
            *action = Some(chosen);
            ui.close();
        }
    };
    item(ui, icons::PENCIL, "Renombrar", TabAction::Rename(i));
    if app.can_reopen(i) {
        item(ui, icons::REFRESH, "Reconectar", TabAction::Reconnect(i));
        item(ui, icons::COPY, "Duplicar", TabAction::Duplicate(i));
    }
    ui.separator();
    share_menu(ui, &app.tabs[i], teams, action);
    let label = if app.split == Some(i) {
        "Quitar de la vista dividida"
    } else {
        "Abrir en vista dividida"
    };
    if ui.button(ui::with_icon(icons::COLUMNS, label)).clicked() {
        *action = Some(TabAction::ToggleSplit(i));
        ui.close();
    }
    if ui
        .button(ui::with_icon(icons::CLOSE, "Cerrar pestaña"))
        .clicked()
    {
        *action = Some(TabAction::Close(i));
        ui.close();
    }
}

pub fn tab_bar(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let frame = egui::Frame::new()
        .fill(p.sidebar)
        .inner_margin(egui::Margin {
            left: 8,
            right: 8,
            top: TAB_TOP_GAP as i8,
            bottom: 0,
        })
        .stroke(Stroke::new(1.0, p.border));
    let mut action = None;
    let teams = shareable_teams(app);
    let border = app.data().and_then(|d| d.settings.tab_border);
    egui::Panel::top("pestañas")
        .exact_size(TAB_BAR_HEIGHT)
        .frame(frame)
        .show(ui, |ui| {
            egui::ScrollArea::horizontal()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                .show(ui, |ui| {
                    ui.horizontal_centered(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let home = TabSpec {
                            icon: icons::SERVERS,
                            title: "Bóveda",
                            selected: app.active.is_none().then(|| selected_look(p.bg, border)),
                            dot: None,
                            closable: false,
                        };
                        if tab(ui, home).0.clicked() {
                            action = Some(TabAction::Select(None));
                        }
                        for (i, t) in app.tabs.iter().enumerate() {
                            let selected = app.active == Some(i) || app.split == Some(i);
                            let spec = TabSpec {
                                icon: t.icon(),
                                title: t.title(),
                                selected: selected
                                    .then(|| selected_look(tab_background(app, &p, t), border)),
                                dot: Some(state_color(&p, t.state())),
                                closable: true,
                            };
                            let (response, close) = tab(ui, spec);
                            if close || response.middle_clicked() {
                                action = Some(TabAction::Close(i));
                            } else if response.clicked() {
                                action = Some(TabAction::Select(Some(i)));
                            }
                            response.context_menu(|ui| {
                                context_menu(ui, app, i, &teams, &mut action);
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
        Some(TabAction::Share { tab, team }) => crate::live::start_sharing(app, tab, team),
        Some(TabAction::StopSharing(tab)) => crate::live::stop_sharing(app, tab),
        Some(TabAction::Reconnect(i)) => app.reconnect_tab(i),
        Some(TabAction::Duplicate(i)) => app.duplicate_tab(i),
        Some(TabAction::Rename(i)) => {
            app.tab_rename = Some(TabRename {
                index: i,
                name: app.tabs[i].title().to_string(),
            });
        }
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

/// Nombre que se está escribiendo para una pestaña.
pub struct TabRename {
    index: usize,
    name: String,
}

/// Nombre válido para una pestaña: sin espacios a los lados y no vacío.
fn clean_name(name: &str) -> Option<String> {
    let name: String = name.trim().chars().take(MAX_TAB_NAME).collect();
    (!name.is_empty()).then_some(name)
}

/// Ventana para cambiar el nombre de una pestaña.
pub fn rename_dialog(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(rename) = app.tab_rename.as_mut() else {
        return;
    };
    if rename.index >= app.tabs.len() {
        app.tab_rename = None;
        return;
    }
    let frame = egui::Frame::popup(&ctx.global_style())
        .inner_margin(egui::Margin::same(20))
        .corner_radius(CornerRadius::same(14));
    let mut done = None;
    let modal = egui::Modal::new(egui::Id::unique("renombrar-pestaña"))
        .frame(frame)
        .show(ctx, |ui| {
            ui.set_width(320.0);
            ui.label(egui::RichText::new("Renombrar pestaña").size(16.0).strong());
            ui.add_space(10.0);
            let field = ui.add(
                egui::TextEdit::singleline(&mut rename.name)
                    .char_limit(MAX_TAB_NAME)
                    .desired_width(f32::INFINITY),
            );
            if !field.has_focus() && !field.lost_focus() {
                field.request_focus();
            }
            let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui::primary_button(ui, "Guardar").clicked() || enter {
                    done = Some(true);
                }
                if ui::secondary_button(ui, "Cancelar").clicked() {
                    done = Some(false);
                }
            });
        });
    if modal.should_close() {
        done.get_or_insert(false);
    }
    match done {
        Some(true) => {
            let Some(rename) = app.tab_rename.take() else {
                return;
            };
            match clean_name(&rename.name) {
                Some(name) => app.tabs[rename.index].set_title(name),
                None => {
                    app.tab_rename = Some(rename);
                    app.notify("El nombre de la pestaña no puede estar vacío");
                }
            }
        }
        Some(false) => app.tab_rename = None,
        None => {}
    }
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

    #[test]
    fn a_dark_terminal_gets_light_text_and_a_white_border() {
        let look = selected_look(Color32::from_rgb(0x0f, 0x12, 0x18), None);
        assert_eq!(look.fill, Color32::from_rgb(0x0f, 0x12, 0x18));
        assert_eq!(look.text, LIGHT_TEXT);
        assert_eq!(look.border, Color32::WHITE);
    }

    #[test]
    fn a_light_terminal_gets_dark_text_and_a_gray_border() {
        let look = selected_look(Color32::from_rgb(0xfd, 0xf6, 0xe3), None);
        assert_eq!(look.text, DARK_TEXT);
        assert_eq!(look.border, LIGHT_BG_BORDER);
    }

    #[test]
    fn the_chosen_border_color_wins_over_the_automatic_one() {
        let look = selected_look(Color32::WHITE, Some([0x3b, 0x82, 0xf6]));
        assert_eq!(look.border, Color32::from_rgb(0x3b, 0x82, 0xf6));
        assert_eq!(look.text, DARK_TEXT);
    }

    #[test]
    fn tab_names_are_trimmed_limited_and_not_empty() {
        assert_eq!(clean_name("  prod  ").as_deref(), Some("prod"));
        assert_eq!(clean_name("   "), None);
        assert_eq!(
            clean_name(&"a".repeat(100)).unwrap().chars().count(),
            MAX_TAB_NAME
        );
    }
}
