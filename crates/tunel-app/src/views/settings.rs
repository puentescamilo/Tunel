//! Ajustes: apariencia, terminal, sincronización, importación y seguridad.

use super::themes;
use crate::app::TunelApp;
use crate::engine::LinkAccount;
use crate::sync::SyncStatus;
use crate::ui::{self, icons};
use egui::{Color32, CornerRadius, FontId, RichText};
use tunel_core::ssh_config;
use tunel_term::palette;
use zeroize::Zeroize;

const MIN_FONT: f32 = 9.0;
const MAX_FONT: f32 = 32.0;

#[derive(Default)]
pub struct PasswordChange {
    new: String,
    confirm: String,
}

fn import_ssh_config(app: &mut TunelApp) {
    let Some(home) = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf()) else {
        app.notify("No se encontró el directorio personal");
        return;
    };
    let path = home.join(".ssh").join("config");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => {
            app.notify(format!("No se pudo leer {}: {e}", path.display()));
            return;
        }
    };
    let Some(data) = app.data().cloned() else {
        return;
    };
    let entries = ssh_config::parse(&text);
    let read_key = |file: &str| std::fs::read_to_string(ssh_config::expand_home(file, &home)).ok();
    let (updated, report) = ssh_config::import_into(&data, &entries, read_key);
    app.commit(updated);
    let mut message = format!("Importados {} hosts y {} claves", report.hosts, report.keys);
    if report.skipped_existing > 0 {
        message.push_str(&format!("; {} ya existían", report.skipped_existing));
    }
    if !report.unreadable_keys.is_empty() {
        message.push_str(&format!(
            "; no se pudieron leer: {}",
            report.unreadable_keys.join(", ")
        ));
    }
    app.notify(message);
}

/// Tarjeta con título para agrupar ajustes relacionados.
fn card(ui: &mut egui::Ui, icon: &str, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui::card_frame(ui, false)
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icon)
                        .font(ui::icon_font(18.0))
                        .color(ui::pal(ui).accent),
                );
                ui.label(RichText::new(title).size(16.0).strong());
            });
            ui.add_space(8.0);
            add_contents(ui);
        });
    ui.add_space(12.0);
}

pub(super) fn setting_row(
    ui: &mut egui::Ui,
    label: &str,
    help: &str,
    control: impl FnOnce(&mut egui::Ui),
) {
    let p = ui::pal(ui);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.label(label);
            if !help.is_empty() {
                ui.label(RichText::new(help).size(12.0).color(p.muted));
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), control);
    });
    ui.add_space(6.0);
}

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let mut settings = data.settings.clone();
    let mut import_theme = false;
    ui::page_header(
        ui,
        "Ajustes",
        "Apariencia, terminal, sincronización, importación y seguridad",
        |_| {},
    );
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.set_max_width(760.0);
        card(ui, icons::REFRESH, "Cuenta y sincronización", |ui| sync_card(app, ui));
        if app.sync.account().is_some() {
            card(ui, icons::USERS, "Teams", |ui| super::teams::card(app, ui));
        }
        card(ui, icons::PALETTE, "Apariencia", |ui| {
            setting_row(ui, "Interfaz", "En automático sigue al fondo del tema de la terminal", |ui| {
                themes::ui_mode_selector(ui, &mut settings.ui_theme);
            });
            setting_row(ui, "Cursor", "Los programas como vim pueden cambiarlo mientras se ejecutan", |ui| {
                themes::cursor_selector(ui, &mut settings.cursor_style);
            });
            setting_row(ui, "Tamaño de letra de la terminal", "", |ui| {
                ui.add(egui::Slider::new(&mut settings.font_size, MIN_FONT..=MAX_FONT).suffix(" pt"));
            });
            super::fonts::rows(ui, &mut settings, &app.fonts);
            super::fonts::import_row(app, ui, &mut settings);
            let theme = palette::find(&settings.theme, &settings.custom_themes);
            let [br, bg, bb] = theme.background;
            let [fr, fg, fb] = theme.foreground;
            egui::Frame::new()
                .fill(Color32::from_rgb(br, bg, bb))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let text = RichText::new("deploy@web-01:~$ tail -f /var/log/app.log").font(FontId::monospace(settings.font_size));
                    ui.label(text.color(Color32::from_rgb(fr, fg, fb)));
                });
        });
        // Solo en depuración: `TUNEL_DEV_SCROLL=temas` baja hasta los temas al abrir, para capturas.
        #[cfg(debug_assertions)]
        if std::env::var("TUNEL_DEV_SCROLL").as_deref() == Ok("temas") {
            // Espera unos fotogramas: si al arrancar cambian las fuentes, la vista se recoloca.
            let id = egui::Id::unique("dev-scroll-temas");
            let frame = ui.ctx().data(|d| d.get_temp::<u32>(id).unwrap_or(0));
            if frame <= 30 {
                ui.ctx().data_mut(|d| d.insert_temp(id, frame + 1));
                ui.ctx().request_repaint();
                if frame == 30 {
                    ui.scroll_to_cursor(Some(egui::Align::Max));
                }
            }
        }
        card(ui, icons::TERMINAL, "Tema de la terminal", |ui| {
            ui.horizontal(|ui| {
                let help = "Cada host o grupo puede tener su propio tema, que se elige en su ficha.";
                ui.label(RichText::new(help).color(ui::pal(ui).muted));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    import_theme = ui::secondary_button(ui, &ui::with_icon(icons::DOWNLOAD, "Importar…"))
                        .on_hover_text("Archivos .itermcolors de iTerm2 o .json de Windows Terminal")
                        .clicked();
                });
            });
            ui.add_space(8.0);
            themes::gallery(ui, &mut settings);
        });
        card(ui, icons::TERMINAL, "Terminal", |ui| {
            setting_row(ui, "Líneas de historial", "Cuántas líneas se guardan para desplazarse hacia atrás", |ui| {
                ui.add(egui::DragValue::new(&mut settings.scrollback_lines).range(0..=200_000).speed(100));
            });
            setting_row(ui, "Keepalive SSH", "Segundos entre paquetes para mantener viva la conexión (0 = desactivado)", |ui| {
                ui.add(egui::DragValue::new(&mut settings.keepalive_seconds).range(0..=600).suffix(" s"));
            });
            setting_row(ui, "Copiar al seleccionar", "Copia el texto al portapapeles en cuanto lo seleccionas", |ui| {
                ui::toggle(ui, &mut settings.copy_on_select);
            });
        });
        if settings != data.settings {
            let theme_changed = settings.theme != data.settings.theme || settings.ui_theme != data.settings.ui_theme;
            app.commit(data.with_settings(settings.clone()));
            if theme_changed {
                app.apply_theme(ui.ctx());
            }
        }
        if import_theme {
            themes::import_dialog(app, ui.ctx());
        }
        card(ui, icons::DOWNLOAD, "Importar", |ui| {
            setting_row(ui, "Hosts de OpenSSH", "Lee ~/.ssh/config: hosts, usuarios, puertos, ProxyJump y claves", |ui| {
                if ui::secondary_button(ui, "Importar ~/.ssh/config").clicked() {
                    import_ssh_config(app);
                }
            });
        });
        card(ui, icons::FILE_TEXT, "Registro de sesiones", |ui| log_controls(app, ui));
        card(ui, icons::LOCK, "Seguridad", |ui| {
            let p = ui::pal(ui);
            ui.label(RichText::new("La contraseña maestra cifra toda la bóveda. Si la olvidas no se puede recuperar.").color(p.muted));
            ui.add_space(6.0);
            let change = &mut app.password_change;
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut change.new).password(true).hint_text("Nueva contraseña maestra").desired_width(220.0));
                ui.add(egui::TextEdit::singleline(&mut change.confirm).password(true).hint_text("Repítela").desired_width(220.0));
            });
            ui.add_space(4.0);
            if ui::secondary_button(ui, "Cambiar contraseña maestra").clicked() {
                let result = if change.new != change.confirm {
                    Err("Las contraseñas no coinciden".to_string())
                } else {
                    app.vault.as_mut().map(|v| v.change_password(&change.new).map_err(|e| e.to_string())).unwrap_or(Ok(()))
                };
                change.new.zeroize();
                change.confirm.zeroize();
                app.notify(match result {
                    Ok(()) => "Contraseña maestra cambiada".to_string(),
                    Err(e) => e,
                });
            }
            if let Some(vault) = &app.vault {
                ui.add_space(6.0);
                ui.label(RichText::new(format!("Bóveda: {}", vault.path().display())).size(12.0).color(p.muted));
            }
        });
    });
}

/// "hace 3 min", para la última sincronización.
fn ago(when: std::time::SystemTime) -> String {
    let secs = when.elapsed().map_or(0, |d| d.as_secs());
    match secs {
        0..60 => "hace un momento".into(),
        60..3600 => format!("hace {} min", secs / 60),
        _ => format!("hace {} h", secs / 3600),
    }
}

fn sync_card(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let status = app.sync.status().clone();
    let Some((server, email)) = app.sync.account() else {
        return account_form(app, ui, &status);
    };
    let (server, email) = (server.to_string(), email.to_string());
    ui.horizontal(|ui| {
        let shown = ui::masked(&server, app.sync.form.show_server);
        ui.label(RichText::new(format!("{email} · {shown}")).strong());
        ui::reveal_button(ui, &mut app.sync.form.show_server);
    });
    if server.starts_with("http://") {
        ui.label(
            RichText::new("Conexión sin cifrar (HTTP): úsala solo en tu red local.")
                .size(12.0)
                .color(p.warning),
        );
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| match &status {
        SyncStatus::Running | SyncStatus::Linking => {
            ui.spinner();
            ui.label(RichText::new("Sincronizando…").color(p.muted));
        }
        SyncStatus::Idle { last: Some(when) } => {
            ui.label(RichText::new(format!("Sincronizado {}", ago(*when))).color(p.success));
        }
        SyncStatus::Idle { last: None } | SyncStatus::Off => {
            ui.label(RichText::new("Pendiente de sincronizar").color(p.muted));
        }
        SyncStatus::Failed { message, retrying } => {
            let suffix = if *retrying {
                " Se reintentará automáticamente."
            } else {
                ""
            };
            ui.label(RichText::new(format!("{message}{suffix}")).color(p.danger));
        }
    });
    let pending = app.sync.pending();
    if pending > 0 {
        ui.label(
            RichText::new(format!("{pending} cambios esperando a subir"))
                .size(12.0)
                .color(p.muted),
        );
    }
    ui.add_space(8.0);
    let busy = app.sync.busy();
    ui.horizontal(|ui| {
        if ui
            .add_enabled_ui(!busy, |ui| ui::primary_button(ui, "Sincronizar ahora"))
            .inner
            .clicked()
        {
            crate::sync::sync_now(app);
        }
        if ui
            .add_enabled_ui(!busy, |ui| {
                ui::secondary_button(ui, "Desvincular este equipo")
            })
            .inner
            .on_hover_text("Deja de sincronizar este equipo; la bóveda local no se borra")
            .clicked()
        {
            crate::sync::unlink(app);
        }
    });
}

fn account_form(app: &mut TunelApp, ui: &mut egui::Ui, status: &SyncStatus) {
    let p = ui::pal(ui);
    ui.label(
        RichText::new(
            "Sincroniza la bóveda entre tus equipos a través de tu propio servidor \
             (tunel-server). Todo viaja cifrado: el servidor no puede leer nada. \
             La contraseña de la cuenta no se puede recuperar.",
        )
        .color(p.muted),
    );
    ui.add_space(8.0);
    if *status == SyncStatus::Linking {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Preparando las claves y conectando…").color(p.muted));
        });
        return;
    }
    let form = &mut app.sync.form;
    let field = |ui: &mut egui::Ui, text: &mut String, hint: &str, password: bool| {
        ui.add(
            egui::TextEdit::singleline(text)
                .hint_text(hint)
                .password(password)
                .desired_width(f32::INFINITY),
        );
    };
    ui.horizontal(|ui| {
        let eye = 28.0 + ui.spacing().item_spacing.x;
        ui.add(
            egui::TextEdit::singleline(&mut form.server)
                .hint_text("Servidor, por ejemplo https://tunel.tudominio.com")
                .password(!form.show_server)
                .desired_width(ui.available_width() - eye),
        );
        ui::reveal_button(ui, &mut form.show_server);
    });
    field(ui, &mut form.email, "Correo de la cuenta", false);
    ui.horizontal(|ui| {
        let width = (ui.available_width() - ui.spacing().item_spacing.x) / 2.0;
        ui.add(
            egui::TextEdit::singleline(&mut form.password)
                .password(true)
                .hint_text("Contraseña de la cuenta")
                .desired_width(width),
        );
        ui.add(
            egui::TextEdit::singleline(&mut form.confirm)
                .password(true)
                .hint_text("Repítela (solo al crear la cuenta)")
                .desired_width(width),
        );
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui::primary_button(ui, "Iniciar sesión").clicked() {
            crate::sync::link(app, LinkAccount::SignIn);
        }
        if ui::secondary_button(ui, "Crear cuenta").clicked() {
            crate::sync::link(app, LinkAccount::Create);
        }
    });
    ui.add_space(4.0);
    ui.label(
        RichText::new("Lo que ya tengas en este equipo se combina con la bóveda de la cuenta.")
            .size(12.0)
            .color(p.muted),
    );
}

fn log_controls(app: &mut TunelApp, ui: &mut egui::Ui) {
    let terminals: Vec<usize> = app
        .tabs
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(t, crate::app::Tab::Terminal(_)))
        .map(|(i, _)| i)
        .collect();
    if terminals.is_empty() {
        ui.label(
            RichText::new("Abre una terminal para poder guardar su salida en un archivo.")
                .color(ui::pal(ui).muted),
        );
        return;
    }
    for i in terminals {
        let Some(crate::app::Tab::Terminal(session)) = app.tabs.get_mut(i) else {
            continue;
        };
        let mut message = None;
        ui.horizontal(|ui| {
            ui.label(&session.title);
            if session.is_logging() {
                if ui::secondary_button(ui, "Detener registro").clicked() {
                    session.stop_log();
                }
            } else if ui::secondary_button(ui, "Registrar en archivo…").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .set_file_name("sesion.log")
                    .save_file()
            {
                message = Some(match session.start_log(&path) {
                    Ok(()) => format!("Registrando en {}", path.display()),
                    Err(e) => format!("No se pudo abrir el registro: {e}"),
                });
            }
        });
        if let Some(message) = message {
            app.notify(message);
        }
    }
}
