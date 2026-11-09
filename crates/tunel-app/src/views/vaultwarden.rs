//! Tarjeta **Ajustes → Vaultwarden**: conectar la cuenta, ver su estado y desconectarla.

use crate::app::TunelApp;
use crate::ui;
use crate::vaultwarden::{self, VwStatus};
use egui::RichText;
use tunel_vaultwarden::TwoFactorProvider;

pub fn card(app: &mut TunelApp, ui: &mut egui::Ui) {
    let status = app.vaultwarden.status().clone();
    match &status {
        VwStatus::Off | VwStatus::SigningIn if app.vaultwarden.account().is_none() => {
            intro(ui);
            sign_in_form(app, ui, &status, true);
        }
        VwStatus::NeedsCode(providers) => code_form(app, ui, providers),
        _ => connected(app, ui, &status),
    }
}

fn intro(ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    ui.label(
        RichText::new(
            "Opcional. Usa en las identidades las credenciales que tu empresa guarda en \
             Vaultwarden, sin copiarlas a Túnel. Cada persona entra con su propia cuenta y solo \
             ve lo que Vaultwarden le permite. Sin conectar, Túnel funciona igual.",
        )
        .color(p.muted),
    );
    ui.add_space(8.0);
}

fn field(ui: &mut egui::Ui, text: &mut String, hint: &str, password: bool, enabled: bool) {
    ui.add_enabled(
        enabled,
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .password(password)
            .desired_width(f32::INFINITY),
    );
}

/// Servidor, correo y contraseña maestra. Con `new`, también se pueden cambiar el servidor
/// y el correo; al volver a iniciar sesión solo se pide la contraseña.
fn sign_in_form(app: &mut TunelApp, ui: &mut egui::Ui, status: &VwStatus, new: bool) {
    let p = ui::pal(ui);
    let busy = *status == VwStatus::SigningIn;
    let form = &mut app.vaultwarden.form;
    field(
        ui,
        &mut form.server,
        "Servidor, por ejemplo https://vault.tuempresa.com",
        false,
        new && !busy,
    );
    field(
        ui,
        &mut form.email,
        "Correo de tu cuenta de Vaultwarden",
        false,
        new && !busy,
    );
    field(
        ui,
        &mut form.password,
        "Contraseña maestra de Vaultwarden",
        true,
        !busy,
    );
    ui.add_space(6.0);
    if busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Derivando la clave y conectando…").color(p.muted));
        });
        return;
    }
    ui.horizontal(|ui| {
        let label = if new { "Conectar" } else { "Iniciar sesión" };
        if ui::primary_button(ui, label).clicked() {
            vaultwarden::sign_in(app);
        }
    });
    ui.label(
        RichText::new(
            "La contraseña maestra no se guarda: Túnel guarda la sesión cifrada con tu bóveda, \
             solo en este equipo.",
        )
        .size(12.0)
        .color(p.muted),
    );
}

fn code_form(app: &mut TunelApp, ui: &mut egui::Ui, providers: &[TwoFactorProvider]) {
    let p = ui::pal(ui);
    let busy = app.vaultwarden.busy();
    let authenticator = providers.contains(&TwoFactorProvider::Authenticator);
    let email = providers.contains(&TwoFactorProvider::Email);
    if !authenticator && !email {
        ui.label(
            RichText::new(
                "Tu cuenta usa un segundo factor que Túnel aún no admite (llave de seguridad o \
                 Duo). Activa en Vaultwarden la aplicación de autenticación o el correo.",
            )
            .color(p.danger),
        );
        if ui::secondary_button(ui, "Cancelar").clicked() {
            vaultwarden::cancel_sign_in(app);
        }
        return;
    }
    let form = &mut app.vaultwarden.form;
    if !email {
        form.email_code = false;
    } else if !authenticator {
        form.email_code = true;
    }
    let hint = if form.email_code {
        "Código que llegó a tu correo"
    } else {
        "Código de tu aplicación de autenticación"
    };
    ui.label(RichText::new("Vaultwarden pide el segundo factor.").strong());
    ui.add_space(4.0);
    field(ui, &mut form.code, hint, false, !busy);
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled_ui(!busy, |ui| ui::primary_button(ui, "Verificar"))
            .inner
            .clicked()
        {
            vaultwarden::sign_in(app);
        }
        if email
            && ui
                .add_enabled_ui(!busy, |ui| {
                    ui::secondary_button(ui, "Mandar el código al correo")
                })
                .inner
                .clicked()
        {
            vaultwarden::send_email_code(app);
        }
        if authenticator && email {
            let other = if app.vaultwarden.form.email_code {
                "Usar la aplicación"
            } else {
                "Usar el correo"
            };
            if ui.link(other).clicked() {
                app.vaultwarden.form.email_code = !app.vaultwarden.form.email_code;
            }
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Cancelar"))
            .clicked()
        {
            vaultwarden::cancel_sign_in(app);
        }
    });
}

fn connected(app: &mut TunelApp, ui: &mut egui::Ui, status: &VwStatus) {
    let p = ui::pal(ui);
    let (server, email) = app
        .vaultwarden
        .account()
        .map(|(s, e)| (s.to_string(), e.to_string()))
        .unwrap_or_default();
    ui.label(RichText::new(format!("{email} · {server}")).strong());
    if server.starts_with("http://") {
        ui.label(
            RichText::new("Conexión sin cifrar (HTTP): úsala solo en tu red local.")
                .size(12.0)
                .color(p.warning),
        );
    }
    ui.add_space(6.0);
    match status {
        VwStatus::Syncing | VwStatus::SigningIn => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Sincronizando con Vaultwarden…").color(p.muted));
            });
        }
        VwStatus::Ready { last } => {
            let items = app.vaultwarden.vault().map_or(0, |v| v.items.len());
            ui.label(
                RichText::new(format!(
                    "Sincronizado {} · {items} credenciales disponibles",
                    super::settings::ago(*last)
                ))
                .color(p.success),
            );
        }
        VwStatus::Failed { message } => {
            ui.label(
                RichText::new(format!(
                    "{message}. Se usa la copia local y se reintentará automáticamente."
                ))
                .color(p.danger),
            );
        }
        VwStatus::SignedOut => {
            ui.label(
                RichText::new(
                    "Sesión cerrada: vuelve a escribir la contraseña. Mientras tanto se usa la \
                     copia local de las credenciales (hasta 7 días).",
                )
                .color(p.warning),
            );
            ui.add_space(6.0);
            sign_in_form(app, ui, status, false);
        }
        VwStatus::Off | VwStatus::NeedsCode(_) => {}
    }
    ui.add_space(8.0);
    let busy = app.vaultwarden.busy();
    ui.horizontal(|ui| {
        if matches!(status, VwStatus::Ready { .. } | VwStatus::Failed { .. })
            && ui
                .add_enabled_ui(!busy, |ui| ui::primary_button(ui, "Sincronizar ahora"))
                .inner
                .clicked()
        {
            vaultwarden::sync_now(app);
        }
        // El mismo acceso que en Ajustes → Importar, donde cuesta encontrarlo.
        if matches!(status, VwStatus::Ready { .. })
            && ui
                .add_enabled_ui(!busy, |ui| ui::secondary_button(ui, "Importar hosts…"))
                .inner
                .on_hover_text(
                    "Crea hosts con los elementos que tienen URI ssh://, telnet:// o mosh://",
                )
                .clicked()
        {
            vaultwarden::import::open(app);
        }
        if ui::secondary_button(ui, "Desconectar")
            .on_hover_text(
                "Borra la sesión y la copia de las credenciales de este equipo. Las identidades \
                 vinculadas piden la contraseña al conectar hasta que vuelvas a conectar.",
            )
            .clicked()
        {
            vaultwarden::disconnect(app);
        }
    });
}
