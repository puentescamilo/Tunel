//! Entrar con la cuenta en un equipo sin bóveda, desde la pantalla de bienvenida.
//!
//! Primero se entra en la cuenta (con correo y contraseña o con un proveedor) y, solo si
//! sale bien, se crea la bóveda de este equipo: así un intento fallido no deja una bóveda
//! vacía que haría pensar que ya se entró. La bóveda se cifra con la misma contraseña con
//! la que se entró —la de la cuenta, o la maestra si se entra con un proveedor—, para que
//! en todos los equipos se abra con una sola. Después se sincroniza como siempre.

use crate::app::TunelApp;
use crate::engine::LinkAccount;
use crate::sync::SyncStatus;
use crate::ui::{self, icons};
use egui::{CornerRadius, RichText, Vec2};
use tunel_core::UnlockedVault;
use tunel_core::crypto::KdfParams;
use tunel_core::store::MIN_PASSWORD_LEN;
use tunel_core::sync::SyncLocal;
use tunel_core::vault::VaultData;
use tunel_sync::SyncError;
use zeroize::Zeroizing;

/// Estado de la entrada con la cuenta mientras el equipo no tiene bóveda.
#[derive(Default)]
pub struct JoinState {
    /// La contraseña con la que se creará la bóveda cuando el servidor acepte la entrada.
    pending: Option<Zeroizing<String>>,
    pub error: Option<String>,
    /// La bóveda recién creada, para que la app la abra.
    opened: Option<UnlockedVault>,
}

/// Entra con correo y contraseña.
pub fn sign_in(app: &mut TunelApp) {
    let form = &app.sync.form;
    let server = match tunel_sync::check_server_url(&form.server) {
        Ok(server) => server,
        Err(e) => return fail(app, e.to_string()),
    };
    if !form.email.contains('@') {
        return fail(app, "Escribe el correo de la cuenta".into());
    }
    if form.password.chars().count() < MIN_PASSWORD_LEN {
        return fail(app, "Escribe la contraseña de la cuenta".into());
    }
    let password = Zeroizing::new(std::mem::take(&mut app.sync.form.password));
    let email = app.sync.form.email.trim().to_string();
    start(app);
    app.join.pending = Some(password.clone());
    let round = app.sync.begin(VaultData::default());
    app.engine.link_account(
        round,
        LinkAccount::SignIn,
        server,
        email,
        password,
        VaultData::default(),
    );
}

/// Volvió el navegador del proveedor y se escribió la contraseña maestra.
pub fn finish_provider(app: &mut TunelApp) {
    let master = Zeroizing::new(std::mem::take(&mut app.sync.oauth.master));
    let Some(sign_in) = app.sync.oauth.signed_in.take() else {
        return;
    };
    if sign_in.is_new() {
        let missing = tunel_core::password::problems(&master);
        if !missing.is_empty() {
            app.sync.oauth.signed_in = Some(sign_in);
            return fail(app, tunel_core::password::describe(&missing));
        }
    } else if master.chars().count() < MIN_PASSWORD_LEN {
        app.sync.oauth.signed_in = Some(sign_in);
        return fail(app, "Escribe tu contraseña maestra".into());
    }
    start(app);
    app.join.pending = Some(master.clone());
    let round = app.sync.begin(VaultData::default());
    app.engine
        .oauth_complete(round, sign_in, master, VaultData::default(), None);
}

fn start(app: &mut TunelApp) {
    app.join.error = None;
    app.sync.set_status(SyncStatus::Linking);
}

fn fail(app: &mut TunelApp, message: String) {
    app.sync.set_status(SyncStatus::Off);
    app.join.pending = None;
    app.join.error = Some(message);
}

/// El servidor respondió: si aceptó, se crea la bóveda con la contraseña y la cuenta.
pub fn on_linked(app: &mut TunelApp, round: u64, result: Result<Box<SyncLocal>, SyncError>) {
    if app.sync.finish(round).is_none() {
        return;
    }
    let Some(password) = app.join.pending.take() else {
        return;
    };
    let local = match result {
        Ok(local) => *local,
        Err(e) => return fail(app, crate::sync::describe(&e)),
    };
    let path = app.lock.path().to_path_buf();
    match create(&path, &password, &local) {
        Ok(vault) => {
            app.sync.set_status(SyncStatus::Off);
            app.join.opened = Some(vault);
        }
        Err(e) => {
            // La sesión que se abrió en el servidor ya no sirve.
            app.engine.sign_out(local);
            fail(
                app,
                format!("No se pudo crear la bóveda de este equipo: {e}"),
            );
        }
    }
}

/// Crea la bóveda en `path` con `password` y la deja unida a la cuenta `local`. Si no se
/// puede guardar la cuenta, no deja la bóveda a medias.
fn create(
    path: &std::path::Path,
    password: &str,
    local: &SyncLocal,
) -> Result<UnlockedVault, tunel_core::StoreError> {
    // Si ya hay una bóveda en `path`, falla sin tocarla.
    let vault = UnlockedVault::create(path.to_path_buf(), password, KdfParams::RECOMMENDED)?;
    if let Err(e) = vault.save_sync(local) {
        drop(vault);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    // Si no se puede anotar, mañana se volverá a pedir la contraseña: no pasa nada.
    let _ = vault.record_password_unlock(crate::biometric::today());
    Ok(vault)
}

/// La pantalla de entrar con la cuenta. Devuelve la bóveda cuando ya está creada.
pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) -> Option<UnlockedVault> {
    if let Some(vault) = app.join.opened.take() {
        app.notify("Equipo unido a la cuenta; descargando tu bóveda…");
        return Some(vault);
    }
    let p = ui::pal(ui);
    let frame = egui::Frame::central_panel(ui.style()).fill(p.bg);
    egui::CentralPanel::default().frame(frame).show(ui, |ui| {
        let top = (ui.available_height() * 0.12).max(24.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(top);
                ui::card_frame(ui, false)
                    .inner_margin(egui::Margin::same(32))
                    .corner_radius(CornerRadius::same(16))
                    .show(ui, |ui| {
                        ui.set_width(CARD_WIDTH);
                        header(ui);
                        ui.add_space(20.0);
                        body(app, ui);
                    });
            });
        });
    });
    None
}

const CARD_WIDTH: f32 = 360.0;

fn header(ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    ui.vertical_centered(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(56.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, CornerRadius::same(14), p.accent);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            icons::USER,
            ui::icon_font(28.0),
            p.accent_text,
        );
        ui.add_space(14.0);
        ui.label(RichText::new("Entra con tu cuenta").size(20.0).strong());
        ui.label(
            RichText::new(
                "Tus hosts, claves y snippets se descargan de tu servidor. En este equipo, Túnel \
                 se abrirá con la misma contraseña con la que entres.",
            )
            .color(p.muted),
        );
    });
}

fn body(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    if *app.sync.status() == SyncStatus::Linking {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Preparando las claves y conectando…").color(p.muted));
        });
        return;
    }
    if !provider_flow(app, ui) {
        account_fields(app, ui);
    }
    if let Some(error) = &app.join.error {
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(icons::WARNING)
                    .font(ui::icon_font(14.0))
                    .color(p.danger),
            );
            ui.label(RichText::new(error).color(p.danger));
        });
    }
    ui.add_space(14.0);
    ui.vertical_centered(|ui| {
        if ui.link("Volver y empezar con una bóveda nueva").clicked() {
            app.sync.oauth.cancel();
            app.join.error = None;
            app.lock.joining = false;
        }
    });
}

fn text_field(ui: &mut egui::Ui, text: &mut String, hint: &str, password: bool) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .password(password)
            .desired_width(f32::INFINITY)
            .margin(egui::Margin::symmetric(10, 8)),
    )
}

/// Servidor, proveedores y, si el servidor lo admite, correo y contraseña.
fn account_fields(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let form = &mut app.sync.form;
    let server_field = ui
        .horizontal(|ui| {
            let eye = 28.0 + ui.spacing().item_spacing.x;
            let edit = ui.add(
                egui::TextEdit::singleline(&mut form.server)
                    .hint_text("Servidor, por ejemplo https://tunel.tudominio.com")
                    .password(!form.show_server)
                    .desired_width(ui.available_width() - eye)
                    .margin(egui::Margin::symmetric(10, 8)),
            );
            ui::reveal_button(ui, &mut form.show_server);
            edit
        })
        .inner;
    ui::describe(&server_field, egui::Role::TextInput, "Servidor");
    // Con la dirección escrita, se pregunta al servidor con qué proveedores se puede entrar.
    if !server_field.has_focus() {
        crate::sync::oauth::refresh_providers(app);
    }
    let server = tunel_sync::check_server_url(&app.sync.form.server)
        .map(|s| s.base)
        .unwrap_or_default();
    let providers = app.sync.oauth.providers_for(&server).to_vec();
    let password_login = app.sync.oauth.password_login_for(&server);
    if !providers.is_empty() {
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
            for provider in providers {
                if ui::brand::sign_in_button(ui, &provider.id, &provider.name).clicked() {
                    app.join.error = None;
                    crate::sync::oauth::start(app, provider);
                }
            }
        });
        if password_login {
            ui.add_space(4.0);
            ui.label(
                RichText::new("O con correo y contraseña:")
                    .size(12.0)
                    .color(p.muted),
            );
        }
    }
    if !password_login {
        return;
    }
    ui.add_space(8.0);
    let form = &mut app.sync.form;
    let email = text_field(ui, &mut form.email, "Correo de la cuenta", false);
    ui::describe(&email, egui::Role::TextInput, "Correo de la cuenta");
    ui.add_space(4.0);
    let password = text_field(ui, &mut form.password, "Contraseña de la cuenta", true);
    ui::describe(
        &password,
        egui::Role::PasswordInput,
        "Contraseña de la cuenta",
    );
    let enter = password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    ui.add_space(12.0);
    if wide_button(ui, "Entrar").clicked() || enter {
        sign_in(app);
    }
}

/// Entrada con un proveedor en curso. Devuelve `true` si ocupa el sitio del formulario.
fn provider_flow(app: &mut TunelApp, ui: &mut egui::Ui) -> bool {
    let p = ui::pal(ui);
    if let Some(provider) = app.sync.oauth.waiting.clone() {
        ui.horizontal_wrapped(|ui| {
            ui.spinner();
            ui.label(
                RichText::new(format!(
                    "Termina de iniciar sesión con {provider} en el navegador…"
                ))
                .color(p.muted),
            );
        });
        ui.add_space(8.0);
        if ui::secondary_button(ui, "Cancelar").clicked() {
            app.sync.oauth.cancel();
        }
        return true;
    }
    let Some(sign_in) = &app.sync.oauth.signed_in else {
        return false;
    };
    let new = sign_in.is_new();
    ui.label(
        RichText::new(format!(
            "Has entrado como {} con {}.",
            sign_in.email(),
            sign_in.provider_name()
        ))
        .strong(),
    );
    let help = if new {
        "No hay cuenta con ese correo: se creará. Elige una contraseña maestra; la usarás para \
         abrir Túnel en todos tus equipos."
    } else {
        "Escribe tu contraseña maestra: la misma con la que abres Túnel en tus otros equipos."
    };
    ui.label(RichText::new(help).color(p.muted));
    ui.add_space(8.0);
    let master = &mut app.sync.oauth.master;
    let field = text_field(ui, master, "Contraseña maestra de Túnel", true);
    ui::describe(
        &field,
        egui::Role::PasswordInput,
        "Contraseña maestra de Túnel",
    );
    if new {
        crate::lock::password_rules(ui, master);
    }
    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    ui.add_space(12.0);
    let label = if new { "Crear la cuenta" } else { "Continuar" };
    if wide_button(ui, label).clicked() || enter {
        finish_provider(app);
    }
    ui.add_space(6.0);
    if ui::secondary_button(ui, "Cancelar").clicked() {
        app.sync.oauth.cancel();
    }
    true
}

fn wide_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let p = ui::pal(ui);
    let button = egui::Button::new(RichText::new(label).color(p.accent_text).strong())
        .fill(p.accent)
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(ui.available_width(), 38.0));
    ui.add(button)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::sync::SyncState;

    fn account() -> SyncLocal {
        SyncLocal {
            server: "https://tunel.ejemplo.com".into(),
            email: "ana@ejemplo.com".into(),
            auth: Zeroizing::new("clave".into()),
            vault_key: tunel_core::sync::VaultKey::generate(),
            token: None,
            state: SyncState::new(uuid::Uuid::from_u128(1)),
            keypair: None,
            teams: Vec::new(),
            invitations: Vec::new(),
            contacts: Default::default(),
            oauth: None,
            audit_queue: Vec::new(),
        }
    }

    #[test]
    fn the_vault_is_created_with_the_password_and_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let vault = create(&path, "contraseña-de-la-cuenta", &account()).unwrap();
        drop(vault);

        let vault = UnlockedVault::unlock(path.clone(), "contraseña-de-la-cuenta").unwrap();
        let local = vault.load_sync().unwrap().unwrap();
        assert_eq!(local.email, "ana@ejemplo.com");
    }

    #[test]
    fn an_existing_vault_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        UnlockedVault::create(path.clone(), "la-de-antes-123", KdfParams::FAST_FOR_TESTS).unwrap();

        assert!(create(&path, "contraseña-de-la-cuenta", &account()).is_err());
        assert!(UnlockedVault::unlock(path, "la-de-antes-123").is_ok());
    }
}
