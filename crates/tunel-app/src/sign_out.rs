//! Cerrar sesión en este equipo: se borran la bóveda local y todo lo que guarda a su lado,
//! y Túnel vuelve a la bienvenida, donde se puede crear una bóveda nueva o entrar con una
//! cuenta. Se pide la contraseña maestra para que nadie lo haga por descuido o desde un
//! equipo que se dejó abierto.

use crate::app::TunelApp;
use crate::biometric::Pending;
use crate::lock::LockScreen;
use crate::ui;
use egui::{CornerRadius, RichText};
use zeroize::Zeroizing;

/// El diálogo de confirmación abierto.
#[derive(Default)]
pub struct SignOut {
    password: Zeroizing<String>,
    checking: Option<Pending<bool>>,
    error: Option<String>,
}

/// Abre el diálogo de confirmación.
pub fn ask(app: &mut TunelApp) {
    if app.sync.busy() {
        return app.notify("Espera a que termine la sincronización en curso");
    }
    app.sign_out = Some(SignOut::default());
}

/// Lo que se pierde al cerrar sesión, según haya cuenta y cambios sin subir.
fn warning(app: &TunelApp) -> (String, Option<String>) {
    let Some((_, email)) = app.sync.account() else {
        return (
            "Se borran de este equipo la bóveda, las pestañas guardadas, el historial de \
             comandos y la cuenta de Vaultwarden."
                .into(),
            Some(
                "Este equipo no está unido a ninguna cuenta: la bóveda se borrará para siempre \
                 y no se podrá recuperar."
                    .into(),
            ),
        );
    };
    let text = format!(
        "Se borran de este equipo la bóveda, la conexión con la cuenta {email}, las pestañas \
         guardadas, el historial de comandos y la cuenta de Vaultwarden. Tus hosts siguen en \
         la cuenta: podrás entrar de nuevo con ella o crear una bóveda nueva."
    );
    let danger = match app.sync.pending() {
        0 => None,
        1 => Some("Hay 1 cambio sin subir a la cuenta y se perderá.".into()),
        n => Some(format!(
            "Hay {n} cambios sin subir a la cuenta y se perderán."
        )),
    };
    (text, danger)
}

/// Diálogo de confirmación; al aceptar con la contraseña correcta, cierra la sesión.
pub fn dialog(app: &mut TunelApp, ctx: &egui::Context) {
    if app.sign_out.is_none() {
        return;
    }
    if app.vault.is_none() {
        app.sign_out = None;
        return;
    }
    let (text, danger) = warning(app);
    let check = app.vault.as_ref().map(|v| v.password_check());
    let Some(state) = app.sign_out.as_mut() else {
        return;
    };
    if let Some(result) = state.checking.as_ref().and_then(Pending::take) {
        state.checking = None;
        if result == Some(true) {
            app.sign_out = None;
            return sign_out(app);
        }
        state.error = Some("La contraseña maestra no es correcta".into());
    }
    let frame = egui::Frame::popup(&ctx.global_style())
        .inner_margin(egui::Margin::same(20))
        .corner_radius(CornerRadius::same(14));
    let mut cancel = false;
    let mut confirm = false;
    let modal = egui::Modal::new(egui::Id::unique("cerrar-sesion-equipo"))
        .frame(frame)
        .show(ctx, |ui| {
            let p = ui::pal(ui);
            ui.set_width(420.0);
            ui.label(
                RichText::new("Cerrar sesión en este equipo")
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(10.0);
            ui.label(RichText::new(text).color(p.text));
            if let Some(danger) = danger {
                ui.add_space(6.0);
                ui.label(RichText::new(danger).color(p.danger).strong());
            }
            ui.add_space(12.0);
            let checking = state.checking.is_some();
            let field = ui.add_enabled(
                !checking,
                egui::TextEdit::singleline(&mut *state.password)
                    .password(true)
                    .hint_text("Contraseña maestra")
                    .id_salt("contrasena-cerrar-sesion")
                    .desired_width(f32::INFINITY),
            );
            ui::describe(&field, egui::Role::PasswordInput, "Contraseña maestra");
            let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if let Some(error) = &state.error {
                ui.add_space(4.0);
                ui.label(RichText::new(error).color(p.danger));
            }
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if checking {
                    ui.spinner();
                } else {
                    confirm = ui::danger_button(ui, "Cerrar sesión y borrar").clicked() || enter;
                    cancel = ui::secondary_button(ui, "Cancelar").clicked();
                }
            });
        });
    if state.checking.is_none() && (cancel || modal.should_close()) {
        app.sign_out = None;
        return;
    }
    if confirm && !state.password.is_empty() {
        let password = std::mem::take(&mut state.password);
        state.error = None;
        if let Some(check) = check {
            state.checking = Some(crate::biometric::run(ctx, move || check.matches(&password)));
        }
    }
}

/// Cierra las sesiones abiertas, avisa al servidor, borra la bóveda de este equipo con lo
/// que guarda a su lado y vuelve a la bienvenida.
pub fn sign_out(app: &mut TunelApp) {
    let Some(vault) = app.vault.take() else {
        return;
    };
    if let Some(local) = app.sync.local().cloned() {
        app.engine.sign_out(local);
    }
    let path = vault.path().to_path_buf();
    // Lo que guarda el sistema para Touch ID o Windows Hello; el archivo lo borra el núcleo.
    if let Ok(Some(enrollment)) = tunel_core::biometric::enrollment(&path) {
        crate::biometric::forget_system(&enrollment);
    }
    app.lock_vault();
    app.lock = LockScreen::new(path);
    app.join = Default::default();
    match vault.destroy() {
        Ok(()) => app.notify("Sesión cerrada: este equipo ya no guarda ninguna bóveda"),
        Err(e) => app.notify(format!("No se pudo borrar del todo la bóveda: {e}")),
    }
}
