//! Pantalla para crear o desbloquear la bóveda con la contraseña maestra, o con Touch ID o
//! Windows Hello si están activados.

use crate::biometric::{self, Pending, Unlocked};
use crate::ui::{self, icons};
use egui::{CornerRadius, RichText, Vec2};
use std::path::PathBuf;
use tunel_core::crypto::KdfParams;
use tunel_core::store::MIN_PASSWORD_LEN;
use tunel_core::{StoreError, UnlockedVault};
use zeroize::Zeroize;

pub struct LockScreen {
    path: PathBuf,
    password: String,
    confirm: String,
    error: Option<String>,
    biometric: Option<Pending<Unlocked>>,
    /// Al abrir Túnel se pide la huella sin esperar al botón, una sola vez.
    auto_biometric: bool,
}

impl LockScreen {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            password: String::new(),
            confirm: String::new(),
            error: None,
            biometric: None,
            auto_biometric: true,
        }
    }

    /// Solo lo usan los ganchos de desarrollo (`TUNEL_DEV_*`).
    #[cfg(debug_assertions)]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn clear(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }

    fn try_open(&mut self, creating: bool) -> Option<UnlockedVault> {
        if creating {
            let missing = tunel_core::password::problems(&self.password);
            if !missing.is_empty() {
                self.error = Some(tunel_core::password::describe(&missing));
                return None;
            }
            if self.password != self.confirm {
                self.error = Some("Las contraseñas no coinciden".into());
                return None;
            }
        }
        let result = if creating {
            UnlockedVault::create(self.path.clone(), &self.password, KdfParams::RECOMMENDED)
        } else {
            UnlockedVault::unlock(self.path.clone(), &self.password)
        };
        match result {
            Ok(vault) => {
                // Si no se puede anotar, mañana se volverá a pedir la contraseña: no pasa nada.
                let _ = vault.record_password_unlock(biometric::today());
                self.clear();
                self.error = None;
                Some(vault)
            }
            Err(StoreError::Crypto(_)) => {
                self.error = Some("Contraseña incorrecta".into());
                self.password.zeroize();
                None
            }
            Err(e) => {
                self.error = Some(e.to_string());
                None
            }
        }
    }

    fn biometric_enabled(&self) -> bool {
        biometric::available() && tunel_core::biometric::is_enabled(&self.path)
    }

    /// La huella solo sirve si hoy ya se entró con la contraseña maestra, para no olvidarla.
    fn biometric_ready(&self) -> bool {
        self.biometric_enabled()
            && tunel_core::biometric::password_entered_on(&self.path, biometric::today())
    }

    fn start_biometric(&mut self, ctx: &egui::Context) {
        let path = self.path.clone();
        self.error = None;
        self.biometric = Some(biometric::run(ctx, move || biometric::unlock(path)));
    }

    /// La bóveda, si el desbloqueo biométrico en curso terminó bien.
    fn biometric_result(&mut self) -> Option<UnlockedVault> {
        let result = self.biometric.as_ref()?.take()?;
        self.biometric = None;
        let Some(result) = result else {
            self.error = Some(format!("{} falló inesperadamente", biometric::name()));
            return None;
        };
        match result {
            Unlocked::Opened(vault) => {
                self.clear();
                self.error = None;
                Some(*vault)
            }
            Unlocked::Cancelled => None,
            Unlocked::Failed(e) => {
                self.error = Some(e);
                None
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<UnlockedVault> {
        if let Some(vault) = self.biometric_result() {
            return Some(vault);
        }
        let creating = !UnlockedVault::exists(&self.path);
        let biometric_enabled = !creating && self.biometric_enabled();
        let biometric_ready = biometric_enabled && self.biometric_ready();
        if biometric_ready && self.auto_biometric {
            self.auto_biometric = false;
            self.start_biometric(ui.ctx());
        }
        let p = ui::pal(ui);
        let mut opened = None;
        let mut use_biometric = false;
        let frame = egui::Frame::central_panel(ui.style()).fill(p.bg);
        egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            let top = (ui.available_height() * 0.18).max(24.0);
            ui.vertical_centered(|ui| {
                ui.add_space(top);
                ui::card_frame(ui, false).inner_margin(egui::Margin::same(32)).corner_radius(CornerRadius::same(16)).show(ui, |ui| {
                    ui.set_width(CARD_WIDTH);
                    ui.vertical_centered(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(56.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, CornerRadius::same(14), p.accent);
                        let icon = if creating { icons::TERMINAL } else { icons::LOCK };
                        ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, icon, ui::icon_font(28.0), p.accent_text);
                        ui.add_space(14.0);
                        let title = if creating { "Bienvenido a Túnel" } else { "Desbloquea tu bóveda" };
                        ui.label(RichText::new(title).size(20.0).strong());
                        let subtitle = if creating {
                            "Crea una contraseña maestra. Cifra en este equipo todos tus hosts, claves y contraseñas."
                        } else {
                            "Introduce tu contraseña maestra para continuar."
                        };
                        ui.label(RichText::new(subtitle).color(p.muted));
                    });
                    ui.add_space(20.0);
                    let field = password_field(ui, &mut self.password, "Contraseña maestra");
                    if !creating && self.password.is_empty() && !field.has_focus() {
                        field.request_focus();
                    }
                    let mut submit = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if creating {
                        strength_meter(ui, password_strength(&self.password));
                        ui.add_space(4.0);
                        let confirm = password_field(ui, &mut self.confirm, "Repite la contraseña");
                        submit = confirm.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.add_space(2.0);
                        password_rules(ui, &self.password);
                        ui.label(RichText::new("Si la olvidas, no se puede recuperar.").size(12.0).color(p.muted));
                    }
                    if let Some(error) = &self.error {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icons::WARNING).font(ui::icon_font(14.0)).color(p.danger));
                            ui.label(RichText::new(error).color(p.danger));
                        });
                    }
                    ui.add_space(12.0);
                    let label = if creating { "Crear bóveda" } else { "Desbloquear" };
                    let button = egui::Button::new(RichText::new(label).color(p.accent_text).strong())
                        .fill(p.accent)
                        .corner_radius(CornerRadius::same(8))
                        .min_size(Vec2::new(ui.available_width(), 38.0));
                    if ui.add(button).clicked() || submit {
                        // Argon2id tarda ~0,5 s; se acepta la breve pausa en el hilo de la interfaz.
                        opened = self.try_open(creating);
                        if opened.is_some() {
                            // Lo que responda después la huella ya no hace falta.
                            self.biometric = None;
                        }
                    }
                    if biometric_ready {
                        ui.add_space(8.0);
                        let waiting = self.biometric.is_some();
                        let label = if waiting {
                            format!("Esperando a {}…", biometric::name())
                        } else {
                            format!("Usar {}", biometric::name())
                        };
                        let button = egui::Button::new(label)
                            .corner_radius(CornerRadius::same(8))
                            .min_size(Vec2::new(ui.available_width(), 34.0));
                        use_biometric = ui.add_enabled(!waiting, button).clicked();
                    } else if biometric_enabled {
                        ui.add_space(8.0);
                        let note = format!(
                            "La primera vez de cada día se entra con la contraseña maestra. Después podrás usar {}.",
                            biometric::name()
                        );
                        ui.label(RichText::new(note).size(12.0).color(p.muted));
                    }
                });
                ui.add_space(14.0);
                ui.label(RichText::new(self.path.display().to_string()).size(11.0).color(p.muted));
            });
        });
        if use_biometric {
            self.start_biometric(ui.ctx());
        }
        opened
    }
}

const CARD_WIDTH: f32 = 340.0;

/// Las reglas de la contraseña maestra, marcadas según se cumplen.
pub fn password_rules(ui: &mut egui::Ui, password: &str) {
    let p = ui::pal(ui);
    let missing = tunel_core::password::problems(password);
    let rules = [
        "al menos 12 caracteres",
        "una mayúscula",
        "una minúscula",
        "un número",
        "un carácter especial",
    ];
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for rule in rules {
            let ok = !password.is_empty() && !missing.contains(&rule);
            let (icon, color) = if ok {
                (icons::CHECK, p.success)
            } else {
                (icons::CLOSE, p.muted)
            };
            ui.label(
                RichText::new(format!("{icon} {rule}"))
                    .size(12.0)
                    .color(color)
                    .family(egui::FontFamily::Proportional),
            );
        }
    });
}

fn password_field(ui: &mut egui::Ui, text: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(text)
            .password(true)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(egui::Margin::symmetric(10, 8)),
    )
}

/// Fuerza aproximada de 0 (vacía) a 4 (fuerte) según longitud y variedad de caracteres.
pub fn password_strength(password: &str) -> u8 {
    let len = password.chars().count();
    if len == 0 {
        return 0;
    }
    let classes = [
        password.chars().any(|c| c.is_lowercase()),
        password.chars().any(|c| c.is_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&present| present)
    .count();
    let level = match (len, classes) {
        (0..MIN_PASSWORD_LEN, _) => 1,
        (_, 0..=1) if len < 16 => 2,
        (16.., _) | (12.., 3..) => 4,
        _ => 3,
    };
    // «Fuerte» solo si cumple todas las reglas de la contraseña maestra.
    if tunel_core::password::is_strong(password) {
        level
    } else {
        level.min(3)
    }
}

fn strength_meter(ui: &mut egui::Ui, strength: u8) {
    let p = ui::pal(ui);
    let (color, label) = match strength {
        0 => (p.border, ""),
        1 => (p.danger, "Demasiado corta"),
        2 => (p.warning, "Débil"),
        3 => (p.accent, "Buena"),
        _ => (p.success, "Fuerte"),
    };
    ui.horizontal(|ui| {
        let width = (ui.available_width() - 90.0) / 4.0;
        for i in 0..4u8 {
            let (rect, _) =
                ui.allocate_exact_size(Vec2::new(width - 4.0, 4.0), egui::Sense::hover());
            ui.painter().rect_filled(
                rect,
                CornerRadius::same(2),
                if i < strength { color } else { p.border },
            );
        }
        ui.label(RichText::new(label).size(12.0).color(color));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_grows_with_length_and_variety() {
        assert_eq!(password_strength(""), 0);
        assert_eq!(password_strength("corta"), 1);
        assert_eq!(password_strength("solominusculas"), 2);
        assert_eq!(password_strength("Mezcla2024x"), 3);
        assert_eq!(password_strength("Mezcla-2024-Fuerte"), 4);
        // Larga, pero sin mayúsculas ni números: no cumple las reglas de la maestra.
        assert_eq!(password_strength("una frase de paso muy larga"), 3);
        assert_eq!(password_strength("Una frase de paso de 2026"), 4);
    }
}
