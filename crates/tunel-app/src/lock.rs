//! Pantalla para crear o desbloquear la bóveda con la contraseña maestra.

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
}

impl LockScreen {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            password: String::new(),
            confirm: String::new(),
            error: None,
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
        if creating && self.password != self.confirm {
            self.error = Some("Las contraseñas no coinciden".into());
            return None;
        }
        let result = if creating {
            UnlockedVault::create(self.path.clone(), &self.password, KdfParams::RECOMMENDED)
        } else {
            UnlockedVault::unlock(self.path.clone(), &self.password)
        };
        match result {
            Ok(vault) => {
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

    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<UnlockedVault> {
        let creating = !UnlockedVault::exists(&self.path);
        let p = ui::pal(ui);
        let mut opened = None;
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
                        ui.label(RichText::new(format!("Mínimo {MIN_PASSWORD_LEN} caracteres. Si la olvidas, no se puede recuperar.")).size(12.0).color(p.muted));
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
                    }
                });
                ui.add_space(14.0);
                ui.label(RichText::new(self.path.display().to_string()).size(11.0).color(p.muted));
            });
        });
        opened
    }
}

const CARD_WIDTH: f32 = 340.0;

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
    match (len, classes) {
        (0..MIN_PASSWORD_LEN, _) => 1,
        (_, 0..=1) if len < 16 => 2,
        (16.., _) | (12.., 3..) => 4,
        _ => 3,
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
        assert_eq!(password_strength("una frase de paso muy larga"), 4);
    }
}
