//! Preguntas que llegan desde las conexiones: claves de host y keyboard-interactive.

use crate::app::TunelApp;
use crate::ui::{self, icons};
use egui::RichText;
use std::collections::VecDeque;
use tunel_core::{HostKeyStatus, KnownHost};
use tunel_ssh::Interaction;
use zeroize::Zeroize;

#[derive(Default)]
pub struct Prompts {
    queue: VecDeque<Interaction>,
    answers: Vec<String>,
}

impl Prompts {
    pub fn push(&mut self, interaction: Interaction) {
        self.queue.push_back(interaction);
    }

    fn clear_answers(&mut self) {
        self.answers.iter_mut().for_each(Zeroize::zeroize);
        self.answers.clear();
    }
}

enum Decision {
    Pending,
    HostKey(bool),
    Keyboard(Option<Vec<String>>),
}

const WIDTH: f32 = 480.0;

fn header(ui: &mut egui::Ui, icon: &str, color: egui::Color32, title: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(36.0), egui::Sense::hover());
        ui::avatar(ui, rect, icon, color);
        ui.label(RichText::new(title).size(18.0).strong());
    });
    ui.add_space(8.0);
}

fn fingerprint_box(ui: &mut egui::Ui, endpoint: &str, algorithm: &str, fingerprint: &str) {
    let p = ui::pal(ui);
    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(endpoint).strong());
                ui::chip(ui, algorithm, p.muted);
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new(fingerprint).monospace().color(p.text));
                if ui::icon_button(ui, icons::COPY, "Copiar huella").clicked() {
                    ui.ctx().copy_text(fingerprint.to_string());
                }
            });
        });
}

pub fn show(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(current) = app.prompts.queue.front() else {
        return;
    };
    let mut decision = Decision::Pending;
    let answers = &mut app.prompts.answers;
    let p = ui::theme::palette(ctx);
    let frame = egui::Frame::popup(&ctx.global_style())
        .inner_margin(egui::Margin::same(24))
        .corner_radius(egui::CornerRadius::same(14));
    egui::Modal::new(egui::Id::unique("pregunta-conexion")).frame(frame).show(ctx, |ui| {
        ui.set_width(WIDTH);
        match current {
            Interaction::HostKey { host, port, algorithm, fingerprint, status, .. } => {
                let changed = matches!(status, HostKeyStatus::Mismatch { .. });
                let (icon, color, title, body) = if changed {
                    (
                        icons::WARNING,
                        p.danger,
                        "La clave del servidor ha cambiado",
                        "Alguien podría estar interceptando la conexión. Acepta solo si sabes que el servidor se reinstaló o cambió de clave.",
                    )
                } else {
                    (
                        icons::FINGERPRINT,
                        p.accent,
                        "Servidor desconocido",
                        "Es la primera vez que te conectas. Comprueba que la huella coincide con la que te dio el administrador.",
                    )
                };
                header(ui, icon, color, title);
                ui.label(RichText::new(body).color(p.muted));
                ui.add_space(12.0);
                fingerprint_box(ui, &format!("{host}:{port}"), algorithm, fingerprint);
                if let HostKeyStatus::Mismatch { expected } = status {
                    ui.add_space(6.0);
                    ui.label(RichText::new(format!("Clave guardada: {expected}")).size(12.0).monospace().color(p.danger));
                }
                ui.add_space(16.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if changed {
                        if ui::primary_button(ui, "Cancelar").clicked() {
                            decision = Decision::HostKey(false);
                        }
                        if ui::danger_button(ui, "Aceptar la clave nueva").clicked() {
                            decision = Decision::HostKey(true);
                        }
                    } else {
                        if ui::primary_button(ui, "Confiar y conectar").clicked() {
                            decision = Decision::HostKey(true);
                        }
                        if ui::secondary_button(ui, "Cancelar").clicked() {
                            decision = Decision::HostKey(false);
                        }
                    }
                });
            }
            Interaction::KeyboardInteractive { host, instructions, prompts, .. } => {
                header(ui, icons::KEYBOARD, p.accent, &format!("Autenticación en {host}"));
                if !instructions.is_empty() {
                    ui.label(RichText::new(instructions).color(p.muted));
                }
                ui.add_space(8.0);
                answers.resize(prompts.len(), String::new());
                let mut submit = false;
                for (i, ((prompt, echo), answer)) in prompts.iter().zip(answers.iter_mut()).enumerate() {
                    ui.label(prompt);
                    let field = ui.add(
                        egui::TextEdit::singleline(answer)
                            .password(!echo)
                            .desired_width(f32::INFINITY)
                            .margin(egui::Margin::symmetric(10, 8)),
                    );
                    if i == 0 && answer.is_empty() && !field.has_focus() {
                        field.request_focus();
                    }
                    submit |= field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                }
                ui.add_space(16.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui::primary_button(ui, "Enviar").clicked() || submit {
                        decision = Decision::Keyboard(Some(answers.clone()));
                    }
                    if ui::secondary_button(ui, "Cancelar").clicked() {
                        decision = Decision::Keyboard(None);
                    }
                });
            }
        }
    });

    if matches!(decision, Decision::Pending) {
        return;
    }
    let Some(interaction) = app.prompts.queue.pop_front() else {
        return;
    };
    app.prompts.clear_answers();
    match (interaction, decision) {
        (
            Interaction::HostKey {
                host,
                port,
                algorithm,
                fingerprint,
                reply,
                ..
            },
            Decision::HostKey(accept),
        ) => {
            if accept && let Some(data) = app.data() {
                let updated = data.trust_host_key(KnownHost {
                    host,
                    port,
                    algorithm,
                    fingerprint,
                });
                app.commit(updated);
            }
            let _ = reply.send(accept);
        }
        (Interaction::KeyboardInteractive { reply, .. }, Decision::Keyboard(answers)) => {
            let _ = reply.send(answers);
        }
        (other, _) => app.prompts.queue.push_front(other),
    }
}
