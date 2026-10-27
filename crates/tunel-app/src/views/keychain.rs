//! Llavero: identidades (usuario + credencial) y claves SSH.

use crate::app::TunelApp;
use crate::editor::Editor;
use crate::ui::{self, icons};
use egui::{Rect, RichText, Sense, Vec2};
use tunel_core::{Identity, SshKey, VaultData};

/// Tipo de clave a partir de su cabecera PEM/OpenSSH.
pub fn key_kind(private_key: &str) -> &'static str {
    let header = private_key.lines().next().unwrap_or_default();
    match header {
        h if h.contains("OPENSSH") => "OpenSSH",
        h if h.contains("RSA") => "RSA (PEM)",
        h if h.contains("EC") => "ECDSA (PEM)",
        h if h.contains("PRIVATE KEY") => "PKCS#8",
        _ => "Formato desconocido",
    }
}

fn identity_details(data: &VaultData, identity: &Identity) -> String {
    let mut parts = vec![identity.username.clone()];
    if identity.password.is_some() {
        parts.push("contraseña".into());
    }
    if let Some(key) = identity.key.and_then(|k| data.key(k)) {
        parts.push(format!("clave «{}»", key.label));
    }
    if identity.use_agent {
        parts.push("agente SSH".into());
    }
    let hosts = data
        .hosts
        .iter()
        .filter(|h| h.identity == Some(identity.id))
        .count();
    if hosts > 0 {
        parts.push(format!("{hosts} host{}", if hosts == 1 { "" } else { "s" }));
    }
    parts.join(" · ")
}

/// Fila con avatar, título, detalle y botones de editar/eliminar. Devuelve (editar, eliminar).
fn item_row(
    ui: &mut egui::Ui,
    key: impl std::hash::Hash + std::fmt::Debug,
    icon: &str,
    title: &str,
    detail: &str,
) -> (bool, bool) {
    let p = ui::pal(ui);
    let (_, actions) = ui::list_row(ui, key, |ui| {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
            ui::avatar(
                ui,
                Rect::from_min_size(rect.min, rect.size()),
                icon,
                ui::theme::avatar_color(title),
            );
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new(title).strong());
                ui.label(RichText::new(detail).size(12.0).color(p.muted));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let delete = ui::icon_button(ui, icons::TRASH, "Eliminar").clicked();
                let edit = ui::icon_button(ui, icons::PENCIL, "Editar").clicked();
                (edit, delete)
            })
            .inner
        })
        .inner
    });
    ui.add_space(2.0);
    actions
}

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let mut updated = None;
    ui::page_header(
        ui,
        "Llavero",
        "Usuarios, contraseñas y claves que usan tus hosts",
        |ui| {
            if ui::primary_button(ui, &ui::with_icon(icons::PLUS, "Clave")).clicked() {
                app.editor = Some(Editor::Key(SshKey::new("Nueva clave", "")));
            }
            if ui::secondary_button(ui, &ui::with_icon(icons::IDENTITY, "Identidad")).clicked() {
                app.editor = Some(Editor::Identity(Identity::new("Nueva identidad", "")));
            }
        },
    );
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui::section_label(ui, "Identidades");
        if data.identities.is_empty() {
            ui::empty_state(ui, icons::IDENTITY, "Sin identidades", "Una identidad agrupa usuario y credenciales para reutilizarlos en varios hosts.");
        }
        for identity in &data.identities {
            let (edit, delete) = item_row(ui, identity.id, icons::USER, &identity.label, &identity_details(&data, identity));
            if edit {
                app.editor = Some(Editor::Identity(identity.clone()));
            }
            if delete {
                updated = Some(data.without_identity(identity.id));
            }
        }
        ui.add_space(12.0);
        ui::section_label(ui, "Claves SSH");
        if data.keys.is_empty() {
            ui::empty_state(ui, icons::KEY, "Sin claves", "Importa una clave privada con «Clave». Se guarda cifrada en la bóveda.");
        }
        for key in &data.keys {
            let mut detail = key_kind(&key.private_key).to_string();
            if key.passphrase.is_some() {
                detail.push_str(" · con frase de paso");
            }
            if key.certificate.is_some() {
                detail.push_str(" · con certificado");
            }
            let icon = if key.certificate.is_some() { icons::CERTIFICATE } else { icons::KEY };
            let (edit, delete) = item_row(ui, key.id, icon, &key.label, &detail);
            if edit {
                app.editor = Some(Editor::Key(key.clone()));
            }
            if delete {
                updated = Some(data.without_key(key.id));
            }
        }
    });
    if let Some(data) = updated {
        app.commit(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_kind_reads_pem_header() {
        assert_eq!(
            key_kind("-----BEGIN OPENSSH PRIVATE KEY-----\nabc"),
            "OpenSSH"
        );
        assert_eq!(key_kind("-----BEGIN RSA PRIVATE KEY-----"), "RSA (PEM)");
        assert_eq!(key_kind("-----BEGIN PRIVATE KEY-----"), "PKCS#8");
        assert_eq!(key_kind(""), "Formato desconocido");
    }

    #[test]
    fn identity_details_lists_credentials_and_usage() {
        let identity = Identity {
            password: Some("x".into()),
            use_agent: true,
            ..Identity::new("ana", "ana")
        };
        let host = tunel_core::Host {
            identity: Some(identity.id),
            ..tunel_core::Host::new("h", "h")
        };
        let data = VaultData::default()
            .with_identity(identity.clone())
            .with_host(host);
        assert_eq!(
            identity_details(&data, &identity),
            "ana · contraseña · agente SSH · 1 host"
        );
    }
}
