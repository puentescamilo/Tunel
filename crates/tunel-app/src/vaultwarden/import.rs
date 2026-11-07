//! Ventana «Importar de Vaultwarden» (8d): elegir qué elementos con URI `ssh://`, `telnet://`
//! o `mosh://` pasan a ser hosts.

use crate::app::TunelApp;
use crate::ui;
use egui::RichText;
use tunel_core::vaultwarden_import::{SourceItem, import_items, targets};
use tunel_vaultwarden::{Content, Item, Vault};

/// Grupo raíz donde quedan los hosts importados.
const ROOT_GROUP: &str = "Vaultwarden";

pub struct ImportDialog {
    items: Vec<SourceItem>,
    selected: Vec<bool>,
    filter: String,
}

/// Lo que hace falta de un elemento para importarlo. `None` si no es de usuario y contraseña.
pub fn source_item(item: &Item, vault: &Vault) -> Option<SourceItem> {
    let Content::Login { username, uris, .. } = &item.content else {
        return None;
    };
    let mut collections: Vec<&str> = vault
        .collections
        .iter()
        .filter(|c| item.collection_ids.contains(&c.id))
        .map(|c| c.name.as_str())
        .collect();
    collections.sort();
    Some(SourceItem {
        item_id: item.id.clone(),
        organization_id: item.organization_id.clone(),
        name: item.name.clone(),
        username: username.clone().filter(|u| !u.is_empty()),
        uris: uris.clone(),
        notes: item.notes.clone(),
        collection: collections.first().map(|c| c.to_string()),
    })
}

/// Los elementos con al menos una URI de conexión, ordenados por colección y nombre.
pub fn importable(vault: &Vault) -> Vec<SourceItem> {
    let mut items: Vec<SourceItem> = vault
        .items
        .iter()
        .filter_map(|i| source_item(i, vault))
        .filter(|i| !targets(i).is_empty())
        .collect();
    items.sort_by(|a, b| (&a.collection, &a.name).cmp(&(&b.collection, &b.name)));
    items
}

/// Abre la ventana con lo que trajo la última sincronización.
pub fn open(app: &mut TunelApp) {
    let Some(vault) = app.vaultwarden.vault() else {
        return app.notify("Conecta Vaultwarden en Ajustes y espera a que sincronice");
    };
    let items = importable(vault);
    if items.is_empty() {
        return app
            .notify("Ningún elemento de Vaultwarden tiene una URI ssh://, telnet:// o mosh://");
    }
    let selected = vec![true; items.len()];
    app.vaultwarden.import = Some(ImportDialog {
        items,
        selected,
        filter: String::new(),
    });
}

fn hosts(n: usize) -> String {
    if n == 1 {
        "1 host".into()
    } else {
        format!("{n} hosts")
    }
}

fn summary_text(added: usize, existing: usize) -> String {
    let imported = |n| {
        if n == 1 { "importado" } else { "importados" }
    };
    match (added, existing) {
        (0, 0) => "No se importó ningún host".into(),
        (0, n) => format!("Ya estaban todos ({})", hosts(n)),
        (a, 0) => format!("{} {} de Vaultwarden", hosts(a), imported(a)),
        (a, n) => format!(
            "{} {} de Vaultwarden; {} ya {}",
            hosts(a),
            imported(a),
            n,
            if n == 1 { "estaba" } else { "estaban" }
        ),
    }
}

pub fn show(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(dialog) = app.vaultwarden.import.as_mut() else {
        return;
    };
    let mut open = true;
    let mut import = false;
    let mut cancel = false;
    egui::Window::new("Importar de Vaultwarden")
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .show(ctx, |ui| {
            let p = ui::pal(ui);
            ui.label(
                RichText::new(format!(
                    "Cada URI ssh://, telnet:// o mosh:// será un host en el grupo «{ROOT_GROUP}», \
                     con un subgrupo por colección y la credencial vinculada al elemento. Volver a \
                     importar no duplica."
                ))
                .color(p.muted),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut dialog.filter)
                        .hint_text("Buscar…")
                        .desired_width(220.0),
                );
                if ui.button("Todos").clicked() {
                    dialog.selected.iter_mut().for_each(|s| *s = true);
                }
                if ui.button("Ninguno").clicked() {
                    dialog.selected.iter_mut().for_each(|s| *s = false);
                }
            });
            ui.add_space(4.0);
            let needle = dialog.filter.to_lowercase();
            egui::ScrollArea::vertical()
                .max_height(360.0)
                .show(ui, |ui| {
                    for (item, selected) in dialog.items.iter().zip(dialog.selected.iter_mut()) {
                        let place = item.collection.as_deref().unwrap_or("personal");
                        let hosts: Vec<String> = targets(item)
                            .iter()
                            .map(|t| match t.port {
                                Some(port) => format!("{}:{port}", t.address),
                                None => t.address.clone(),
                            })
                            .collect();
                        let text = format!("{} · {place} · {}", item.name, hosts.join(", "));
                        if !needle.is_empty() && !text.to_lowercase().contains(&needle) {
                            continue;
                        }
                        ui.checkbox(selected, text);
                    }
                });
            ui.add_space(8.0);
            let count = dialog.selected.iter().filter(|s| **s).count();
            ui.horizontal(|ui| {
                import = ui
                    .add_enabled(count > 0, egui::Button::new(format!("Importar ({count})")))
                    .clicked();
                cancel = ui.button("Cancelar").clicked();
            });
        });
    if import {
        let chosen: Vec<SourceItem> = dialog
            .items
            .iter()
            .zip(&dialog.selected)
            .filter(|(_, s)| **s)
            .map(|(i, _)| i.clone())
            .collect();
        app.vaultwarden.import = None;
        let Some(data) = app.data().cloned() else {
            return;
        };
        let (imported, summary) = import_items(&data, &chosen, ROOT_GROUP);
        app.commit(imported);
        app.notify(summary_text(summary.added, summary.updated));
    } else if cancel || !open {
        app.vaultwarden.import = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_says_what_happened() {
        assert_eq!(summary_text(3, 0), "3 hosts importados de Vaultwarden");
        assert_eq!(
            summary_text(1, 1),
            "1 host importado de Vaultwarden; 1 ya estaba"
        );
        assert_eq!(
            summary_text(2, 3),
            "2 hosts importados de Vaultwarden; 3 ya estaban"
        );
        assert_eq!(summary_text(0, 2), "Ya estaban todos (2 hosts)");
        assert_eq!(summary_text(0, 0), "No se importó ningún host");
    }
}
