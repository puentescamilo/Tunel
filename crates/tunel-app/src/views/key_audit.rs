//! Avisos del llavero: claves débiles, y claves de `~/.ssh` sin frase de paso.

use crate::ui::{self, icons};
use egui::RichText;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use tunel_core::{KeyId, SshKey, VaultData};
use tunel_ssh::key_audit::{self, UnprotectedKey, Weakness};

/// Lo ya calculado, para no volver a leer las claves en cada fotograma.
#[derive(Clone, Default)]
struct Audit {
    /// Por clave: la huella de su texto cuando se miró, y lo débil que es.
    weak: HashMap<KeyId, (u64, Option<Weakness>)>,
    /// Las claves sin frase de paso de `~/.ssh`, con la huella de su texto; `None` hasta
    /// que se mira.
    disk: Option<Vec<(UnprotectedKey, u64)>>,
}

fn audit_id() -> egui::Id {
    egui::Id::unique("auditoria-llavero")
}

fn fingerprint(parts: &[Option<&str>]) -> u64 {
    let mut hasher = DefaultHasher::new();
    parts.hash(&mut hasher);
    hasher.finish()
}

/// Huella del texto de una clave privada, para saber si ya está en el llavero.
fn text_fingerprint(text: &str) -> u64 {
    fingerprint(&[Some(text.trim())])
}

/// Lo débil de `key`, calculado solo si cambió desde la última vez.
pub fn weakness(ctx: &egui::Context, key: &SshKey) -> Option<Weakness> {
    let print = fingerprint(&[
        Some(&key.private_key),
        key.passphrase.as_deref(),
        key.public_key.as_deref(),
    ]);
    ctx.data_mut(|d| {
        let audit = d.get_temp_mut_or_default::<Audit>(audit_id());
        match audit.weak.get(&key.id) {
            Some((seen, weakness)) if *seen == print => *weakness,
            _ => {
                let weakness = key_audit::weakness(
                    &key.private_key,
                    key.passphrase.as_deref(),
                    key.public_key.as_deref(),
                );
                audit.weak.insert(key.id, (print, weakness));
                weakness
            }
        }
    })
}

fn ssh_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|d| d.home_dir().join(".ssh"))
}

fn scan(dir: &Path) -> Vec<(UnprotectedKey, u64)> {
    key_audit::unprotected_keys(dir)
        .into_iter()
        .filter_map(|key| {
            let text = std::fs::read_to_string(&key.path).ok()?;
            Some((key, text_fingerprint(&text)))
        })
        .collect()
}

/// Las claves de `~/.ssh` sin frase de paso, mirando el disco la primera vez.
fn disk_keys(ctx: &egui::Context) -> Vec<(UnprotectedKey, u64)> {
    let cached = ctx.data(|d| d.get_temp::<Audit>(audit_id()).and_then(|a| a.disk));
    cached.unwrap_or_else(|| {
        let found = ssh_dir().map(|dir| scan(&dir)).unwrap_or_default();
        ctx.data_mut(|d| {
            d.get_temp_mut_or_default::<Audit>(audit_id()).disk = Some(found.clone());
        });
        found
    })
}

/// Olvida lo que se vio en `~/.ssh`, para volver a mirarlo.
fn rescan(ctx: &egui::Context) {
    ctx.data_mut(|d| d.get_temp_mut_or_default::<Audit>(audit_id()).disk = None);
}

/// La clave de `path` lista para el llavero, con su clave pública si se puede leer.
pub fn import(path: &Path) -> Result<SshKey, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("No se pudo leer {}: {e}", path.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(SshKey {
        public_key: tunel_ssh::keygen::public_key(&text, None),
        ..SshKey::new(name, text)
    })
}

/// La sección «En este equipo»: las claves de `~/.ssh` que cualquiera que lea el archivo
/// puede usar. Devuelve la clave que se pidió importar.
pub fn disk_section(ui: &mut egui::Ui, data: &VaultData) -> Option<PathBuf> {
    let p = ui::pal(ui);
    let keys = disk_keys(ui.ctx());
    let in_vault: Vec<u64> = data
        .keys
        .iter()
        .map(|k| text_fingerprint(&k.private_key))
        .collect();
    let mut import = None;
    ui.horizontal(|ui| {
        ui::section_label(ui, "En este equipo");
        if ui::icon_button(ui, icons::REFRESH, "Volver a comprobar ~/.ssh").clicked() {
            rescan(ui.ctx());
        }
    });
    if keys.is_empty() {
        ui.label(
            RichText::new("No hay claves sin frase de paso en ~/.ssh.")
                .size(12.0)
                .color(p.muted),
        );
        return None;
    }
    ui.label(
        RichText::new(format!(
            "{}  Estas claves de ~/.ssh no tienen frase de paso: cualquiera que lea el archivo \
             puede usarlas. Impórtalas al llavero, que va cifrado, y bórralas del disco, o \
             ponles frase de paso con «ssh-keygen -p -f archivo».",
            icons::WARNING
        ))
        .size(12.0)
        .color(p.warning),
    );
    ui.add_space(4.0);
    for (key, print) in &keys {
        let name = key
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let imported = in_vault.contains(print);
        let mut detail = format!("~/.ssh/{name}");
        if let Some(weakness) = key.weakness {
            detail.push_str(&format!(" · {}", weakness.describe()));
        }
        if imported {
            detail.push_str(" · ya está en el llavero");
        }
        ui::list_row(ui, &key.path, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::WARNING)
                        .font(ui::icon_font(16.0))
                        .color(p.warning),
                );
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new(&name).strong());
                    ui.label(RichText::new(&detail).size(12.0).color(p.muted));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !imported && ui::secondary_button(ui, "Importar").clicked() {
                        import = Some(key.path.clone());
                    }
                });
            });
        });
        ui.add_space(2.0);
    }
    import
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_weakness_is_recomputed_only_when_the_key_changes() {
        let ctx = egui::Context::default();
        let dsa = "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----";
        let mut key = SshKey::new("vieja", dsa);
        assert_eq!(weakness(&ctx, &key), Some(Weakness::Dsa));
        assert_eq!(weakness(&ctx, &key), Some(Weakness::Dsa));
        key.private_key = "otra cosa".into();
        assert_eq!(weakness(&ctx, &key), None);
    }

    #[test]
    fn an_imported_disk_key_is_recognised_in_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let key = tunel_ssh::keygen::generate(Default::default(), "ana", None).unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, format!("{}\n", key.private_key)).unwrap();
        let found = scan(dir.path());
        assert_eq!(found.len(), 1);
        let imported = import(&path).unwrap();
        assert_eq!(imported.label, "id_ed25519");
        assert_eq!(imported.public_key, Some(key.public_key));
        assert_eq!(text_fingerprint(&imported.private_key), found[0].1);
    }
}
