//! Editar el archivo hosts de este equipo: leerlo, guardar una copia antes de cada cambio,
//! escribirlo como administrador y comprobar que el sistema lo guardó.

mod elevate;

use crate::biometric::Pending;
use chrono::NaiveDateTime;
use std::path::{Path, PathBuf};
use tunel_core::hosts_file::{self, HostsText};

/// Se guardan las últimas copias; las más viejas se borran.
const MAX_BACKUPS: usize = 20;
/// Carpeta de las copias, junto a la bóveda.
const BACKUP_DIR: &str = "copias-hosts";

pub struct HostsFileEditor {
    pub path: PathBuf,
    /// Lo que hay en el archivo, según la última lectura.
    pub saved: Option<HostsText>,
    /// Lo que se está editando, con `\n`.
    pub text: String,
    pub load_error: Option<String>,
    pub saving: Option<Pending<Result<HostsText, String>>>,
    pub backups: Vec<Backup>,
    pub show_backups: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub path: PathBuf,
    pub date: NaiveDateTime,
}

impl Default for HostsFileEditor {
    fn default() -> Self {
        Self::new(target_path())
    }
}

impl HostsFileEditor {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            saved: None,
            text: String::new(),
            load_error: None,
            saving: None,
            backups: Vec::new(),
            show_backups: false,
        }
    }

    /// Vuelve a leer el archivo y descarta lo que no se guardó.
    pub fn load(&mut self, backups: &Path) {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let read = HostsText::from_bytes(&bytes);
                self.text = read.text.clone();
                self.saved = Some(read);
                self.load_error = None;
            }
            Err(e) => {
                self.saved = None;
                self.load_error = Some(format!("No se pudo leer {}: {e}", self.path.display()));
            }
        }
        self.backups = list_backups(backups);
    }

    pub fn is_modified(&self) -> bool {
        self.saved.as_ref().is_some_and(|s| s.text != self.text)
    }

    pub fn discard(&mut self) {
        if let Some(saved) = &self.saved {
            self.text = saved.text.clone();
        }
    }

    /// Lo que se escribiría: el texto editado con los finales de línea del archivo.
    pub fn to_save(&self) -> Option<HostsText> {
        let saved = self.saved.as_ref()?;
        Some(HostsText {
            text: self.text.clone(),
            line_ending: saved.line_ending,
        })
    }
}

/// El archivo del sistema. En depuración, `TUNEL_HOSTS_FILE` apunta a otro, para probar sin
/// tocar el de verdad.
fn target_path() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("TUNEL_HOSTS_FILE") {
        return path.into();
    }
    hosts_file::system_path()
}

/// Dónde se guardan las copias: junto a la bóveda, así cada bóveda de pruebas tiene las suyas.
pub fn backup_dir(vault: &Path) -> PathBuf {
    vault
        .parent()
        .map_or_else(|| PathBuf::from(BACKUP_DIR), |dir| dir.join(BACKUP_DIR))
}

/// Las copias de `dir`, la más reciente primero.
pub fn list_backups(dir: &Path) -> Vec<Backup> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut backups: Vec<Backup> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let date = hosts_file::backup_date(entry.file_name().to_str()?)?;
            Some(Backup {
                path: entry.path(),
                date,
            })
        })
        .collect();
    backups.sort_by_key(|b| std::cmp::Reverse(b.date));
    backups
}

/// Copia `current` en `dir` con la fecha `now` y borra las que sobran.
pub fn make_backup(dir: &Path, current: &[u8], now: NaiveDateTime) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(hosts_file::backup_name(now));
    std::fs::write(&path, current)?;
    for old in list_backups(dir).into_iter().skip(MAX_BACKUPS) {
        let _ = std::fs::remove_file(old.path);
    }
    Ok(path)
}

/// Guarda `text` en `target`: primero la copia de lo que había, luego el archivo (como
/// administrador si es el del sistema) y al final comprueba que quedó lo que se quería.
/// Devuelve lo que quedó en el archivo. Tarda (espera al diálogo de permisos): va en otro
/// hilo.
pub fn save(
    target: &Path,
    text: &HostsText,
    backups: &Path,
    now: NaiveDateTime,
) -> Result<HostsText, String> {
    let current =
        std::fs::read(target).map_err(|e| format!("No se pudo leer {}: {e}", target.display()))?;
    make_backup(backups, &current, now)
        .map_err(|e| format!("No se guardó: falló la copia de seguridad ({e})"))?;
    let bytes = text.to_bytes();
    if target == hosts_file::system_path() {
        elevate::write(target, &bytes).map_err(|e| match e {
            elevate::ElevatedError::Cancelled => {
                "Se canceló: el archivo hosts no cambió".to_string()
            }
            elevate::ElevatedError::Failed(detail) => {
                format!("No se pudo guardar el archivo hosts: {detail}")
            }
        })?;
    } else {
        std::fs::write(target, &bytes)
            .map_err(|e| format!("No se pudo guardar {}: {e}", target.display()))?;
    }
    let written = std::fs::read(target)
        .map_err(|e| format!("No se pudo comprobar {}: {e}", target.display()))?;
    if written != bytes {
        return Err(
            "El sistema no guardó los cambios (¿lo protege un antivirus o una política?)".into(),
        );
    }
    Ok(HostsText::from_bytes(&written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use tunel_core::hosts_file::LineEnding;

    fn at(second: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 11, 19)
            .unwrap()
            .and_hms_opt(9, 0, second)
            .unwrap()
    }

    #[test]
    fn saving_keeps_a_backup_of_what_there_was() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("hosts");
        let backups = dir.path().join(BACKUP_DIR);
        std::fs::write(&target, "127.0.0.1 localhost\r\n").unwrap();
        let text = HostsText {
            text: "127.0.0.1 localhost\n10.0.0.1 web".into(),
            line_ending: LineEnding::CrLf,
        };

        let saved = save(&target, &text, &backups, at(0)).unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"127.0.0.1 localhost\r\n10.0.0.1 web\r\n"
        );
        assert_eq!(saved.text, "127.0.0.1 localhost\n10.0.0.1 web\n");
        let copies = list_backups(&backups);
        assert_eq!(copies.len(), 1);
        assert_eq!(
            std::fs::read(&copies[0].path).unwrap(),
            b"127.0.0.1 localhost\r\n"
        );
    }

    #[test]
    fn without_a_file_to_back_up_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("no-existe");
        let text = HostsText::from_bytes(b"10.0.0.1 web\n");

        let error = save(&target, &text, dir.path(), at(0)).unwrap_err();

        assert!(error.starts_with("No se pudo leer"), "{error}");
        assert!(!target.exists());
    }

    #[test]
    fn only_the_newest_backups_are_kept() {
        let dir = tempfile::tempdir().unwrap();

        for second in 0..(MAX_BACKUPS as u32 + 3) {
            make_backup(dir.path(), b"x", at(second)).unwrap();
        }

        let copies = list_backups(dir.path());
        assert_eq!(copies.len(), MAX_BACKUPS);
        assert_eq!(copies[0].date, at(MAX_BACKUPS as u32 + 2));
        assert_eq!(copies.last().unwrap().date, at(3));
    }

    #[test]
    fn other_files_in_the_folder_are_not_backups() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notas.txt"), "").unwrap();
        make_backup(dir.path(), b"x", at(1)).unwrap();

        assert_eq!(list_backups(dir.path()).len(), 1);
    }

    #[test]
    fn the_editor_knows_when_there_are_changes_and_can_discard_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        let mut editor = HostsFileEditor::new(path);
        editor.load(dir.path());
        assert!(!editor.is_modified());

        editor.text.push_str("10.0.0.1 web\n");
        assert!(editor.is_modified());

        editor.discard();
        assert!(!editor.is_modified());
    }

    #[test]
    fn backups_live_next_to_the_vault() {
        assert_eq!(
            backup_dir(Path::new("/datos/tunel/vault.json")),
            Path::new("/datos/tunel/copias-hosts")
        );
    }
}
