//! Historial de comandos para el autocompletado de la terminal. Se guarda cifrado junto a la
//! bóveda, solo en este equipo: no se sincroniza.

use crate::model::{HostId, Snippet};
use serde::{Deserialize, Serialize};

/// Comandos que se recuerdan, entre todos los hosts.
pub const MAX_ENTRIES: usize = 1000;
/// Un comando más largo no se recuerda: suele ser un texto pegado, no algo que se repite.
pub const MAX_COMMAND_LEN: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// `None`: la terminal de este equipo.
    pub host: Option<HostId>,
    pub command: String,
}

/// Del más reciente al más antiguo.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandHistory {
    entries: Vec<Entry>,
}

impl CommandHistory {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// El historial con `command` ejecutado en `host` como el más reciente. Como en bash con
    /// `ignorespace`, lo que empieza por un espacio no se recuerda: así se puede escribir un
    /// comando con una contraseña sin que se guarde.
    pub fn record(&self, host: Option<HostId>, command: &str) -> Self {
        let command = command.trim_end();
        if command.trim().is_empty()
            || command.starts_with(char::is_whitespace)
            || command.chars().count() > MAX_COMMAND_LEN
            || command.chars().any(char::is_control)
        {
            return self.clone();
        }
        let entry = Entry {
            host,
            command: command.to_string(),
        };
        let entries = std::iter::once(entry.clone())
            .chain(self.entries.iter().filter(|e| **e != entry).cloned())
            .take(MAX_ENTRIES)
            .collect();
        Self { entries }
    }

    /// Lo que falta para completar `typed`. Primero lo ejecutado en `host`, luego los
    /// snippets de una línea y sin variables, y por último lo ejecutado en otros hosts.
    pub fn suggest(
        &self,
        host: Option<HostId>,
        typed: &str,
        snippets: &[Snippet],
    ) -> Option<String> {
        if typed.trim().is_empty() || typed.starts_with(char::is_whitespace) {
            return None;
        }
        let here = self
            .entries
            .iter()
            .filter(|e| e.host == host)
            .map(|e| e.command.as_str());
        let from_snippets = snippets
            .iter()
            .map(|s| s.script.trim())
            .filter(|s| !s.contains("{{"));
        let elsewhere = self
            .entries
            .iter()
            .filter(|e| e.host != host)
            .map(|e| e.command.as_str());
        // Sin caracteres de control: un salto de línea o un Escape en un snippet (o en un
        // historial manipulado) ejecutaría algo al aceptar la sugerencia.
        here.chain(from_snippets)
            .chain(elsewhere)
            .filter(|c| !c.chars().any(char::is_control))
            .find(|c| c.len() > typed.len() && c.starts_with(typed))
            .map(|c| c[typed.len()..].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history(commands: &[(Option<HostId>, &str)]) -> CommandHistory {
        commands
            .iter()
            .fold(CommandHistory::default(), |h, (host, c)| h.record(*host, c))
    }

    #[test]
    fn suggests_the_most_recent_command_of_the_same_host_first() {
        let (web, db) = (HostId::new(), HostId::new());
        let h = history(&[
            (Some(web), "git status"),
            (Some(db), "git stash"),
            (Some(web), "git log --oneline"),
        ]);
        assert_eq!(
            h.suggest(Some(web), "git ", &[]).as_deref(),
            Some("log --oneline")
        );
        assert_eq!(h.suggest(Some(db), "git st", &[]).as_deref(), Some("ash"));
        // De otro host, si en este no hay nada.
        assert_eq!(
            h.suggest(Some(db), "git l", &[]).as_deref(),
            Some("og --oneline")
        );
        assert_eq!(h.suggest(None, "git s", &[]).as_deref(), Some("tash"));
    }

    #[test]
    fn snippets_come_after_this_host_and_before_others() {
        let (web, db) = (HostId::new(), HostId::new());
        let h = history(&[(Some(db), "systemctl status nginx")]);
        let snippets = [
            Snippet::new("reiniciar", "systemctl restart nginx"),
            Snippet::new("con variable", "systemctl restart {{servicio}}"),
            Snippet::new(
                "varias líneas",
                "systemctl daemon-reload\nsystemctl restart app",
            ),
        ];
        assert_eq!(
            h.suggest(Some(web), "systemctl ", &snippets).as_deref(),
            Some("restart nginx")
        );
        let h = h.record(Some(web), "systemctl reload nginx");
        assert_eq!(
            h.suggest(Some(web), "systemctl ", &snippets).as_deref(),
            Some("reload nginx")
        );
        assert_eq!(h.suggest(Some(web), "systemctl d", &snippets), None);
    }

    #[test]
    fn nothing_with_control_characters_is_suggested_or_recorded() {
        let snippets = [
            Snippet::new("retorno", "ls\rrm -rf ~/x"),
            Snippet::new("escape", "ls \x1b[31m"),
            Snippet::new("tabulador", "ls\t-la"),
        ];
        let h = CommandHistory::default();
        assert_eq!(h.suggest(None, "ls", &snippets), None);
        assert!(h.record(None, "ls\x03").is_empty());
    }

    #[test]
    fn nothing_to_suggest_for_an_empty_or_complete_line() {
        let h = history(&[(None, "ls -la")]);
        assert_eq!(h.suggest(None, "", &[]), None);
        assert_eq!(h.suggest(None, "   ", &[]), None);
        assert_eq!(h.suggest(None, "ls -la", &[]), None);
        assert_eq!(h.suggest(None, "LS", &[]), None);
        assert_eq!(h.suggest(None, " ls", &[]), None);
    }

    #[test]
    fn repeating_a_command_moves_it_to_the_front_without_duplicates() {
        let h = history(&[(None, "make"), (None, "make test"), (None, "make  ")]);
        let commands: Vec<_> = h.entries().iter().map(|e| e.command.as_str()).collect();
        assert_eq!(commands, ["make", "make test"]);
    }

    #[test]
    fn lines_starting_with_a_space_or_too_long_are_not_recorded() {
        let h = history(&[
            (None, " mysql -pSecreto"),
            (None, ""),
            (None, &"x".repeat(MAX_COMMAND_LEN + 1)),
        ]);
        assert!(h.is_empty());
    }

    #[test]
    fn only_the_most_recent_commands_are_kept() {
        let h = (0..MAX_ENTRIES + 10).fold(CommandHistory::default(), |h, i| {
            h.record(None, &format!("echo {i}"))
        });
        assert_eq!(h.entries().len(), MAX_ENTRIES);
        assert_eq!(h.entries()[0].command, format!("echo {}", MAX_ENTRIES + 9));
    }

    #[test]
    fn multibyte_text_is_completed_on_a_character_boundary() {
        let h = history(&[(None, "echo «hola» ñandú")]);
        assert_eq!(
            h.suggest(None, "echo «", &[]).as_deref(),
            Some("hola» ñandú")
        );
    }
}
