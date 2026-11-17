//! Snippets: comandos guardados que se envían a la terminal. Llegan con la sincronización,
//! como los hosts; las variables (`{{servicio}}`) se resuelven igual que en el escritorio.

use crate::{TunelError, Vault};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use tunel_core::template;
use tunel_core::{Snippet, SnippetId};
use uuid::Uuid;

/// Un snippet tal como lo muestra la lista.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnippetSummary {
    pub id: String,
    pub label: String,
    pub script: String,
    /// Team al que pertenece; `None` si es de la bóveda personal.
    pub team: Option<String>,
    pub tags: Vec<String>,
    /// Nombres de sus variables, sin repetir y en el orden en que aparecen.
    pub variables: Vec<String>,
}

/// Una variable de un snippet con el valor que se usó la última vez (vacío si ninguno).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnippetVariable {
    pub name: String,
    pub value: String,
}

#[uniffi::export]
impl Vault {
    /// Los snippets personales y de los Teams, ordenados por nombre sin distinguir
    /// mayúsculas. Con `query`, solo los que lo contienen en el nombre, el comando o una
    /// etiqueta.
    pub fn snippets(&self, query: String) -> Vec<SnippetSummary> {
        let query = query.trim().to_lowercase();
        let vault = self.lock();
        let mut snippets: Vec<_> = vault
            .data
            .snippets
            .iter()
            .filter(|s| query.is_empty() || matches(s, &query))
            .map(summarize)
            .collect();
        snippets.sort_by_key(|s| s.label.to_lowercase());
        snippets
    }

    /// Las variables del snippet `snippet_id`, con el último valor de cada una mientras la
    /// bóveda sigue abierta.
    pub fn snippet_variables(
        &self,
        snippet_id: String,
    ) -> Result<Vec<SnippetVariable>, TunelError> {
        let script = self.snippet_script(&snippet_id)?;
        let remembered = self.remembered_values();
        Ok(template::variables(&script)
            .into_iter()
            .map(|name| {
                let value = remembered.get(&name).cloned().unwrap_or_default();
                SnippetVariable { name, value }
            })
            .collect())
    }

    /// Lo que hay que enviar a la terminal para ejecutar `snippet_id`: el comando con las
    /// variables sustituidas por `values`, terminado en salto de línea. Recuerda los valores
    /// para la próxima vez.
    pub fn snippet_command(
        &self,
        snippet_id: String,
        values: HashMap<String, String>,
    ) -> Result<String, TunelError> {
        let script = self.snippet_script(&snippet_id)?;
        let values = clean_values(values);
        let command = template::fill(&script, &values);
        self.remember_values(values);
        Ok(with_newline(command))
    }
}

/// `script` con las variables que ya tienen valor sustituidas, tal como se enviaría: para
/// mostrarlo mientras se escriben los valores. No recuerda nada.
#[uniffi::export]
pub fn snippet_preview(script: String, values: HashMap<String, String>) -> String {
    let written = values.into_iter().filter(|(_, value)| !value.is_empty());
    template::fill(&script, &clean_values(written))
}

/// Como en el escritorio, una variable vacía se envía vacía.
fn clean_values(values: impl IntoIterator<Item = (String, String)>) -> BTreeMap<String, String> {
    values
        .into_iter()
        .map(|(name, value)| (name, template::clean_value(&value)))
        .collect()
}

impl Vault {
    fn snippet_script(&self, snippet_id: &str) -> Result<String, TunelError> {
        let id = Uuid::from_str(snippet_id)
            .map(SnippetId)
            .map_err(|_| TunelError::SnippetNotFound)?;
        self.lock()
            .data
            .snippet(id)
            .map(|s| s.script.clone())
            .ok_or(TunelError::SnippetNotFound)
    }
}

fn matches(snippet: &Snippet, query: &str) -> bool {
    snippet.label.to_lowercase().contains(query)
        || snippet.script.to_lowercase().contains(query)
        || snippet
            .tags
            .iter()
            .any(|t| t.to_lowercase().contains(query))
}

fn summarize(snippet: &Snippet) -> SnippetSummary {
    SnippetSummary {
        id: snippet.id.0.to_string(),
        label: snippet.label.clone(),
        script: snippet.script.clone(),
        team: snippet.team.clone(),
        tags: snippet.tags.clone(),
        variables: template::variables(&snippet.script),
    }
}

/// Como en el escritorio: sin el salto final, el comando se quedaría escrito sin ejecutarse.
pub(crate) fn with_newline(script: String) -> String {
    if script.ends_with('\n') {
        script
    } else {
        script + "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::crypto::KdfParams;
    use tunel_core::{UnlockedVault, VaultData};

    fn vault_with(snippets: Vec<Snippet>) -> (tempfile::TempDir, std::sync::Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut vault =
            UnlockedVault::create(&path, "correcta-caballo", KdfParams::FAST_FOR_TESTS).unwrap();
        vault
            .commit(VaultData {
                snippets,
                ..VaultData::default()
            })
            .unwrap();
        (dir, Vault::wrap(vault))
    }

    fn restart() -> Snippet {
        let mut snippet = Snippet::new("Reiniciar servicio", "sudo systemctl restart {{servicio}}");
        snippet.tags = vec!["linux".into()];
        snippet
    }

    #[test]
    fn lists_snippets_by_name_with_their_variables() {
        let (_dir, vault) = vault_with(vec![restart(), Snippet::new("disco", "df -h")]);

        let snippets = vault.snippets(String::new());

        let labels: Vec<_> = snippets.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["disco", "Reiniciar servicio"]);
        assert!(snippets[0].variables.is_empty());
        assert_eq!(snippets[1].variables, ["servicio"]);
    }

    #[test]
    fn the_search_looks_at_name_command_and_tags() {
        let (_dir, vault) = vault_with(vec![restart(), Snippet::new("disco", "df -h")]);

        let found = |q: &str| -> Vec<String> {
            vault
                .snippets(q.into())
                .into_iter()
                .map(|s| s.label)
                .collect()
        };

        assert_eq!(found("DISCO"), ["disco"]);
        assert_eq!(found("systemctl"), ["Reiniciar servicio"]);
        assert_eq!(found("linux"), ["Reiniciar servicio"]);
        assert!(found("nada").is_empty());
    }

    #[test]
    fn a_snippet_without_variables_is_sent_with_a_newline() {
        let snippet = Snippet::new("disco", "df -h");
        let id = snippet.id.0.to_string();
        let (_dir, vault) = vault_with(vec![snippet]);

        let command = vault.snippet_command(id, HashMap::new()).unwrap();

        assert_eq!(command, "df -h\n");
    }

    #[test]
    fn variables_are_filled_without_control_characters_and_remembered() {
        let snippet = restart();
        let id = snippet.id.0.to_string();
        let (_dir, vault) = vault_with(vec![snippet]);
        assert_eq!(
            vault.snippet_variables(id.clone()).unwrap(),
            [SnippetVariable {
                name: "servicio".into(),
                value: String::new()
            }]
        );

        let values = HashMap::from([("servicio".to_string(), "nginx\n; rm -rf /".to_string())]);
        let command = vault.snippet_command(id.clone(), values).unwrap();

        // Un salto de línea en un valor ejecutaría el comando antes de tiempo.
        assert_eq!(command, "sudo systemctl restart nginx; rm -rf /\n");
        assert_eq!(
            vault.snippet_variables(id).unwrap()[0].value,
            "nginx; rm -rf /"
        );
    }

    #[test]
    fn an_empty_value_is_sent_empty_like_on_the_desktop() {
        let snippet = Snippet::new("Logs", "journalctl {{opciones}} -u web");
        let id = snippet.id.0.to_string();
        let (_dir, vault) = vault_with(vec![snippet]);

        let values = HashMap::from([("opciones".to_string(), String::new())]);
        let command = vault.snippet_command(id, values).unwrap();

        assert_eq!(command, "journalctl  -u web\n");
    }

    #[test]
    fn the_preview_leaves_empty_variables_as_they_are() {
        let values = HashMap::from([
            ("usuario".to_string(), "ana".to_string()),
            ("grupo".to_string(), String::new()),
        ]);

        let preview = snippet_preview("usermod -aG {{grupo}} {{ usuario }}".into(), values);

        assert_eq!(preview, "usermod -aG {{grupo}} ana");
    }

    #[test]
    fn an_unknown_snippet_is_an_error() {
        let (_dir, vault) = vault_with(vec![]);

        assert!(matches!(
            vault.snippet_command("no-es-un-id".into(), HashMap::new()),
            Err(TunelError::SnippetNotFound)
        ));
        assert!(matches!(
            vault.snippet_variables(Uuid::new_v4().to_string()),
            Err(TunelError::SnippetNotFound)
        ));
    }
}
