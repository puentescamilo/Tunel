//! Autocompletado en la terminal: se sigue lo que el usuario escribe desde el último Enter y,
//! si la pantalla lo muestra tal cual, se sugiere cómo seguir con el historial y los snippets.
//!
//! Lo tecleado solo cuenta si el servidor lo repite en pantalla: así no se guarda una
//! contraseña que se escribe sin eco, y lo que la shell cambie por su cuenta (flechas,
//! Tab, búsqueda con Ctrl+R) anula la línea hasta el siguiente Enter.

use crate::app::TunelApp;
use std::time::{Duration, Instant};
use tunel_core::history::CommandHistory;
use tunel_core::{HostId, Snippet};
use tunel_term::Screen;
use unicode_width::UnicodeWidthChar;

/// Lo que hizo el usuario, en lo que importa para seguir la línea.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit<'a> {
    Text(&'a str),
    Paste(&'a str),
    Backspace,
    Enter,
    /// Ctrl+C o Ctrl+U: la shell empieza una línea vacía.
    Clear,
    /// Cualquier otra tecla: ya no se sabe qué hay en la línea.
    Other,
}

#[derive(Debug, Default)]
pub struct LineTracker {
    line: String,
    /// Se sabe lo que hay en la línea desde el último Enter.
    known: bool,
    /// Bytes del principio de `line` que ya se vieron en pantalla.
    echoed: usize,
    /// Hay un programa a pantalla completa (vim, less, top).
    full_screen: bool,
}

impl LineTracker {
    pub fn new() -> Self {
        Self {
            known: true,
            ..Self::default()
        }
    }

    /// Aplica lo que hizo el usuario. Con Enter devuelve el comando, si se vio en pantalla.
    pub fn edit(&mut self, edit: Edit) -> Option<String> {
        match edit {
            Edit::Text(text) => self.line.push_str(text),
            Edit::Paste(text) if !text.contains(['\n', '\r']) => self.line.push_str(text),
            Edit::Backspace => {
                self.line.pop();
                self.echoed = self.echoed.min(self.line.len());
            }
            Edit::Enter => {
                let command = (self.known && self.echoed > 0).then(|| self.line.clone());
                self.reset();
                return command;
            }
            Edit::Clear => self.reset(),
            Edit::Paste(_) | Edit::Other => self.known = false,
        }
        None
    }

    fn reset(&mut self) {
        self.line.clear();
        self.echoed = 0;
        self.known = !self.full_screen;
    }

    /// En cada fotograma, con lo que muestra la terminal.
    pub fn observe(&mut self, screen: &Screen, full_screen: bool) {
        if full_screen != self.full_screen {
            self.full_screen = full_screen;
            // Al salir del programa vuelve la shell con una línea vacía.
            self.reset();
        }
        if !self.known || self.line.is_empty() {
            return;
        }
        let before = before_cursor(screen);
        if before.ends_with(&self.line) {
            self.echoed = self.line.len();
        } else if !before.ends_with(&self.line[..self.echoed]) {
            // Lo que ya se veía desapareció: la línea cambió por otro lado (otra terminal
            // escribió en esta, o la shell la redibujó).
            self.known = false;
        }
    }

    /// La línea escrita, si se sabe cuál es y ya está entera en pantalla.
    pub fn typed(&self) -> Option<&str> {
        (self.known && !self.full_screen && !self.line.is_empty() && self.echoed == self.line.len())
            .then_some(self.line.as_str())
    }
}

/// El texto antes del cursor, con la fila anterior por si la línea se partió.
fn before_cursor(screen: &Screen) -> String {
    let Some((row, col)) = screen.cursor else {
        return String::new();
    };
    let cells = |r: usize, end: usize| {
        (0..end)
            .map(move |c| screen.cell(r, c))
            .filter(|c| !c.spacer)
            .map(|c| c.ch)
    };
    let previous = row
        .checked_sub(1)
        .into_iter()
        .flat_map(|r| cells(r, screen.cols));
    previous.chain(cells(row, col.min(screen.cols))).collect()
}

/// Si a la derecha del cursor no hay nada: la sugerencia no tapa lo que pinte la shell
/// (como las sugerencias de fish o de zsh-autosuggestions).
pub fn blank_after_cursor(screen: &Screen) -> bool {
    screen
        .cursor
        .is_some_and(|(row, col)| (col..screen.cols).all(|c| screen.cell(row, c).ch == ' '))
}

/// De dónde salen las sugerencias de una terminal.
pub struct Source<'a> {
    pub history: &'a CommandHistory,
    pub snippets: &'a [Snippet],
    pub host: Option<HostId>,
}

/// Lo que falta para completar `typed`, que es lo que había escrito al calcularla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub typed: String,
    pub rest: String,
}

impl Source<'_> {
    /// Solo si cabe entera en la fila sin tapar nada: lo que se acepta con → es lo que se ve.
    pub fn suggest(&self, typed: &str, screen: &Screen) -> Option<Suggestion> {
        let (_, col) = screen.cursor?;
        let rest = self.history.suggest(self.host, typed, self.snippets)?;
        let narrow = rest.chars().all(|c| c.width() == Some(1));
        let fits = rest.chars().count() < screen.cols.saturating_sub(col);
        (narrow && fits && blank_after_cursor(screen)).then(|| Suggestion {
            typed: typed.to_string(),
            rest,
        })
    }
}

/// Al desbloquear: el historial guardado en este equipo.
pub fn load(app: &mut TunelApp) {
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    app.history = vault
        .load_history()
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "no se pudo leer el historial de comandos");
            None
        })
        .unwrap_or_default();
}

/// Cada cuánto, como mucho, se guarda el historial: cifrar y escribir en cada Enter
/// pararía la interfaz en un disco lento.
const SAVE_DELAY: Duration = Duration::from_secs(2);

/// Anota los comandos que se ejecutaron en `host`; se guardan poco después (ver [`tick`]).
pub fn record(app: &mut TunelApp, host: Option<HostId>, commands: &[String]) {
    if commands.is_empty() || !app.data().is_some_and(|d| d.settings.autocomplete) {
        return;
    }
    let history = commands
        .iter()
        .fold(app.history.clone(), |h, c| h.record(host, c));
    if history != app.history {
        app.history = history;
        app.history_changed.get_or_insert_with(Instant::now);
    }
}

/// En cada fotograma: guarda el historial si cambió hace un rato.
pub fn tick(app: &mut TunelApp) {
    if app
        .history_changed
        .is_some_and(|t| t.elapsed() >= SAVE_DELAY)
    {
        save(app);
    }
}

/// Guarda ya lo pendiente: al bloquear la bóveda o al cerrar Túnel.
pub fn save(app: &mut TunelApp) {
    if app.history_changed.take().is_none() {
        return;
    }
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    if let Err(e) = vault.save_history(&app.history) {
        tracing::warn!(error = %e, "no se pudo guardar el historial de comandos");
        // Una vez por sesión: en un disco lleno se repetiría en cada comando.
        if !std::mem::replace(&mut app.history_failed, true) {
            app.notify(format!("No se pudo guardar el historial de comandos: {e}"));
        }
    }
}

/// Borra el historial de este equipo, en memoria y en disco.
pub fn clear(app: &mut TunelApp) -> Result<(), tunel_core::StoreError> {
    app.history = CommandHistory::default();
    app.history_changed = None;
    app.vault.as_ref().map_or(Ok(()), |v| v.delete_history())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_term::Emulator;

    /// Lo que mostraría la terminal tras recibir `output` del servidor.
    fn screen(output: &str) -> Screen {
        let mut emulator = Emulator::new(40, 5, 100);
        emulator.feed(output.as_bytes());
        emulator.screen(tunel_term::palette::default_theme())
    }

    fn typed(tracker: &mut LineTracker, text: &str) {
        for c in text.chars() {
            tracker.edit(Edit::Text(&c.to_string()));
        }
    }

    #[test]
    fn a_command_counts_once_the_server_echoes_it() {
        let mut tracker = LineTracker::new();
        typed(&mut tracker, "git st");
        assert_eq!(tracker.typed(), None);
        tracker.observe(&screen("$ git st"), false);
        assert_eq!(tracker.typed(), Some("git st"));
        tracker.edit(Edit::Backspace);
        assert_eq!(tracker.typed(), Some("git s"));
        // Lo último aún no se ve, pero el principio sí: se recuerda.
        typed(&mut tracker, "tatus");
        assert_eq!(tracker.typed(), None);
        assert_eq!(tracker.edit(Edit::Enter).as_deref(), Some("git status"));
        assert_eq!(tracker.typed(), None);
    }

    #[test]
    fn a_password_typed_without_echo_is_not_recorded() {
        let mut tracker = LineTracker::new();
        typed(&mut tracker, "secreto");
        tracker.observe(&screen("[sudo] password for ana: "), false);
        assert_eq!(tracker.typed(), None);
        assert_eq!(tracker.edit(Edit::Enter), None);
    }

    #[test]
    fn keys_the_shell_handles_itself_forget_the_line_until_enter() {
        let mut tracker = LineTracker::new();
        typed(&mut tracker, "ls");
        tracker.observe(&screen("$ ls"), false);
        tracker.edit(Edit::Other);
        typed(&mut tracker, " -la");
        tracker.observe(&screen("$ ls -la"), false);
        assert_eq!(tracker.typed(), None);
        assert_eq!(tracker.edit(Edit::Enter), None);
        // Después de Enter vuelve a seguirse.
        typed(&mut tracker, "pwd");
        tracker.observe(&screen("$ pwd"), false);
        assert_eq!(tracker.typed(), Some("pwd"));
        tracker.edit(Edit::Clear);
        assert_eq!(tracker.typed(), None);
    }

    #[test]
    fn a_paste_with_a_newline_is_not_followed() {
        let mut tracker = LineTracker::new();
        tracker.edit(Edit::Paste("echo uno"));
        tracker.observe(&screen("$ echo uno"), false);
        assert_eq!(tracker.typed(), Some("echo uno"));
        tracker.edit(Edit::Paste("\necho dos"));
        assert_eq!(tracker.typed(), None);
    }

    #[test]
    fn full_screen_programs_are_left_alone() {
        let mut tracker = LineTracker::new();
        typed(&mut tracker, "ihola");
        tracker.observe(&screen("ihola"), true);
        assert_eq!(tracker.typed(), None);
        assert_eq!(tracker.edit(Edit::Enter), None);
        typed(&mut tracker, ":wq");
        assert_eq!(tracker.edit(Edit::Enter), None);
        // Al volver a la shell se sigue de nuevo.
        tracker.observe(&screen("$ "), false);
        typed(&mut tracker, "ls");
        tracker.observe(&screen("$ ls"), false);
        assert_eq!(tracker.typed(), Some("ls"));
    }

    #[test]
    fn a_line_that_wraps_is_still_recognised() {
        let mut tracker = LineTracker::new();
        let command = "echo una línea bastante larga que no cabe";
        typed(&mut tracker, command);
        tracker.observe(&screen(&format!("$ {command}")), false);
        assert_eq!(tracker.typed(), Some(command));
    }

    #[test]
    fn the_suggestion_only_shows_over_an_empty_rest_of_line() {
        assert!(blank_after_cursor(&screen("$ git")));
        // fish pinta su propia sugerencia y deja el cursor detrás de lo escrito.
        assert!(!blank_after_cursor(&screen("$ git status\x1b[6D")));
    }

    #[test]
    fn a_line_changed_from_elsewhere_is_forgotten() {
        let mut tracker = LineTracker::new();
        typed(&mut tracker, "ab");
        tracker.observe(&screen("$ ab"), false);
        // Otra terminal marcada escribió y ejecutó algo en esta: ya no se ve «ab».
        tracker.observe(&screen("$ ab\r\nhecho\r\n$ "), false);
        typed(&mut tracker, "x");
        tracker.observe(&screen("$ ab\r\nhecho\r\n$ x"), false);
        assert_eq!(tracker.typed(), None);
        assert_eq!(tracker.edit(Edit::Enter), None);
    }

    fn suggestion(history: &CommandHistory, typed: &str, screen: &Screen) -> Option<String> {
        let source = Source {
            history,
            snippets: &[],
            host: None,
        };
        source.suggest(typed, screen).map(|s| s.rest)
    }

    #[test]
    fn a_suggestion_that_does_not_fit_or_has_wide_characters_is_not_offered() {
        let history = CommandHistory::default()
            .record(None, "echo corto")
            .record(None, &format!("cat {}", "x".repeat(60)))
            .record(None, "echo 日本");
        assert_eq!(
            suggestion(&history, "echo c", &screen("$ echo c")).as_deref(),
            Some("orto")
        );
        assert_eq!(suggestion(&history, "cat", &screen("$ cat")), None);
        // El más reciente lleva caracteres anchos: no se sugiere nada.
        assert_eq!(suggestion(&history, "echo ", &screen("$ echo ")), None);
    }
}
