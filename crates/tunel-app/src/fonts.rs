//! Fuentes de Google Fonts para la terminal y la interfaz.
//!
//! No se incluyen en la aplicación: se descargan de Google Fonts la primera vez que se
//! eligen y se guardan en la caché del usuario. Solo se pide el peso normal (400), en
//! TrueType, y antes de usar un archivo se comprueba que es una fuente válida.

use crate::app::TunelApp;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// Sugeridas para la terminal: monoespaciadas.
pub const TERMINAL_FONTS: &[&str] = &[
    "JetBrains Mono",
    "Source Code Pro",
    "Ubuntu Mono",
    "Fira Code",
    "IBM Plex Mono",
    "Roboto Mono",
    "Inconsolata",
    "Space Mono",
    "Red Hat Mono",
    "Noto Sans Mono",
];

/// Sugeridas para la interfaz.
pub const UI_FONTS: &[&str] = &[
    "Open Sans",
    "Inter",
    "Roboto",
    "Ubuntu",
    "Noto Sans",
    "Source Sans 3",
    "Lato",
    "IBM Plex Sans",
    "Nunito Sans",
];

/// Tope del nombre de una familia, en caracteres.
pub const MAX_FAMILY_CHARS: usize = 60;
const CSS_API: &str = "https://fonts.googleapis.com/css2";
/// Los archivos solo se descargan de aquí, aunque la hoja de estilos diga otra cosa.
const FONT_HOST: &str = "https://fonts.gstatic.com/";
const MAX_CSS_BYTES: usize = 64 * 1024;
const MAX_FONT_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Nombre de familia normalizado (espacios simples, sin los de los extremos), o `None`
/// si no parece una familia de Google Fonts: solo letras, números y espacios.
pub fn family_name(text: &str) -> Option<String> {
    let name = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let valid = !name.is_empty()
        && name.chars().count() <= MAX_FAMILY_CHARS
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ');
    valid.then_some(name)
}

fn cache_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "tunel", "tunel").map(|d| d.cache_dir().join("fuentes"))
}

/// Archivo de la caché para una familia ya normalizada: `JetBrains Mono` →
/// `jetbrains-mono.ttf`.
fn file_name(family: &str) -> String {
    format!("{}.ttf", family.to_lowercase().replace(' ', "-"))
}

/// La fuente guardada en la caché, si existe y es válida.
pub fn cached(family: &str) -> Option<Vec<u8>> {
    let bytes = std::fs::read(cache_dir()?.join(file_name(family))).ok()?;
    is_font(&bytes).then_some(bytes)
}

/// Es un archivo de fuente que egui puede cargar: si no, `set_fonts` fallaría.
fn is_font(bytes: &[u8]) -> bool {
    use skrifa::MetadataProvider;
    skrifa::FontRef::new(bytes).is_ok_and(|font| font.charmap().map('a').is_some())
}

/// URL del archivo TrueType en la hoja de estilos de Google Fonts.
fn ttf_url(css: &str) -> Option<String> {
    css.split("url(")
        .skip(1)
        .filter_map(|rest| rest.split(')').next())
        .map(|url| url.trim_matches(['\'', '"']).to_string())
        .find(|url| url.starts_with(FONT_HOST) && url.ends_with(".ttf"))
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > limit {
            return Err("el archivo es demasiado grande".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn get(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("sin conexión con Google Fonts ({})", e.without_url()))?;
    match response.status() {
        reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::NOT_FOUND => {
            Err("Google Fonts no tiene esa familia".into())
        }
        status if !status.is_success() => Err(format!("Google Fonts respondió {status}")),
        _ => read_limited(response, limit).await,
    }
}

/// Descarga la familia de Google Fonts y la guarda en la caché.
pub async fn download(family: String) -> Result<Vec<u8>, String> {
    // Sin la cabecera de un navegador, Google Fonts entrega TrueType en lugar de WOFF2.
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("Tunel/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let query = family.replace(' ', "+");
    let css = get(&client, &format!("{CSS_API}?family={query}"), MAX_CSS_BYTES).await?;
    let css = String::from_utf8_lossy(&css);
    let url = ttf_url(&css).ok_or("Google Fonts no ofrece esa familia en TrueType")?;
    let bytes = get(&client, &url, MAX_FONT_BYTES).await?;
    if !is_font(&bytes) {
        return Err("el archivo descargado no es una fuente válida".into());
    }
    if let Some(dir) = cache_dir() {
        let saved = std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(dir.join(file_name(&family)), &bytes));
        if let Err(e) = saved {
            tracing::warn!(error = %e, "no se pudo guardar la fuente en la caché");
        }
    }
    Ok(bytes)
}

/// Qué fuentes están instaladas en egui y cuáles se están descargando.
pub struct FontState {
    /// Fuentes de interfaz y terminal con las que se instaló egui por última vez.
    applied: Option<(Option<String>, Option<String>)>,
    /// Descargadas en esta ejecución o leídas de la caché.
    loaded: HashMap<String, Vec<u8>>,
    pending: HashSet<String>,
    /// Familias que no se pudieron descargar, con el motivo.
    pub failed: HashMap<String, String>,
    /// Familia que se está importando desde Ajustes: al llegar se añade a la lista.
    importing: Option<String>,
}

/// Al arrancar ya están las del sistema (ver `main`).
impl Default for FontState {
    fn default() -> Self {
        Self {
            applied: Some((None, None)),
            loaded: HashMap::new(),
            pending: HashSet::new(),
            failed: HashMap::new(),
            importing: None,
        }
    }
}

impl FontState {
    pub fn is_pending(&self, family: &str) -> bool {
        self.pending.contains(family)
    }

    pub fn importing(&self) -> Option<&str> {
        self.importing.as_deref()
    }

    /// La fuente, si ya está disponible; si no, la pide (una sola vez).
    fn bytes(&mut self, app_engine: &crate::engine::Engine, family: &str) -> Option<Vec<u8>> {
        if let Some(bytes) = self.loaded.get(family) {
            return Some(bytes.clone());
        }
        if let Some(bytes) = cached(family) {
            self.loaded.insert(family.to_string(), bytes.clone());
            return Some(bytes);
        }
        if !self.pending.contains(family) && !self.failed.contains_key(family) {
            self.pending.insert(family.to_string());
            app_engine.download_font(family.to_string());
        }
        None
    }
}

/// Instala en egui las fuentes elegidas en Ajustes en cuanto están disponibles.
pub fn tick(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(settings) = app.data().map(|d| d.settings.clone()) else {
        return;
    };
    let wanted = (settings.ui_font.clone(), settings.terminal_font.clone());
    if app.fonts.applied.as_ref() == Some(&wanted) {
        return;
    }
    let engine = &app.engine;
    let state = &mut app.fonts;
    let ui = wanted.0.as_deref().map(|f| (f, state.bytes(engine, f)));
    let mono = wanted.1.as_deref().map(|f| (f, state.bytes(engine, f)));
    // Se espera a tenerlas todas para no recolocar la interfaz dos veces.
    let waiting = [&ui, &mono]
        .into_iter()
        .flatten()
        .any(|(family, bytes)| bytes.is_none() && state.pending.contains(*family));
    if waiting {
        return;
    }
    let pick =
        |font: Option<(&str, Option<Vec<u8>>)>| font.and_then(|(f, b)| Some((f.to_string(), b?)));
    crate::ui::theme::install_fonts(ctx, pick(ui), pick(mono));
    app.fonts.applied = Some(wanted);
}

/// Llegó una fuente descargada (o el error).
pub fn on_downloaded(app: &mut TunelApp, family: String, result: Result<Vec<u8>, String>) {
    app.fonts.pending.remove(&family);
    let importing = app.fonts.importing.as_deref() == Some(family.as_str());
    match result {
        Ok(bytes) => {
            app.fonts.failed.remove(&family);
            app.fonts.loaded.insert(family.clone(), bytes);
            if importing {
                app.fonts.importing = None;
                add_custom(app, &family);
            }
        }
        Err(error) => {
            app.notify(format!("No se pudo descargar «{family}»: {error}"));
            app.fonts.failed.insert(family, error);
            if importing {
                app.fonts.importing = None;
            }
        }
    }
    // Vuelve a decidir con lo que haya ahora.
    app.fonts.applied = None;
}

fn add_custom(app: &mut TunelApp, family: &str) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let mut settings = data.settings.clone();
    remember(&mut settings, family);
    if settings != data.settings {
        app.commit(data.with_settings(settings));
    }
    app.notify(format!(
        "«{family}» ya está disponible en las listas de fuentes"
    ));
}

/// Importa una familia de Google Fonts escrita por la persona. Si ya estaba descargada
/// devuelve su nombre para añadirla a la lista; si no, la descarga y se añade al llegar.
pub fn import(app: &mut TunelApp, text: &str) -> Result<Option<String>, String> {
    let family = family_name(text).ok_or(
        "escribe el nombre tal como aparece en Google Fonts (solo letras, números y espacios)",
    )?;
    if app.fonts.importing.is_some() {
        return Err("espera a que termine la importación en curso".into());
    }
    app.fonts.failed.remove(&family);
    if cached(&family).is_some() || app.fonts.loaded.contains_key(&family) {
        return Ok(Some(family));
    }
    app.fonts.importing = Some(family.clone());
    if app.fonts.pending.insert(family.clone()) {
        app.engine.download_font(family);
    }
    Ok(None)
}

/// Añade `family` a las importadas de `settings` si no está ya en alguna lista.
pub fn remember(settings: &mut tunel_core::Settings, family: &str) {
    let known = TERMINAL_FONTS
        .iter()
        .chain(UI_FONTS)
        .copied()
        .chain(settings.custom_fonts.iter().map(String::as_str))
        .any(|f| f.eq_ignore_ascii_case(family));
    if !known {
        settings.custom_fonts.push(family.to_string());
    }
}

/// Vuelve a intentar las descargas que fallaron.
pub fn retry(app: &mut TunelApp) {
    app.fonts.failed.clear();
    app.fonts.applied = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_names_are_normalized_and_restricted() {
        assert_eq!(
            family_name("  JetBrains   Mono "),
            Some("JetBrains Mono".into())
        );
        assert_eq!(family_name("Source Sans 3"), Some("Source Sans 3".into()));
        for bad in [
            "",
            "   ",
            "Fira&Code",
            "../x",
            "Open+Sans",
            "Inter;wght@700",
        ] {
            assert_eq!(family_name(bad), None, "{bad}");
        }
        assert_eq!(family_name(&"a".repeat(MAX_FAMILY_CHARS + 1)), None);
    }

    #[test]
    fn cache_files_are_named_after_the_family() {
        assert_eq!(file_name("JetBrains Mono"), "jetbrains-mono.ttf");
        assert_eq!(file_name("Source Sans 3"), "source-sans-3.ttf");
    }

    #[test]
    fn the_truetype_url_comes_only_from_google() {
        let css = "@font-face {\n  font-family: 'Inter';\n  src: url(https://fonts.gstatic.com/s/inter/v1/abc.ttf) format('truetype');\n}";
        assert_eq!(
            ttf_url(css).as_deref(),
            Some("https://fonts.gstatic.com/s/inter/v1/abc.ttf")
        );
        let elsewhere = "src: url(https://example.com/x.ttf) format('truetype');";
        assert_eq!(ttf_url(elsewhere), None);
        let woff2 = "src: url(https://fonts.gstatic.com/s/inter/v1/abc.woff2) format('woff2');";
        assert_eq!(ttf_url(woff2), None);
    }

    #[test]
    fn imported_families_are_remembered_once() {
        let mut settings = tunel_core::Settings::default();
        remember(&mut settings, "Cascadia Code");
        remember(&mut settings, "cascadia code");
        remember(&mut settings, "JetBrains Mono");
        assert_eq!(settings.custom_fonts, vec!["Cascadia Code".to_string()]);
    }

    #[test]
    fn system_fonts_are_accepted() {
        // En cada sistema hay alguna de estas; en CI sin ninguna, no se comprueba nada.
        let system = [
            "/System/Library/Fonts/SFNS.ttf",
            "C:\\Windows\\Fonts\\segoeui.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ];
        for path in system {
            if let Ok(bytes) = std::fs::read(path) {
                assert!(is_font(&bytes), "{path}");
            }
        }
    }

    #[test]
    fn only_real_fonts_are_accepted() {
        assert!(!is_font(b"no soy una fuente"));
        assert!(!is_font(&[]));
        // Una cabecera TrueType sin tablas detrás tampoco.
        assert!(!is_font(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
}
