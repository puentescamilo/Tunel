//! Túnel: cliente SSH multiplataforma.

// Sin esto, Windows abre una consola junto a la ventana.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod chrome;
mod editor;
mod engine;
mod lock;
mod prompts;
mod quick_connect;
mod session;
mod sync;
mod terminal_view;
mod ui;
mod views;

use anyhow::Context as _;

const APP_NAME: &str = "Túnel";
const VAULT_FILE: &str = "vault.json";
/// Coincide con el nombre del `.desktop` del paquete de Linux, para que Wayland asocie la ventana.
const APP_ID: &str = "tunel";

fn vault_path() -> anyhow::Result<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("TUNEL_VAULT") {
        return Ok(path.into());
    }
    let dirs = directories::ProjectDirs::from("dev", "tunel", "tunel")
        .context("no se encontró el directorio de datos del usuario")?;
    Ok(dirs.data_dir().join(VAULT_FILE))
}

/// Icono de la barra de tareas en Windows y Linux. En macOS se usa el del paquete `.app`.
fn window_icon(viewport: egui::ViewportBuilder) -> egui::ViewportBuilder {
    if cfg!(target_os = "macos") {
        return viewport;
    }
    match eframe::icon_data::from_png_bytes(include_bytes!("../assets/icons/256x256.png")) {
        Ok(icon) => viewport.with_icon(icon),
        Err(err) => {
            tracing::warn!("no se pudo cargar el icono de la ventana: {err}");
            viewport
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,tunel=info".into()),
        )
        .init();
    let path = vault_path()?;
    let options = eframe::NativeOptions {
        viewport: window_icon(
            egui::ViewportBuilder::default()
                .with_title(APP_NAME)
                .with_app_id(APP_ID)
                .with_inner_size([1200.0, 780.0])
                .with_min_inner_size([720.0, 420.0]),
        ),
        ..Default::default()
    };
    eframe::run_native(
        APP_NAME,
        options,
        Box::new(move |cc| {
            ui::theme::install_fonts(&cc.egui_ctx);
            ui::theme::apply(&cc.egui_ctx, ui::theme::DARK);
            Ok(Box::new(app::TunelApp::new(cc, path)?))
        }),
    )
    .map_err(|e| anyhow::anyhow!("error de la interfaz: {e}"))
}
