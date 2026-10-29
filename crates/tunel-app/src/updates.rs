//! Aviso de versiones nuevas: consulta la última versión publicada en GitHub y, si es
//! más reciente que la instalada, ofrece descargar el instalador de este sistema.
//!
//! No instala nada por su cuenta: abre la descarga en el navegador y es el usuario quien
//! ejecuta el instalador, con las mismas comprobaciones del sistema que la primera vez.

use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Versión de esta compilación, la misma que la de los paquetes.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const LATEST_RELEASE_API: &str = "https://api.github.com/repos/puentescamilo/Tunel/releases/latest";
/// Todas las páginas y descargas de versiones cuelgan de aquí; nada fuera se abre.
const RELEASES_PAGE: &str = "https://github.com/puentescamilo/Tunel/releases/";
const LATEST_RELEASE_PAGE: &str = "https://github.com/puentescamilo/Tunel/releases/latest";

/// Espera tras abrir la bóveda, para no competir con el arranque.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(5);
const CHECK_PERIOD: Duration = Duration::from_secs(12 * 60 * 60);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// La respuesta de GitHub ocupa unos pocos KiB; más que esto no es una respuesta normal.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Versión instalada. Solo en depuración, `TUNEL_DEV_VERSION=0.1.0` simula una anterior
/// para ver el aviso con la última versión real de GitHub.
pub fn current_version() -> String {
    #[cfg(debug_assertions)]
    if let Ok(version) = std::env::var("TUNEL_DEV_VERSION") {
        return version;
    }
    CURRENT_VERSION.to_string()
}

/// Versión `mayor.menor.parche`. Las preliminares (`0.3.0-rc1`) no se ofrecen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

impl Version {
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let mut parts = text.split('.').map(|p| {
            // `u64::from_str` acepta un `+` delante; aquí solo valen dígitos.
            (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                .then(|| p.parse().ok())
                .flatten()
        });
        let version = Self(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(version)
    }
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Una versión más reciente que la instalada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub version: String,
    /// Página de la versión en GitHub, con las novedades.
    pub notes_url: String,
    /// Instalador de este sistema o, si no hay uno, la página de la versión.
    pub download_url: String,
}

/// Solo se abren direcciones de las versiones del repositorio, aunque la respuesta diga
/// otra cosa: un enlace ajeno podría llevar a un instalador falso.
fn is_release_url(url: &str) -> bool {
    url.starts_with(RELEASES_PAGE) && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Final del nombre del instalador de este sistema en los archivos de cada versión.
fn installer_suffix(os: &str, arch: &str, from_program_files: bool) -> Option<&'static str> {
    match (os, arch) {
        ("macos", _) => Some("_universal.dmg"),
        // El .msi se instala en «Archivos de programa»; el .exe, en la carpeta del usuario.
        ("windows", "x86_64") if from_program_files => Some("_x64_es-ES.msi"),
        ("windows", "x86_64") => Some("_x64-setup.exe"),
        ("linux", "x86_64") => Some("_amd64.deb"),
        ("linux", "aarch64") => Some("_arm64.deb"),
        _ => None,
    }
}

fn this_installer_suffix() -> Option<&'static str> {
    let from_program_files = std::env::current_exe()
        .map(|p| {
            p.components().any(|c| {
                c.as_os_str()
                    .to_string_lossy()
                    .to_lowercase()
                    .starts_with("program files")
            })
        })
        .unwrap_or(false);
    installer_suffix(
        std::env::consts::OS,
        std::env::consts::ARCH,
        from_program_files,
    )
}

/// Decide si `release` es una versión nueva para quien tiene instalada `current`.
fn evaluate(release: &Release, current: Version, suffix: Option<&str>) -> Option<Update> {
    if release.draft || release.prerelease {
        return None;
    }
    let version = Version::parse(&release.tag_name)?;
    if version <= current {
        return None;
    }
    let notes_url = if is_release_url(&release.html_url) {
        release.html_url.clone()
    } else {
        LATEST_RELEASE_PAGE.to_string()
    };
    let download_url = suffix
        .and_then(|suffix| {
            release
                .assets
                .iter()
                .find(|a| a.name.ends_with(suffix) && is_release_url(&a.browser_download_url))
        })
        .map_or_else(|| notes_url.clone(), |a| a.browser_download_url.clone());
    Some(Update {
        version: format!("{}.{}.{}", version.0, version.1, version.2),
        notes_url,
        download_url,
    })
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("respuesta demasiado grande".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Pide a GitHub la última versión publicada.
pub async fn fetch_latest() -> Result<Option<Update>, String> {
    let current = Version::parse(&current_version()).ok_or("versión actual no válida")?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("Tunel/{CURRENT_VERSION}"))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(LATEST_RELEASE_API)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("sin conexión con GitHub ({e})"))?;
    match response.status() {
        // Aún no se ha publicado ninguna versión.
        reqwest::StatusCode::NOT_FOUND => return Ok(None),
        status if !status.is_success() => return Err(format!("GitHub respondió {status}")),
        _ => {}
    }
    let body = read_limited(response).await?;
    let release: Release =
        serde_json::from_slice(&body).map_err(|e| format!("respuesta no válida ({e})"))?;
    Ok(evaluate(&release, current, this_installer_suffix()))
}

/// Estado de la última comprobación, para mostrarlo junto a la versión.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatus {
    NotChecked,
    Checking,
    UpToDate,
    Available(Update),
    Failed(String),
}

type Pending = oneshot::Receiver<Result<Option<Update>, String>>;

/// Programa las comprobaciones y guarda su resultado. No depende de la bóveda: bloquearla
/// no cancela una comprobación en curso.
pub struct UpdateChecker {
    pub status: UpdateStatus,
    pending: Option<Pending>,
    next_check: Instant,
}

impl Default for UpdateChecker {
    fn default() -> Self {
        Self {
            status: UpdateStatus::NotChecked,
            pending: None,
            next_check: Instant::now() + FIRST_CHECK_DELAY,
        }
    }
}

impl UpdateChecker {
    pub fn available(&self) -> Option<&Update> {
        match &self.status {
            UpdateStatus::Available(update) => Some(update),
            _ => None,
        }
    }

    /// Comprueba ya, salvo que haya una comprobación en curso.
    pub fn check_now(&mut self, start: impl FnOnce() -> Pending) {
        if self.pending.is_some() {
            return;
        }
        self.pending = Some(start());
        // Si ya se sabía de una versión nueva, se sigue mostrando mientras tanto.
        if self.available().is_none() {
            self.status = UpdateStatus::Checking;
        }
    }

    /// Recoge el resultado si llegó y lanza la siguiente comprobación cuando toca.
    /// Devuelve la versión nueva la primera vez que se descubre, para avisar.
    pub fn tick(&mut self, start: impl FnOnce() -> Pending) -> Option<Update> {
        let discovered = self.collect(Instant::now());
        if self.pending.is_none() && Instant::now() >= self.next_check {
            self.check_now(start);
        }
        discovered
    }

    fn collect(&mut self, now: Instant) -> Option<Update> {
        let result = match self.pending.as_mut()?.try_recv() {
            Ok(result) => result,
            Err(oneshot::error::TryRecvError::Empty) => return None,
            Err(oneshot::error::TryRecvError::Closed) => Err("comprobación interrumpida".into()),
        };
        self.pending = None;
        self.apply(result, now)
    }

    fn apply(&mut self, result: Result<Option<Update>, String>, now: Instant) -> Option<Update> {
        let previous = self.available().cloned();
        match result {
            Ok(Some(update)) => {
                self.next_check = now + CHECK_PERIOD;
                self.status = UpdateStatus::Available(update.clone());
                (previous.as_ref() != Some(&update)).then_some(update)
            }
            Ok(None) => {
                self.next_check = now + CHECK_PERIOD;
                self.status = UpdateStatus::UpToDate;
                None
            }
            Err(error) => {
                tracing::info!(%error, "no se pudo comprobar si hay versiones nuevas");
                self.next_check = now + RETRY_AFTER_FAILURE;
                // Un fallo de red no borra una versión nueva que ya se conocía.
                if previous.is_none() {
                    self.status = UpdateStatus::Failed(error);
                }
                None
            }
        }
    }

    /// Cuánto falta para que haya algo que hacer, para despertar a la interfaz.
    pub fn wait(&self) -> Duration {
        if self.pending.is_some() {
            return Duration::from_millis(500);
        }
        self.next_check.saturating_duration_since(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, assets: &[&str]) -> Release {
        Release {
            tag_name: tag.into(),
            html_url: format!("{RELEASES_PAGE}tag/{tag}"),
            draft: false,
            prerelease: false,
            assets: assets
                .iter()
                .map(|name| Asset {
                    name: (*name).into(),
                    browser_download_url: format!("{RELEASES_PAGE}download/{tag}/{name}"),
                })
                .collect(),
        }
    }

    const ASSETS: [&str; 5] = [
        "tunel_0.3.0_universal.dmg",
        "tunel_0.3.0_amd64.deb",
        "tunel_0.3.0_x64_es-ES.msi",
        "tunel_0.3.0_x64-setup.exe",
        "SHA256SUMS.txt",
    ];

    #[test]
    fn versions_compare_numerically_and_reject_prereleases() {
        assert_eq!(Version::parse("v0.10.0"), Some(Version(0, 10, 0)));
        assert!(Version::parse("0.10.0") > Version::parse("0.9.9"));
        assert_eq!(Version::parse(" 1.2.3 "), Some(Version(1, 2, 3)));
        for invalid in ["0.3.0-rc1", "0.3", "0.3.0.1", "v", "", "0.+3.0", "0..1"] {
            assert_eq!(Version::parse(invalid), None, "{invalid}");
        }
        assert!(Version::parse(CURRENT_VERSION).is_some());
    }

    #[test]
    fn a_newer_release_offers_this_systems_installer() {
        let current = Version(0, 2, 0);
        let update = evaluate(&release("v0.3.0", &ASSETS), current, Some("_amd64.deb")).unwrap();
        assert_eq!(update.version, "0.3.0");
        assert_eq!(
            update.download_url,
            format!("{RELEASES_PAGE}download/v0.3.0/tunel_0.3.0_amd64.deb")
        );
        assert_eq!(update.notes_url, format!("{RELEASES_PAGE}tag/v0.3.0"));
    }

    #[test]
    fn same_older_draft_and_prerelease_versions_are_not_offered() {
        let current = Version(0, 2, 0);
        assert_eq!(evaluate(&release("v0.2.0", &ASSETS), current, None), None);
        assert_eq!(evaluate(&release("v0.1.9", &ASSETS), current, None), None);
        assert_eq!(
            evaluate(&release("v0.3.0-rc1", &ASSETS), current, None),
            None
        );
        let draft = Release {
            draft: true,
            ..release("v0.3.0", &ASSETS)
        };
        assert_eq!(evaluate(&draft, current, None), None);
        let prerelease = Release {
            prerelease: true,
            ..release("v0.3.0", &ASSETS)
        };
        assert_eq!(evaluate(&prerelease, current, None), None);
    }

    #[test]
    fn without_an_installer_for_this_system_the_release_page_is_opened() {
        let current = Version(0, 2, 0);
        let update = evaluate(&release("v0.3.0", &ASSETS), current, Some("_arm64.deb")).unwrap();
        assert_eq!(update.download_url, update.notes_url);
        let update = evaluate(&release("v0.3.0", &ASSETS), current, None).unwrap();
        assert_eq!(update.download_url, update.notes_url);
    }

    #[test]
    fn links_outside_the_repositorys_releases_are_never_opened() {
        let mut tampered = release("v0.3.0", &ASSETS);
        tampered.html_url = "https://example.com/tunel".into();
        for asset in &mut tampered.assets {
            asset.browser_download_url = format!("https://example.com/{}", asset.name);
        }
        let update = evaluate(&tampered, Version(0, 2, 0), Some("_universal.dmg")).unwrap();
        assert_eq!(update.notes_url, LATEST_RELEASE_PAGE);
        assert_eq!(update.download_url, LATEST_RELEASE_PAGE);
        assert!(!is_release_url(
            "https://github.com/puentescamilo/Tunel/releases/x y"
        ));
        assert!(!is_release_url(
            "https://github.com/puentescamilo/Tunel-falso/releases/"
        ));
    }

    #[test]
    fn each_system_downloads_its_own_installer() {
        assert_eq!(
            installer_suffix("macos", "aarch64", false),
            Some("_universal.dmg")
        );
        assert_eq!(
            installer_suffix("windows", "x86_64", true),
            Some("_x64_es-ES.msi")
        );
        assert_eq!(
            installer_suffix("windows", "x86_64", false),
            Some("_x64-setup.exe")
        );
        assert_eq!(
            installer_suffix("linux", "x86_64", false),
            Some("_amd64.deb")
        );
        assert_eq!(installer_suffix("freebsd", "x86_64", false), None);
    }

    fn update(version: &str) -> Update {
        Update {
            version: version.into(),
            notes_url: LATEST_RELEASE_PAGE.into(),
            download_url: LATEST_RELEASE_PAGE.into(),
        }
    }

    #[test]
    fn a_new_version_is_announced_once_and_survives_network_failures() {
        let mut checker = UpdateChecker::default();
        let now = Instant::now();
        assert_eq!(
            checker.apply(Ok(Some(update("0.3.0"))), now),
            Some(update("0.3.0"))
        );
        assert_eq!(checker.apply(Ok(Some(update("0.3.0"))), now), None);
        assert_eq!(checker.apply(Err("sin red".into()), now), None);
        assert_eq!(checker.available(), Some(&update("0.3.0")));
        assert_eq!(
            checker.apply(Ok(Some(update("0.4.0"))), now),
            Some(update("0.4.0"))
        );
    }

    #[test]
    fn checks_are_scheduled_after_each_result() {
        let mut checker = UpdateChecker::default();
        let now = Instant::now();
        checker.apply(Ok(None), now);
        assert_eq!(checker.status, UpdateStatus::UpToDate);
        assert_eq!(checker.next_check, now + CHECK_PERIOD);
        checker.apply(Err("sin red".into()), now);
        assert_eq!(checker.status, UpdateStatus::Failed("sin red".into()));
        assert_eq!(checker.next_check, now + RETRY_AFTER_FAILURE);
    }

    #[test]
    fn only_one_check_runs_at_a_time_and_its_result_is_collected() {
        let mut checker = UpdateChecker::default();
        let (tx, rx) = oneshot::channel();
        checker.check_now(|| rx);
        assert_eq!(checker.status, UpdateStatus::Checking);
        checker.check_now(|| panic!("ya hay una comprobación en curso"));
        assert_eq!(checker.tick(|| panic!("no toca todavía")), None);

        tx.send(Ok(Some(update("0.3.0")))).unwrap();
        assert_eq!(
            checker.tick(|| panic!("no toca todavía")),
            Some(update("0.3.0"))
        );
        assert!(checker.pending.is_none());
    }

    #[test]
    fn an_interrupted_check_counts_as_a_failure() {
        let mut checker = UpdateChecker::default();
        let (tx, rx) = oneshot::channel();
        checker.check_now(|| rx);
        drop(tx);
        checker.tick(|| panic!("no toca todavía"));
        assert!(matches!(checker.status, UpdateStatus::Failed(_)));
    }
}
