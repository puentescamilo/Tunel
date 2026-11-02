//! Desbloqueo con Touch ID (macOS) o Windows Hello: el sistema guarda o calcula la clave de
//! envoltura de [`tunel_core::biometric`] y solo la da tras la huella o el PIN.
//!
//! Las llamadas al sistema esperan a que el usuario responda: se hacen en un hilo aparte
//! con [`run`].

use crate::app::TunelApp;
use std::sync::OnceLock;
use std::sync::mpsc;
use tunel_core::biometric::{self as core, Enrollment, WrappingKey};
use tunel_core::{StoreError, UnlockedVault};

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;

#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

#[cfg(not(any(target_os = "macos", windows)))]
mod platform {
    use super::Error;
    use tunel_core::biometric::{Enrollment, WrappingKey};

    pub const NAME: &str = "";

    pub fn available() -> bool {
        false
    }

    pub fn wrapping_key(_: &Enrollment, _: bool) -> Result<WrappingKey, Error> {
        Err(Error::Failed("no disponible en este sistema".into()))
    }

    pub fn forget(_: &Enrollment) {}
}

#[derive(Debug)]
pub enum Error {
    /// El usuario cerró el aviso: no hay nada que decirle.
    #[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
    Cancelled,
    Failed(String),
}

/// «Touch ID» o «Windows Hello».
pub fn name() -> &'static str {
    platform::NAME
}

static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Comprueba en segundo plano si el equipo tiene huella o Windows Hello configurados.
pub fn probe(ctx: &egui::Context) {
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let _ = AVAILABLE.set(platform::available());
        ctx.request_repaint();
    });
}

pub fn available() -> bool {
    AVAILABLE.get() == Some(&true)
}

/// Algo que se hace en otro hilo y cuyo resultado se recoge en un frame posterior.
pub struct Pending<T>(mpsc::Receiver<T>);

pub fn run<T: Send + 'static>(
    ctx: &egui::Context,
    work: impl FnOnce() -> T + Send + 'static,
) -> Pending<T> {
    let (tx, rx) = mpsc::channel();
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let _ = tx.send(work());
        ctx.request_repaint();
    });
    Pending(rx)
}

impl<T> Pending<T> {
    /// El resultado, si ya está; `Some(None)` si el hilo terminó sin darlo.
    pub fn take(&self) -> Option<Option<T>> {
        match self.0.try_recv() {
            Ok(value) => Some(Some(value)),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(None),
        }
    }
}

pub enum Unlocked {
    Opened(Box<UnlockedVault>),
    Cancelled,
    Failed(String),
}

/// Pide la huella o el PIN y abre la bóveda de `path`. Bloquea: va en [`run`].
pub fn unlock(path: std::path::PathBuf) -> Unlocked {
    let enrollment = match core::enrollment(&path) {
        Ok(Some(enrollment)) => enrollment,
        Ok(None) => return Unlocked::Failed("el desbloqueo biométrico no está activado".into()),
        Err(e) => return Unlocked::Failed(e.to_string()),
    };
    let wrapping = match platform::wrapping_key(&enrollment, false) {
        Ok(wrapping) => wrapping,
        Err(Error::Cancelled) => return Unlocked::Cancelled,
        Err(Error::Failed(e)) => return Unlocked::Failed(e),
    };
    match UnlockedVault::unlock_biometric(&path, &wrapping) {
        Ok(vault) => Unlocked::Opened(Box::new(vault)),
        // No se quita solo: un fallo pasajero del sistema no debe desactivarlo sin preguntar.
        Err(StoreError::Crypto(_)) => Unlocked::Failed(format!(
            "{} no pudo abrir esta bóveda. Entra con la contraseña; si se repite, desactívalo \
             y vuelve a activarlo en Ajustes → Seguridad.",
            name()
        )),
        Err(e) => Unlocked::Failed(e.to_string()),
    }
}

/// Quita el desbloqueo biométrico de la bóveda de `path`, también lo que guarda el sistema.
pub fn disable(path: &std::path::Path) -> Result<(), StoreError> {
    // Un archivo ilegible no impide quitarlo: no hay secreto del sistema que se pueda nombrar.
    if let Ok(Some(enrollment)) = core::enrollment(path) {
        platform::forget(&enrollment);
    }
    core::forget(path)
}

/// Cambia la contraseña maestra. La clave que guardaba el desbloqueo biométrico deja de
/// servir: el núcleo borra su archivo y aquí se borra lo que guarda el sistema. Devuelve si
/// estaba activado, para avisar.
pub fn change_password(vault: &mut UnlockedVault, password: &str) -> Result<bool, StoreError> {
    let enrollment = core::enrollment(vault.path()).ok().flatten();
    vault.change_password(password)?;
    if let Some(enrollment) = &enrollment {
        platform::forget(enrollment);
    }
    Ok(enrollment.is_some())
}

/// Activación en curso desde Ajustes.
pub type Setup = Pending<(Enrollment, Result<WrappingKey, Error>)>;

pub fn start_setup(app: &mut TunelApp, ctx: &egui::Context) {
    let enrollment = Enrollment::new();
    app.biometric_setup = Some(run(ctx, move || {
        let result = platform::wrapping_key(&enrollment, true);
        (enrollment, result)
    }));
}

/// Termina la activación cuando el sistema responde.
pub fn tick(app: &mut TunelApp) {
    let Some(result) = app.biometric_setup.as_ref().and_then(Pending::take) else {
        return;
    };
    app.biometric_setup = None;
    let message = match result {
        None | Some((_, Err(Error::Cancelled))) => return,
        Some((_, Err(Error::Failed(e)))) => format!("No se pudo activar {}: {e}", name()),
        Some((enrollment, Ok(wrapping))) => {
            let Some(vault) = app.vault.as_ref() else {
                // Se bloqueó mientras tanto: el secreto ya no tendría quien lo usara.
                platform::forget(&enrollment);
                return;
            };
            let previous = core::enrollment(vault.path()).ok().flatten();
            match vault.enable_biometric(&enrollment, &wrapping) {
                Ok(()) => {
                    if let Some(previous) = previous.filter(|p| p != &enrollment) {
                        platform::forget(&previous);
                    }
                    format!("{} activado: ya puedes abrir la bóveda con él", name())
                }
                Err(e) => {
                    platform::forget(&enrollment);
                    format!("No se pudo activar {}: {e}", name())
                }
            }
        }
    };
    app.notify(message);
}
