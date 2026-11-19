//! Copiar una contraseña al portapapeles sin mostrarla.
//!
//! A diferencia de `egui::Context::copy_text`, la copia se marca para que el historial del
//! portapapeles del sistema (y los gestores que siguen el estándar de nspasteboard.org) no
//! la guarden, y se borra a los [`CLEAR_AFTER`] si sigue ahí: si mientras tanto se copió
//! otra cosa, no se toca.

use std::time::Duration;
use zeroize::Zeroizing;

/// Tiempo que la contraseña copiada se queda en el portapapeles.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Copia `secret` en segundo plano. Si el sistema no deja escribir en el portapapeles, el
/// error se recoge con [`take_failure`].
pub fn copy_secret(ctx: &egui::Context, secret: Zeroizing<String>) {
    #[cfg(test)]
    {
        let _ = ctx;
        tests::COPIED.with(|c| *c.borrow_mut() = Some(secret));
    }
    #[cfg(not(test))]
    {
        let worker_ctx = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("portapapeles".into())
            .spawn(move || {
                if let Err(e) = system::copy_then_clear(&secret, CLEAR_AFTER) {
                    tracing::warn!(error = %e, "no se pudo copiar la contraseña");
                    report_failure(&worker_ctx);
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "no se pudo copiar la contraseña");
            report_failure(ctx);
        }
    }
}

fn failure_id() -> egui::Id {
    egui::Id::unique("portapapeles-falló")
}

/// Mensaje para la persona si la última copia no se pudo hacer; lo olvida.
pub fn take_failure(ctx: &egui::Context) -> Option<String> {
    ctx.data_mut(|d| d.remove_temp::<String>(failure_id()))
}

#[cfg(not(test))]
fn report_failure(ctx: &egui::Context) {
    ctx.data_mut(|d| {
        d.insert_temp(
            failure_id(),
            "No se pudo copiar la contraseña al portapapeles".to_string(),
        )
    });
    ctx.request_repaint();
}

#[cfg(not(test))]
mod system {
    use std::time::Duration;

    /// Escribe `secret`, espera `clear_after` y lo borra si nadie copió otra cosa. Mantiene
    /// vivo el mismo `Clipboard` todo el tiempo: en Linux el contenido lo sirve este
    /// proceso y desaparecería al soltarlo.
    pub fn copy_then_clear(secret: &str, clear_after: Duration) -> Result<(), arboard::Error> {
        let mut clipboard = arboard::Clipboard::new()?;
        hidden_from_history(clipboard.set()).text(secret)?;
        std::thread::sleep(clear_after);
        let still_there = clipboard
            .get_text()
            .map(|now| zeroize::Zeroizing::new(now).as_str() == secret)
            .unwrap_or(false);
        if still_there {
            clipboard.clear()?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn hidden_from_history(set: arboard::Set<'_>) -> arboard::Set<'_> {
        use arboard::SetExtApple;
        set.exclude_from_history()
    }

    #[cfg(target_os = "windows")]
    fn hidden_from_history(set: arboard::Set<'_>) -> arboard::Set<'_> {
        use arboard::SetExtWindows;
        set.exclude_from_monitoring()
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn hidden_from_history(set: arboard::Set<'_>) -> arboard::Set<'_> {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    }
}

#[cfg(test)]
pub mod tests {
    use std::cell::RefCell;
    use zeroize::Zeroizing;

    thread_local! {
        /// Lo que se habría copiado: las pruebas no tocan el portapapeles de verdad.
        pub static COPIED: RefCell<Option<Zeroizing<String>>> = const { RefCell::new(None) };
    }

    /// Lo último que copió la app en este hilo, y lo olvida.
    pub fn take_copied() -> Option<String> {
        COPIED.with(|c| c.borrow_mut().take().map(|s| s.to_string()))
    }
}
