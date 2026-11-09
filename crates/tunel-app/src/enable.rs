//! «Enviar contraseña enable»: escribe en la terminal la contraseña *enable* de la identidad
//! del host, solo cuando la persona lo pide (menú de la pestaña o atajo). Túnel no mira lo
//! que muestra el switch: nunca la envía por su cuenta.
//!
//! Sale de la identidad (guardada en Túnel) o, si está vinculada, del campo oculto `enable`
//! del elemento de Vaultwarden. Sin Vaultwarden funciona igual con la guardada en Túnel.

use crate::app::{Tab, TunelApp};
use egui::{Key, KeyboardShortcut, Modifiers};
use zeroize::Zeroizing;

/// ⌘⇧E en macOS, Ctrl+Shift+E en Windows y Linux.
pub const SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::E);

/// Lo que se escribe en la terminal: la contraseña y Enter.
fn keystrokes(password: &str) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    bytes.extend_from_slice(password.as_bytes());
    bytes.push(b'\r');
    bytes
}

/// Si la pestaña `index` es una terminal propia, viva y de un host guardado.
pub fn available(app: &TunelApp, index: usize) -> bool {
    matches!(
        app.tabs.get(index),
        Some(Tab::Terminal(s)) if s.host.is_some() && s.is_alive() && !s.is_watching()
    )
}

/// La contraseña *enable* del host de la pestaña `index`, o por qué no la hay.
fn password_for(app: &TunelApp, index: usize) -> Result<Zeroizing<String>, String> {
    let Some(Tab::Terminal(session)) = app.tabs.get(index) else {
        return Err("Abre una terminal de un host para enviar la contraseña enable".into());
    };
    let (Some(host), Some(data)) = (session.host, app.data()) else {
        return Err("Esta terminal no es de un host guardado".into());
    };
    let (target, _) = app.engine.resolve(data, host).map_err(|e| e.to_string())?;
    let identity = target.identity.as_ref();
    match identity.and_then(|i| i.enable_password.as_deref()) {
        Some(password) if !password.is_empty() => Ok(Zeroizing::new(password.to_string())),
        _ if identity.is_some_and(|i| i.vaultwarden.is_some()) => Err(format!(
            "Falta la contraseña enable: en Vaultwarden, edita el elemento y añade un campo \
             personalizado de tipo Oculto llamado «{}» con la contraseña; luego pulsa \
             «Sincronizar ahora» en Ajustes",
            crate::vaultwarden::ENABLE_FIELD
        )),
        _ if identity.is_some() => Err(
            "La identidad de este host no tiene contraseña enable: añádela en el Llavero".into(),
        ),
        _ => Err("Este host no tiene identidad con contraseña enable".into()),
    }
}

/// Escribe la contraseña *enable* en la terminal de la pestaña `index`. Solo en esa: no se
/// repite en las marcadas para escribir a la vez, ni se guarda para autocompletar.
pub fn send(app: &mut TunelApp, index: usize) {
    if !available(app, index) {
        return app.notify("La contraseña enable solo se envía a una terminal abierta de un host");
    }
    match password_for(app, index) {
        Ok(password) => {
            if let Some(Tab::Terminal(session)) = app.tabs.get(index) {
                session.send(keystrokes(&password).to_vec());
            }
        }
        Err(reason) => app.notify(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_password_is_typed_followed_by_enter() {
        assert_eq!(keystrokes("en4ble").as_slice(), b"en4ble\r");
    }
}
