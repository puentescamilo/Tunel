//! Touch ID: LocalAuthentication pide la huella y, después, la clave de envoltura se lee
//! del llavero de macOS, que solo se la da a Túnel sin preguntar.

use super::Error;
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};
use security_framework::passwords;
use tunel_core::biometric::{self as core, Enrollment, WrappingKey};
use tunel_core::crypto::KEY_LEN;
use zeroize::Zeroizing;

pub const NAME: &str = "Touch ID";
const SERVICE: &str = "Túnel";
const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

pub fn available() -> bool {
    // SAFETY: crear un LAContext y preguntarle por una política no tiene requisitos.
    unsafe { LAContext::new().canEvaluatePolicy_error(POLICY) }.is_ok()
}

fn account(enrollment: &Enrollment) -> String {
    format!("boveda-{}", enrollment.id())
}

/// Pide la huella y espera la respuesta.
fn ask(reason: &str) -> Result<(), Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let result = if ok.as_bool() {
            Ok(())
        } else {
            // SAFETY: si no es nulo, LocalAuthentication pasa un NSError válido mientras
            // dura la llamada.
            Err(match unsafe { error.as_ref() } {
                Some(error) => from_error(error),
                None => Error::Failed("no se pudo comprobar la huella".into()),
            })
        };
        let _ = tx.send(result);
    });
    // SAFETY: el contexto vive hasta que llega la respuesta, y el bloque no depende del
    // hilo en que se llame.
    let context = unsafe { LAContext::new() };
    unsafe {
        context.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &reply)
    };
    rx.recv()
        .unwrap_or_else(|_| Err(Error::Failed("Touch ID no respondió".into())))
}

fn from_error(error: &NSError) -> Error {
    let code = error.code();
    if [
        LAError::UserCancel,
        LAError::SystemCancel,
        LAError::AppCancel,
        // «Introducir contraseña»: se usa la maestra, sin error que mostrar.
        LAError::UserFallback,
    ]
    .iter()
    .any(|c| c.0 == code)
    {
        Error::Cancelled
    } else {
        Error::Failed(error.localizedDescription().to_string())
    }
}

fn keychain_error(e: security_framework::base::Error) -> Error {
    // errSecUserCanceled: el usuario no dejó leer el llavero.
    if e.code() == -128 {
        Error::Cancelled
    } else {
        Error::Failed(format!("llavero de macOS: {e}"))
    }
}

pub fn wrapping_key(enrollment: &Enrollment, create: bool) -> Result<WrappingKey, Error> {
    if create {
        ask("activar el desbloqueo de la bóveda con Touch ID")?;
        let key = core::random_wrapping_key();
        passwords::set_generic_password(SERVICE, &account(enrollment), key.as_ref())
            .map_err(keychain_error)?;
        return Ok(key);
    }
    ask("desbloquear la bóveda")?;
    let stored = Zeroizing::new(
        passwords::get_generic_password(SERVICE, &account(enrollment)).map_err(keychain_error)?,
    );
    if stored.len() != KEY_LEN {
        return Err(Error::Failed(
            "la clave guardada en el llavero no es válida".into(),
        ));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&stored);
    Ok(key)
}

pub fn forget(enrollment: &Enrollment) {
    let _ = passwords::delete_generic_password(SERVICE, &account(enrollment));
}
