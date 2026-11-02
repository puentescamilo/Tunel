//! Windows Hello: una clave RSA de Windows Hello, que solo firma tras la huella, la cara o
//! el PIN, firma el reto del alta. La firma PKCS#1 v1.5 es siempre la misma para el mismo
//! reto, y de ella sale la clave de envoltura: no se guarda nada secreto en el disco.

use super::Error;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tunel_core::biometric::{Enrollment, WrappingKey};
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
use windows::core::{Array, HSTRING, PCWSTR, w};
use zeroize::{Zeroize, Zeroizing};

pub const NAME: &str = "Windows Hello";
const DOMAIN: &[u8] = b"tunel-biometria-windows-hello-v1";
/// Cuánto se busca el aviso de Windows Hello para traerlo al frente.
const FOCUS_WAIT: Duration = Duration::from_secs(5);

pub fn available() -> bool {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| op.join())
        .unwrap_or(false)
}

fn credential_name(enrollment: &Enrollment) -> HSTRING {
    HSTRING::from(format!("Túnel-{}", enrollment.id()))
}

fn failed(e: windows::core::Error) -> Error {
    Error::Failed(format!("Windows Hello: {}", e.message()))
}

fn check(status: KeyCredentialStatus) -> Result<(), Error> {
    match status {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            Err(Error::Cancelled)
        }
        KeyCredentialStatus::NotFound => Err(Error::Failed(
            "Windows Hello ya no tiene la clave de Túnel: vuelve a activarlo en Ajustes".into(),
        )),
        KeyCredentialStatus::SecurityDeviceLocked => Err(Error::Failed(
            "Windows Hello está bloqueado por demasiados intentos".into(),
        )),
        other => Err(Error::Failed(format!(
            "Windows Hello no pudo completar la operación ({})",
            other.0
        ))),
    }
}

/// El aviso de Windows Hello de una aplicación de escritorio puede abrirse detrás de su
/// ventana: se busca un rato y se trae al frente.
fn bring_prompt_to_front() {
    std::thread::spawn(|| {
        let start = Instant::now();
        while start.elapsed() < FOCUS_WAIT {
            // SAFETY: solo se pasan cadenas constantes terminadas en cero.
            if let Ok(window) =
                unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) }
                && !window.is_invalid()
            {
                // SAFETY: `window` es una ventana que acaba de devolver el sistema.
                let _ = unsafe { SetForegroundWindow(window) };
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

pub fn wrapping_key(enrollment: &Enrollment, create: bool) -> Result<WrappingKey, Error> {
    let name = credential_name(enrollment);
    bring_prompt_to_front();
    let retrieval = if create {
        KeyCredentialManager::RequestCreateAsync(
            &name,
            KeyCredentialCreationOption::ReplaceExisting,
        )
    } else {
        KeyCredentialManager::OpenAsync(&name)
    }
    .and_then(|op| op.join())
    .map_err(failed)?;
    check(retrieval.Status().map_err(failed)?)?;
    let credential = retrieval.Credential().map_err(failed)?;
    let challenge =
        CryptographicBuffer::CreateFromByteArray(enrollment.challenge()).map_err(failed)?;
    bring_prompt_to_front();
    let signed = credential
        .RequestSignAsync(&challenge)
        .and_then(|op| op.join())
        .map_err(failed)?;
    check(signed.Status().map_err(failed)?)?;
    let mut signature = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signed.Result().map_err(failed)?, &mut signature)
        .map_err(failed)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&signature[..])
        .finalize_into(key.as_mut().into());
    signature[..].zeroize();
    Ok(key)
}

pub fn forget(enrollment: &Enrollment) {
    let _ =
        KeyCredentialManager::DeleteAsync(&credential_name(enrollment)).and_then(|op| op.join());
}
