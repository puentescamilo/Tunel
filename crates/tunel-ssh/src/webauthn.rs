//! Llaves de seguridad FIDO2 en Windows, a través de la API WebAuthn del sistema
//! (`webauthn.dll`, Windows 10 1903 o posterior). Windows no deja hablar con la llave por HID
//! sin ser administrador; esta API sí, y muestra su propia ventana para tocarla y pedir el PIN.
//!
//! Como en OpenSSH para Windows, el mensaje SSH va como «client data» y Windows le calcula el
//! SHA-256: ese `clientDataHash` es justo el que firma una llave en SSH.

use crate::fido::{Assertion, AssertionRequest, Authenticator, FidoError};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED, WebAuthNAuthenticatorGetAssertion,
    WebAuthNFreeAssertion, WebAuthNGetApiVersionNumber, WebAuthNGetErrorName,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

/// Lo que espera Windows a que se toque la llave antes de rendirse.
const TIMEOUT_MS: u32 = 60_000;
/// El usuario cerró la ventana de Windows.
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;
/// Ninguna llave conectada tiene esta credencial.
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;

pub struct WebAuthnAuthenticator;

impl WebAuthnAuthenticator {
    /// `None` si este Windows no tiene la API (anterior a la 1903).
    pub fn new() -> Option<Self> {
        // SAFETY: sin argumentos; solo devuelve la versión de la API.
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        (version >= 1).then_some(Self)
    }
}

impl Authenticator for WebAuthnAuthenticator {
    fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, FidoError> {
        let rp_id = wide(request.application);
        let mut message = request.message.to_vec();
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: len_u32(&message)?,
            pbClientDataJSON: message.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut key_handle = request.key_handle.to_vec();
        let mut credential = WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: len_u32(&key_handle)?,
            pbId: key_handle.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        // SAFETY: estructura de C de enteros y punteros; todo a cero es «sin rellenar».
        let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS =
            unsafe { std::mem::zeroed() };
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        options.CredentialList.cCredentials = 1;
        options.CredentialList.pCredentials = &mut credential;
        // Solo llaves externas: no las passkeys de Windows Hello del propio equipo.
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.dwUserVerificationRequirement = if request.pin.is_some() {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        };

        let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        // SAFETY: todos los punteros apuntan a datos vivos hasta que vuelve la llamada; la
        // ventana de Windows se abre sobre la que está al frente, que es la de Túnel.
        let result = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                GetForegroundWindow(),
                rp_id.as_ptr(),
                &client_data,
                &options,
                &mut assertion,
            )
        };
        if result < 0 {
            return Err(error(result));
        }
        if assertion.is_null() {
            return Err(FidoError::BadResponse);
        }
        // SAFETY: Windows devolvió una respuesta válida; se copia y se libera con su función.
        let copied = unsafe {
            let a = &*assertion;
            let auth_data = bytes(a.pbAuthenticatorData, a.cbAuthenticatorData);
            let signature = bytes(a.pbSignature, a.cbSignature);
            WebAuthNFreeAssertion(assertion);
            Assertion {
                auth_data,
                signature,
            }
        };
        Ok(copied)
    }

    fn prompts_itself(&self) -> bool {
        true
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn len_u32(data: &[u8]) -> Result<u32, FidoError> {
    u32::try_from(data.len()).map_err(|_| FidoError::BadResponse)
}

/// # Safety
/// `ptr` apunta a `len` bytes válidos, o es nulo.
unsafe fn bytes(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: lo garantiza quien llama.
    unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec()
}

fn error(hresult: i32) -> FidoError {
    match hresult {
        NTE_USER_CANCELLED => FidoError::Cancelled,
        NTE_NOT_FOUND => FidoError::NoDevice,
        _ => {
            // SAFETY: devuelve un texto constante de la propia DLL, terminado en cero.
            let name = unsafe {
                let ptr = WebAuthNGetErrorName(hresult);
                if ptr.is_null() {
                    String::new()
                } else {
                    let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
                }
            };
            FidoError::Device(format!("{name} (0x{:08X})", hresult as u32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_windows_has_the_webauthn_api() {
        assert!(WebAuthnAuthenticator::new().is_some());
    }

    #[test]
    fn cancelling_and_missing_keys_have_their_own_errors() {
        assert_eq!(error(NTE_USER_CANCELLED), FidoError::Cancelled);
        assert_eq!(error(NTE_NOT_FOUND), FidoError::NoDevice);
        let other = error(0x8000_4005_u32 as i32);
        assert!(other.to_string().contains("0x80004005"), "{other}");
    }

    #[test]
    fn strings_end_in_a_null() {
        assert_eq!(wide("ssh:"), [115, 115, 104, 58, 0]);
    }
}
