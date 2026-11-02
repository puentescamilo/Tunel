//! Permisos de los archivos de la bóveda en Windows: solo los pueden abrir el usuario actual
//! y SYSTEM, sin heredar los de la carpeta. Es lo que hace `chmod 600` en macOS y Linux.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Deja `path` accesible solo para el usuario actual y SYSTEM.
pub fn restrict(path: &Path) -> io::Result<()> {
    let sddl = wide(OsStr::new(&private_sddl()?));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `sddl` termina en cero y `descriptor` recibe memoria que se libera con LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = Local(descriptor);
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: `descriptor` es válido hasta que se suelta `Local`; `dacl` apunta dentro de él.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let path = wide(path.as_os_str());
    // SAFETY: `path` termina en cero y `dacl` sigue vivo durante la llamada.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Control total para el usuario actual y SYSTEM; `P` impide heredar permisos.
pub(crate) fn private_sddl() -> io::Result<String> {
    Ok(format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", current_user_sid()?))
}

fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: el seudoidentificador del proceso actual siempre es válido.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(token);
    let mut len = 0u32;
    // SAFETY: con un búfer nulo solo pregunta el tamaño que hace falta.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len) };
    // `u64` para que TOKEN_USER quede alineado.
    let mut buffer = vec![0u64; (len as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `buffer` tiene al menos `len` bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation acaba de escribir un TOKEN_USER al principio de `buffer`.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    // SAFETY: el SID vive en `buffer`; `text` recibe memoria que se libera con LocalFree.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let text = Local(text.cast());
    // SAFETY: ConvertSidToStringSidW devuelve una cadena terminada en cero.
    Ok(unsafe { from_wide(text.0.cast()) })
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// # Safety
/// `text` debe apuntar a una cadena UTF-16 terminada en cero.
pub(crate) unsafe fn from_wide(text: *const u16) -> String {
    let mut len = 0;
    // SAFETY: lo garantiza quien llama.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: los `len` primeros caracteres son de la cadena.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

/// Memoria del sistema que se libera con LocalFree.
pub(crate) struct Local(pub(crate) *mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: la reservó el sistema para devolverla y nadie más la libera.
        unsafe { LocalFree(self.0) };
    }
}

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken abrió este identificador y solo se cierra aquí.
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    };

    /// Los permisos de `path`, en SDDL.
    pub(crate) fn dacl_of(path: &Path) -> String {
        let path = wide(path.as_os_str());
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `path` termina en cero; el descriptor se libera con LocalFree.
        let status = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let descriptor = Local(descriptor);
        let mut text = null_mut();
        // SAFETY: `descriptor` es válido; `text` se libera con LocalFree.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        assert_ne!(ok, 0);
        let text = Local(text.cast());
        // SAFETY: la cadena la acaba de escribir el sistema, terminada en cero.
        unsafe { from_wide(text.0.cast()) }
    }

    #[test]
    fn only_the_current_user_and_system_can_open_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archivo");
        std::fs::write(&path, b"x").unwrap();
        assert_ne!(dacl_of(&path), private_sddl().unwrap());

        restrict(&path).unwrap();
        assert_eq!(dacl_of(&path), private_sddl().unwrap());
        assert!(private_sddl().unwrap().starts_with("D:P(A;;FA;;;S-1-5-"));
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }
}
