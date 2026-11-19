//! Escribir el archivo hosts con permisos de administrador y vaciar la caché DNS.
//!
//! Túnel no corre como administrador: deja el contenido en un archivo temporal y pide al
//! sistema que lo copie con su diálogo de siempre: el de autorización en macOS, polkit
//! (`pkexec`) en Linux y el control de cuentas (UAC) en Windows. Las rutas van como
//! argumentos o codificadas, nunca pegadas a una orden de shell sin escapar.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevatedError {
    /// Se cerró el diálogo sin autorizar.
    Cancelled,
    Failed(String),
}

/// Copia `bytes` sobre `target` como administrador y vacía la caché DNS.
pub fn write(target: &Path, bytes: &[u8]) -> Result<(), ElevatedError> {
    let mut source = tempfile::NamedTempFile::new().map_err(failed)?;
    source.write_all(bytes).map_err(failed)?;
    source.flush().map_err(failed)?;
    let output = command(source.path(), target).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ElevatedError::Failed(MISSING_TOOL.into())
        } else {
            failed(e)
        }
    })?;
    interpret(&output)
}

fn failed(error: impl std::fmt::Display) -> ElevatedError {
    ElevatedError::Failed(error.to_string())
}

#[cfg(target_os = "macos")]
const MISSING_TOOL: &str = "no se encontró osascript";
#[cfg(windows)]
const MISSING_TOOL: &str = "no se encontró PowerShell";
#[cfg(not(any(target_os = "macos", windows)))]
const MISSING_TOOL: &str = "hace falta pkexec (polkit) para pedir permisos de administrador";

#[cfg(target_os = "macos")]
fn command(source: &Path, target: &Path) -> Command {
    let mut command = Command::new("osascript");
    command.args(osascript_args(source, target));
    command
}

#[cfg(windows)]
fn command(source: &Path, target: &Path) -> Command {
    use std::os::windows::process::CommandExt as _;
    /// Sin ventana de consola: solo se ve el diálogo de UAC.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let inner = encode_powershell(&powershell_copy(source, target));
    let mut command = Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(powershell_elevate(&inner))
        .creation_flags(CREATE_NO_WINDOW);
    command
}

#[cfg(not(any(target_os = "macos", windows)))]
fn command(source: &Path, target: &Path) -> Command {
    let mut command = Command::new("pkexec");
    command.args(pkexec_args(source, target));
    command
}

#[cfg(target_os = "macos")]
fn interpret(output: &Output) -> Result<(), ElevatedError> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    match output.status.code() {
        Some(0) => Ok(()),
        // «User canceled» es el error -128 de AppleScript.
        _ if stderr.contains("(-128)") => Err(ElevatedError::Cancelled),
        _ => Err(ElevatedError::Failed(stderr.trim().to_string())),
    }
}

#[cfg(windows)]
fn interpret(output: &Output) -> Result<(), ElevatedError> {
    match output.status.code() {
        Some(0) => Ok(()),
        Some(WINDOWS_CANCELLED) => Err(ElevatedError::Cancelled),
        _ => Err(ElevatedError::Failed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        )),
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn interpret(output: &Output) -> Result<(), ElevatedError> {
    match output.status.code() {
        Some(0) => Ok(()),
        // pkexec: 126 si se cerró el diálogo, 127 si no hubo autorización.
        Some(126) => Err(ElevatedError::Cancelled),
        Some(127) => Err(ElevatedError::Failed(
            "no se pudo autorizar (¿hay un agente de polkit en el escritorio?)".into(),
        )),
        _ => Err(ElevatedError::Failed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        )),
    }
}

/// `cat` y no `cp`: así el archivo conserva su dueño y sus permisos.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn osascript_args(source: &Path, target: &Path) -> Vec<OsString> {
    let script = [
        "on run argv",
        "do shell script \"cat \" & quoted form of (item 1 of argv) & \" > \" & quoted form of \
         (item 2 of argv) & \" || exit 1; dscacheutil -flushcache; killall -HUP mDNSResponder; \
         exit 0\" with administrator privileges",
        "end run",
    ];
    let mut args: Vec<OsString> = Vec::new();
    for line in script {
        args.push("-e".into());
        args.push(line.into());
    }
    args.push(source.into());
    args.push(target.into());
    args
}

/// systemd-resolved y nscd guardan lo que leyeron del archivo; si no están, no pasa nada.
#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
fn pkexec_args(source: &Path, target: &Path) -> Vec<OsString> {
    vec![
        "/bin/sh".into(),
        "-c".into(),
        "cat \"$1\" > \"$2\" || exit 1; \
         (resolvectl flush-caches || nscd -i hosts) >/dev/null 2>&1; exit 0"
            .into(),
        "sh".into(),
        source.into(),
        target.into(),
    ]
}

/// Lo que devuelve PowerShell si se rechaza el diálogo de UAC.
#[cfg_attr(not(windows), allow(dead_code))]
const WINDOWS_CANCELLED: i32 = 2;

/// Lo que corre ya como administrador. `WriteAllBytes` reescribe el archivo existente, así
/// que conserva sus permisos.
#[cfg_attr(not(windows), allow(dead_code))]
fn powershell_copy(source: &Path, target: &Path) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         [IO.File]::WriteAllBytes({}, [IO.File]::ReadAllBytes({}))\n\
         ipconfig /flushdns | Out-Null",
        powershell_string(target),
        powershell_string(source)
    )
}

/// Lanza `encoded` como administrador y devuelve su código de salida.
#[cfg_attr(not(windows), allow(dead_code))]
fn powershell_elevate(encoded: &str) -> String {
    format!(
        "try {{ $p = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru \
         -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',\
         '{encoded}' }} catch {{ exit {WINDOWS_CANCELLED} }}\nexit $p.ExitCode"
    )
}

/// Una cadena literal de PowerShell: entre comillas simples, que se escriben dobles.
#[cfg_attr(not(windows), allow(dead_code))]
fn powershell_string(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

/// `-EncodedCommand` espera el guion en UTF-16LE y base64: así no hay comillas que escapar.
#[cfg_attr(not(windows), allow(dead_code))]
fn encode_powershell(script: &str) -> String {
    use base64::Engine as _;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_passes_the_paths_as_arguments_not_inside_the_script() {
        let args = osascript_args(Path::new("/tmp/a b'c"), Path::new("/etc/hosts"));

        let script: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
        assert_eq!(script[0], "-e");
        assert!(script[3].contains("with administrator privileges"));
        assert!(script[3].contains("quoted form of (item 1 of argv)"));
        assert!(!script[3].contains("a b'c"));
        assert_eq!(&script[6..], ["/tmp/a b'c", "/etc/hosts"]);
    }

    #[test]
    fn linux_passes_the_paths_as_positional_parameters() {
        let args = pkexec_args(Path::new("/tmp/x;rm -rf /"), Path::new("/etc/hosts"));

        let args: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
        assert_eq!(args[0], "/bin/sh");
        assert!(args[2].starts_with("cat \"$1\" > \"$2\""));
        assert_eq!(&args[4..], ["/tmp/x;rm -rf /", "/etc/hosts"]);
    }

    #[test]
    fn powershell_quotes_paths_with_apostrophes() {
        let script = powershell_copy(
            Path::new(r"C:\Users\O'Brien\Temp\x"),
            Path::new(r"C:\Windows\System32\drivers\etc\hosts"),
        );

        assert!(script.contains(r"ReadAllBytes('C:\Users\O''Brien\Temp\x')"));
        assert!(script.contains(r"WriteAllBytes('C:\Windows\System32\drivers\etc\hosts'"));
        assert!(script.contains("ipconfig /flushdns"));
    }

    #[test]
    fn the_elevated_script_travels_encoded() {
        let encoded = encode_powershell("ab");
        assert_eq!(encoded, "YQBiAA==");

        let outer = powershell_elevate(&encoded);

        assert!(outer.contains("-Verb RunAs"));
        assert!(outer.contains("'YQBiAA=='"));
        assert!(outer.contains("catch { exit 2 }"));
    }
}
