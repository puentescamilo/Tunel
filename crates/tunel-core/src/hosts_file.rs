//! El archivo hosts del equipo: dónde está, cómo se lee y se escribe sin cambiar sus finales
//! de línea, qué líneas no entiende el sistema y cómo se llaman sus copias de seguridad.
//!
//! Escribirlo necesita permisos de administrador; eso lo hace la app.

use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike};
use std::net::IpAddr;
use std::ops::Range;
use std::path::PathBuf;

/// Un nombre de host no puede pasar de aquí (RFC 1035).
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
/// Las copias se llaman `hosts-AAAAMMDD-HHMMSS`, así se ordenan por fecha.
const BACKUP_PREFIX: &str = "hosts-";

/// Dónde está el archivo hosts en este sistema.
pub fn system_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnding {
    Lf,
    CrLf,
}

/// El contenido del archivo para editarlo, siempre con `\n`, y cómo terminaban sus líneas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsText {
    pub text: String,
    pub line_ending: LineEnding,
}

impl HostsText {
    /// Lee los bytes del archivo. Lo que no sea UTF-8 se sustituye por `�`: el archivo hosts
    /// es texto ASCII y cualquier otra cosa ya era un error.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let text = String::from_utf8_lossy(bytes);
        let line_ending = if text.contains("\r\n") {
            LineEnding::CrLf
        } else {
            LineEnding::Lf
        };
        Self {
            text: text.replace("\r\n", "\n"),
            line_ending,
        }
    }

    /// Los bytes que se escriben: `text` con los finales de línea que tenía el archivo, y
    /// terminado en salto de línea, que algunos sistemas ignoran la última línea sin él.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = self.text.replace("\r\n", "\n");
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        match self.line_ending {
            LineEnding::Lf => text.into_bytes(),
            LineEnding::CrLf => text.replace('\n', "\r\n").into_bytes(),
        }
    }
}

/// Las partes de una línea, como rangos de bytes, para resaltarlas.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LineParts {
    pub address: Option<Range<usize>>,
    pub names: Vec<Range<usize>>,
    pub comment: Option<Range<usize>>,
}

pub fn line_parts(line: &str) -> LineParts {
    let (content, comment) = match line.find('#') {
        Some(start) => (&line[..start], Some(start..line.len())),
        None => (line, None),
    };
    let mut words = words(content);
    LineParts {
        address: words.next(),
        names: words.collect(),
        comment,
    }
}

fn words(text: &str) -> impl Iterator<Item = Range<usize>> + '_ {
    text.split(|c: char| c.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .map(move |w| {
            let start = w.as_ptr() as usize - text.as_ptr() as usize;
            start..start + w.len()
        })
}

/// Una línea que el sistema no va a entender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Desde 1, como en el editor.
    pub line: usize,
    pub message: String,
}

pub fn problems(text: &str) -> Vec<Problem> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            line_problem(line).map(|message| Problem {
                line: index + 1,
                message,
            })
        })
        .collect()
}

fn line_problem(line: &str) -> Option<String> {
    let parts = line_parts(line);
    let address = &line[parts.address?];
    if !is_address(address) {
        return Some(format!("«{address}» no es una dirección IP"));
    }
    if parts.names.is_empty() {
        return Some(format!("Falta el nombre después de {address}"));
    }
    parts
        .names
        .into_iter()
        .map(|range| &line[range])
        .find(|name| !is_name(name))
        .map(|name| format!("«{name}» no es un nombre de host válido"))
}

/// Una IPv4 o IPv6; esta última puede llevar la interfaz (`fe80::1%lo0`).
fn is_address(text: &str) -> bool {
    let address = match text.split_once('%') {
        Some((address, zone)) if !zone.is_empty() => address,
        Some(_) => return false,
        None => text,
    };
    let parsed = address.parse::<IpAddr>();
    // `%` solo tiene sentido en IPv6.
    matches!(parsed, Ok(IpAddr::V6(_))) || (parsed.is_ok() && !text.contains('%'))
}

/// Letras, cifras, `-`, `_` (lo admiten los sistemas, aunque no el DNS) y puntos entre
/// etiquetas.
fn is_name(name: &str) -> bool {
    name.len() <= MAX_NAME_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// El nombre de la copia hecha en `when`.
pub fn backup_name(when: NaiveDateTime) -> String {
    format!(
        "{BACKUP_PREFIX}{:04}{:02}{:02}-{:02}{:02}{:02}",
        when.year(),
        when.month(),
        when.day(),
        when.hour(),
        when.minute(),
        when.second()
    )
}

/// La fecha de una copia por su nombre; `None` si no es una copia.
pub fn backup_date(name: &str) -> Option<NaiveDateTime> {
    let (date, time) = name.strip_prefix(BACKUP_PREFIX)?.split_once('-')?;
    if date.len() != 8
        || time.len() != 6
        || !(date.to_owned() + time).bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let number = |text: &str, range: Range<usize>| text[range].parse::<u32>().ok();
    let year = i32::try_from(number(date, 0..4)?).ok()?;
    NaiveDate::from_ymd_opt(year, number(date, 4..6)?, number(date, 6..8)?)?.and_hms_opt(
        number(time, 0..2)?,
        number(time, 2..4)?,
        number(time, 4..6)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "##\n# Host Database\n##\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1             localhost\n";

    #[test]
    fn the_usual_files_have_no_problems() {
        assert!(problems(MAC).is_empty());
        let linux = "127.0.0.1 localhost\n127.0.1.1 equipo.lan equipo\n\nfe80::1%lo0 localhost\nff02::1 ip6-allnodes\n";
        assert!(problems(linux).is_empty());
    }

    #[test]
    fn a_line_that_is_not_an_entry_is_reported_with_its_number() {
        let text =
            "127.0.0.1 localhost\n10.0.0.300 web\n10.0.0.1\nweb-01 10.0.0.1\n10.0.0.2 -mal\n";

        let found: Vec<_> = problems(text)
            .into_iter()
            .map(|p| (p.line, p.message))
            .collect();

        assert_eq!(
            found,
            [
                (2, "«10.0.0.300» no es una dirección IP".to_string()),
                (3, "Falta el nombre después de 10.0.0.1".to_string()),
                (4, "«web-01» no es una dirección IP".to_string()),
                (5, "«-mal» no es un nombre de host válido".to_string()),
            ]
        );
    }

    #[test]
    fn comments_after_an_entry_are_not_names() {
        assert!(problems("10.0.0.1 web-01 # el servidor web, ¡ojo!\n").is_empty());
        assert!(problems("# 10.0.0.300 desactivada\n").is_empty());
    }

    #[test]
    fn a_zone_only_goes_with_ipv6() {
        assert!(is_address("fe80::1%en0"));
        assert!(!is_address("10.0.0.1%en0"));
        assert!(!is_address("fe80::1%"));
    }

    #[test]
    fn names_follow_the_rules_of_the_system() {
        assert!(is_name("web-01.lab.ejemplo.com"));
        assert!(is_name("_servicio"));
        assert!(!is_name("web..lab"));
        assert!(!is_name("web-.lab"));
        assert!(!is_name("ñandú"));
        assert!(!is_name(&"a".repeat(64)));
    }

    #[test]
    fn the_parts_of_a_line_can_be_highlighted() {
        let line = "10.0.0.1  web  db # nota";

        let parts = line_parts(line);

        assert_eq!(&line[parts.address.unwrap()], "10.0.0.1");
        let names: Vec<_> = parts.names.into_iter().map(|r| &line[r]).collect();
        assert_eq!(names, ["web", "db"]);
        assert_eq!(&line[parts.comment.unwrap()], "# nota");
    }

    #[test]
    fn windows_line_endings_are_kept_when_saving() {
        let read = HostsText::from_bytes(b"127.0.0.1 localhost\r\n# fin\r\n");
        assert_eq!(read.text, "127.0.0.1 localhost\n# fin\n");

        let edited = HostsText {
            text: format!("{}10.0.0.1 web", read.text),
            ..read
        };

        assert_eq!(
            edited.to_bytes(),
            b"127.0.0.1 localhost\r\n# fin\r\n10.0.0.1 web\r\n"
        );
    }

    #[test]
    fn unix_files_stay_unix_and_end_with_a_newline() {
        let read = HostsText::from_bytes(b"127.0.0.1 localhost");

        assert_eq!(read.line_ending, LineEnding::Lf);
        assert_eq!(read.to_bytes(), b"127.0.0.1 localhost\n");
        assert_eq!(HostsText::from_bytes(b"").to_bytes(), b"");
    }

    #[test]
    fn backups_are_named_by_date_and_recognized() {
        let when = NaiveDate::from_ymd_opt(2026, 11, 19)
            .unwrap()
            .and_hms_opt(8, 5, 3)
            .unwrap();

        let name = backup_name(when);

        assert_eq!(name, "hosts-20261119-080503");
        assert_eq!(backup_date(&name), Some(when));
        assert_eq!(backup_date("hosts"), None);
        assert_eq!(backup_date("vault.json"), None);
    }
}
