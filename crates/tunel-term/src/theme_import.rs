//! Importación de esquemas de color de iTerm2 (`.itermcolors`) y Windows Terminal (JSON).

use crate::palette::Theme;
use std::collections::HashMap;

/// Tamaño máximo aceptado: los esquemas reales ocupan unos pocos KB.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("el archivo es demasiado grande para ser un tema")]
    TooLarge,
    #[error("formato no reconocido: usa un .itermcolors de iTerm2 o un .json de Windows Terminal")]
    UnknownFormat,
    #[error("falta el color «{0}»")]
    MissingColor(String),
    #[error("color no válido en «{0}»")]
    InvalidColor(String),
    #[error("el archivo no contiene ningún esquema de color")]
    Empty,
}

const ITERM_ANSI: [&str; 16] = [
    "Ansi 0 Color",
    "Ansi 1 Color",
    "Ansi 2 Color",
    "Ansi 3 Color",
    "Ansi 4 Color",
    "Ansi 5 Color",
    "Ansi 6 Color",
    "Ansi 7 Color",
    "Ansi 8 Color",
    "Ansi 9 Color",
    "Ansi 10 Color",
    "Ansi 11 Color",
    "Ansi 12 Color",
    "Ansi 13 Color",
    "Ansi 14 Color",
    "Ansi 15 Color",
];

const WT_ANSI: [&str; 16] = [
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "purple",
    "cyan",
    "white",
    "brightBlack",
    "brightRed",
    "brightGreen",
    "brightYellow",
    "brightBlue",
    "brightPurple",
    "brightCyan",
    "brightWhite",
];

fn component(value: f64) -> u8 {
    (value.clamp(0.0, 1.0) * 255.0).round() as u8
}

fn iterm_color(colors: &HashMap<String, plist::Value>, key: &str) -> Result<[u8; 3], ImportError> {
    let dict = colors
        .get(key)
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| ImportError::MissingColor(key.into()))?;
    let channel = |name: &str| {
        dict.get(name)
            .and_then(plist::Value::as_real)
            .map(component)
            .ok_or_else(|| ImportError::InvalidColor(key.into()))
    };
    Ok([
        channel("Red Component")?,
        channel("Green Component")?,
        channel("Blue Component")?,
    ])
}

/// Lee un `.itermcolors`. El nombre se toma del archivo, porque el formato no lo incluye.
pub fn parse_itermcolors(bytes: &[u8], name: &str) -> Result<Theme, ImportError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ImportError::TooLarge);
    }
    let colors: HashMap<String, plist::Value> =
        plist::from_bytes(bytes).map_err(|_| ImportError::UnknownFormat)?;
    let get = |key: &str| iterm_color(&colors, key);
    let mut ansi = [[0u8; 3]; 16];
    for (slot, key) in ansi.iter_mut().zip(ITERM_ANSI) {
        *slot = get(key)?;
    }
    let foreground = get("Foreground Color")?;
    let background = get("Background Color")?;
    Ok(Theme {
        id: Theme::custom_id(name),
        name: name.trim().to_string(),
        cursor: get("Cursor Color").unwrap_or(foreground),
        selection: get("Selection Color").unwrap_or(ansi[8]),
        foreground,
        background,
        ansi,
    })
}

/// `#RRGGBB` o `#RGB`.
pub fn parse_hex(text: &str) -> Option<[u8; 3]> {
    let hex = text.trim().strip_prefix('#')?;
    let expand = |s: &str| u8::from_str_radix(s, 16).ok();
    match hex.len() {
        6 => Some([
            expand(&hex[0..2])?,
            expand(&hex[2..4])?,
            expand(&hex[4..6])?,
        ]),
        3 => {
            let d = |i: usize| expand(&hex[i..=i].repeat(2));
            Some([d(0)?, d(1)?, d(2)?])
        }
        _ => None,
    }
}

fn wt_scheme(value: &serde_json::Value) -> Result<Theme, ImportError> {
    let color = |key: &str| -> Result<[u8; 3], ImportError> {
        let text = value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ImportError::MissingColor(key.into()))?;
        parse_hex(text).ok_or_else(|| ImportError::InvalidColor(key.into()))
    };
    let mut ansi = [[0u8; 3]; 16];
    for (slot, key) in ansi.iter_mut().zip(WT_ANSI) {
        *slot = color(key)?;
    }
    let foreground = color("foreground")?;
    let name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Tema importado");
    Ok(Theme {
        id: Theme::custom_id(name),
        name: name.trim().to_string(),
        foreground,
        background: color("background")?,
        cursor: color("cursorColor").unwrap_or(foreground),
        selection: color("selectionBackground").unwrap_or(ansi[8]),
        ansi,
    })
}

/// Lee un esquema de Windows Terminal, o todos los de un `settings.json` (clave `schemes`).
pub fn parse_windows_terminal(text: &str) -> Result<Vec<Theme>, ImportError> {
    if text.len() > MAX_FILE_BYTES {
        return Err(ImportError::TooLarge);
    }
    let json: serde_json::Value =
        serde_json::from_str(text).map_err(|_| ImportError::UnknownFormat)?;
    let schemes: Vec<&serde_json::Value> = match (&json, json.get("schemes")) {
        (_, Some(serde_json::Value::Array(list))) => list.iter().collect(),
        (serde_json::Value::Array(list), _) => list.iter().collect(),
        (serde_json::Value::Object(_), _) => vec![&json],
        _ => return Err(ImportError::UnknownFormat),
    };
    if schemes.is_empty() {
        return Err(ImportError::Empty);
    }
    schemes.into_iter().map(wt_scheme).collect()
}

/// Detecta el formato por extensión o contenido.
pub fn import(file_name: &str, bytes: &[u8]) -> Result<Vec<Theme>, ImportError> {
    let stem = std::path::Path::new(file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Tema importado");
    let looks_like_plist = file_name.ends_with(".itermcolors")
        || bytes.starts_with(b"<?xml")
        || bytes.starts_with(b"bplist");
    if looks_like_plist {
        return parse_itermcolors(bytes, stem).map(|t| vec![t]);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::UnknownFormat)?;
    parse_windows_terminal(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iterm_entry(key: &str, r: f64, g: f64, b: f64) -> String {
        format!(
            "<key>{key}</key><dict><key>Color Space</key><string>sRGB</string>\
             <key>Red Component</key><real>{r}</real><key>Green Component</key><real>{g}</real>\
             <key>Blue Component</key><real>{b}</real></dict>"
        )
    }

    fn iterm_file(skip: Option<&str>) -> String {
        let mut entries: Vec<String> = ITERM_ANSI
            .iter()
            .enumerate()
            .map(|(i, k)| iterm_entry(k, i as f64 / 15.0, 0.0, 0.0))
            .collect();
        entries.push(iterm_entry("Foreground Color", 1.0, 1.0, 1.0));
        entries.push(iterm_entry("Background Color", 0.0, 0.0, 0.2));
        entries.push(iterm_entry("Cursor Color", 0.5, 0.5, 0.5));
        let body: String = entries
            .into_iter()
            .filter(|e| skip.is_none_or(|s| !e.contains(s)))
            .collect();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>{body}</dict></plist>"#
        )
    }

    #[test]
    fn itermcolors_are_converted_to_rgb() {
        let theme = parse_itermcolors(iterm_file(None).as_bytes(), "Mi Tema").unwrap();
        assert_eq!(theme.id, "usuario:mi-tema");
        assert_eq!(theme.foreground, [255, 255, 255]);
        assert_eq!(theme.background, [0, 0, 51]);
        assert_eq!(theme.ansi[15], [255, 0, 0]);
        assert_eq!(theme.cursor, [128, 128, 128]);
        // Sin "Selection Color" se usa el negro brillante.
        assert_eq!(theme.selection, theme.ansi[8]);
    }

    #[test]
    fn itermcolors_missing_ansi_color_is_reported() {
        let err = parse_itermcolors(iterm_file(Some("Ansi 3 Color")).as_bytes(), "x").unwrap_err();
        assert_eq!(err, ImportError::MissingColor("Ansi 3 Color".into()));
    }

    fn wt_scheme_json(name: &str) -> String {
        let colors: Vec<String> = WT_ANSI
            .iter()
            .map(|k| format!(r##""{k}": "#112233""##))
            .collect();
        format!(
            r##"{{"name": "{name}", "foreground": "#FFFFFF", "background": "#000", "cursorColor": "#ff0000", {}}}"##,
            colors.join(",")
        )
    }

    #[test]
    fn windows_terminal_single_scheme() {
        let themes = parse_windows_terminal(&wt_scheme_json("Campbell")).unwrap();
        assert_eq!(themes.len(), 1);
        let t = &themes[0];
        assert_eq!(
            (t.name.as_str(), t.background, t.cursor),
            ("Campbell", [0, 0, 0], [255, 0, 0])
        );
        assert_eq!(t.ansi[9], [0x11, 0x22, 0x33]);
    }

    #[test]
    fn windows_terminal_settings_with_several_schemes() {
        let settings = format!(
            r#"{{"profiles": {{}}, "schemes": [{}, {}]}}"#,
            wt_scheme_json("Uno"),
            wt_scheme_json("Dos")
        );
        let names: Vec<String> = parse_windows_terminal(&settings)
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["Uno", "Dos"]);
    }

    #[test]
    fn invalid_inputs_are_rejected_with_clear_errors() {
        assert_eq!(
            parse_windows_terminal("no es json"),
            Err(ImportError::UnknownFormat)
        );
        assert_eq!(
            parse_windows_terminal(r#"{"schemes": []}"#),
            Err(ImportError::Empty)
        );
        let bad = wt_scheme_json("x").replace(r##""red": "#112233""##, r##""red": "rojo""##);
        assert_eq!(
            parse_windows_terminal(&bad),
            Err(ImportError::InvalidColor("red".into()))
        );
        assert_eq!(
            import("grande.json", &vec![b' '; MAX_FILE_BYTES + 1]),
            Err(ImportError::TooLarge)
        );
    }

    #[test]
    fn import_detects_format_by_name_and_content() {
        assert_eq!(
            import("Solar.itermcolors", iterm_file(None).as_bytes()).unwrap()[0].name,
            "Solar"
        );
        assert_eq!(
            import("tema.json", wt_scheme_json("WT").as_bytes()).unwrap()[0].name,
            "WT"
        );
    }

    #[test]
    fn hex_parsing_accepts_long_and_short_forms() {
        assert_eq!(parse_hex("#0a0B0c"), Some([10, 11, 12]));
        assert_eq!(parse_hex("#fff"), Some([255, 255, 255]));
        assert_eq!(parse_hex("fff"), None);
        assert_eq!(parse_hex("#12345"), None);
    }
}
