//! Variables en los snippets: `systemctl restart {{servicio}}` pide el valor de
//! `servicio` antes de enviarlo.

use std::collections::BTreeMap;

/// Largo máximo del nombre de una variable.
pub const MAX_NAME_CHARS: usize = 40;

/// Busca el siguiente `{{nombre}}` desde `from`: devuelve dónde empieza, dónde acaba
/// (después de `}}`) y el nombre sin espacios a los lados. Lo que no es un nombre válido
/// (vacío, demasiado largo o con caracteres raros) se deja como texto.
fn next_variable(script: &str, from: usize) -> Option<(usize, usize, &str)> {
    let mut search = from;
    while let Some(offset) = script[search..].find("{{") {
        let start = search + offset;
        let inner_start = start + 2;
        let close = script[inner_start..].find("}}")?;
        let inner = &script[inner_start..inner_start + close];
        let name = inner.trim();
        let valid = !name.is_empty()
            && name.chars().count() <= MAX_NAME_CHARS
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '));
        if valid {
            return Some((start, inner_start + close + 2, name));
        }
        search = start + 1;
    }
    None
}

/// Nombres de las variables de `script`, sin repetir y en el orden en que aparecen.
pub fn variables(script: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some((_, end, name)) = next_variable(script, from) {
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
        from = end;
    }
    names
}

/// Quita del valor los caracteres de control: un salto de línea dentro de un valor
/// ejecutaría el comando antes de tiempo.
pub fn clean_value(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

/// `script` con cada variable sustituida por su valor. Las que no tienen valor se dejan
/// como están.
pub fn fill(script: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(script.len());
    let mut from = 0;
    while let Some((start, end, name)) = next_variable(script, from) {
        out.push_str(&script[from..start]);
        match values.get(name) {
            Some(value) => out.push_str(&clean_value(value)),
            None => out.push_str(&script[start..end]),
        }
        from = end;
    }
    out.push_str(&script[from..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn variables_are_found_once_in_order() {
        let script = "systemctl restart {{servicio}}\njournalctl -u {{ servicio }} -n {{líneas}}";
        assert_eq!(variables(script), ["servicio", "líneas"]);
        assert!(variables("echo hola").is_empty());
    }

    #[test]
    fn things_that_are_not_variables_stay_as_text() {
        for script in [
            "echo {{}}",
            "echo {{ }}",
            "awk '{{print $1}}'",
            "echo {{sin cerrar",
            "{{ {} }}",
        ] {
            assert!(variables(script).is_empty(), "{script}");
            assert_eq!(fill(script, &values(&[])), script);
        }
        let long = format!("{{{{{}}}}}", "a".repeat(MAX_NAME_CHARS + 1));
        assert!(variables(&long).is_empty());
    }

    #[test]
    fn values_replace_every_occurrence_and_lose_control_characters() {
        let script = "systemctl restart {{servicio}} && systemctl status {{ servicio }}";
        assert_eq!(
            fill(script, &values(&[("servicio", "nginx\nreboot\r")])),
            "systemctl restart nginxreboot && systemctl status nginxreboot"
        );
        assert_eq!(
            fill("{{a}} {{b}}", &values(&[("a", "1")])),
            "1 {{b}}",
            "sin valor se deja como está"
        );
    }

    #[test]
    fn a_brace_inside_text_does_not_hide_a_later_variable() {
        let script = "echo '{{ no-vale! }}' {{nombre}}";
        assert_eq!(variables(script), ["nombre"]);
        assert_eq!(
            fill(script, &values(&[("nombre", "ana")])),
            "echo '{{ no-vale! }}' ana"
        );
    }
}
