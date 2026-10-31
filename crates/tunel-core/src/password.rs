//! Reglas de la contraseña maestra. Con una cuenta de proveedor de identidad (Google,
//! Microsoft 365…) la sincronización se cifra con ella, así que tiene que resistir que
//! alguien con una copia del servidor pruebe contraseñas.

/// Mínimo de caracteres.
pub const MIN_LEN: usize = 12;

/// Lo que le falta a `password` para ser una contraseña maestra fuerte; vacío si cumple
/// todo: al menos 12 caracteres, con mayúsculas, minúsculas, números y algún carácter
/// especial.
pub fn problems(password: &str) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if password.chars().count() < MIN_LEN {
        missing.push("al menos 12 caracteres");
    }
    if !password.chars().any(char::is_uppercase) {
        missing.push("una mayúscula");
    }
    if !password.chars().any(char::is_lowercase) {
        missing.push("una minúscula");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        missing.push("un número");
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        missing.push("un carácter especial");
    }
    missing
}

pub fn is_strong(password: &str) -> bool {
    problems(password).is_empty()
}

/// Frase para la interfaz: «Le falta: una mayúscula y un número».
pub fn describe(missing: &[&str]) -> String {
    match missing {
        [] => String::new(),
        [only] => format!("Le falta {only}"),
        [rest @ .., last] => format!("Le falta {} y {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_passwords_pass() {
        for ok in ["Túnel-2026-segura", "Abcdefghij1!", "contraseÑa 1234"] {
            assert!(is_strong(ok), "{ok}");
        }
    }

    #[test]
    fn each_missing_rule_is_reported() {
        assert_eq!(problems("Ab1!"), vec!["al menos 12 caracteres"]);
        assert_eq!(problems("abcdefghij1!"), vec!["una mayúscula"]);
        assert_eq!(problems("ABCDEFGHIJ1!"), vec!["una minúscula"]);
        assert_eq!(problems("Abcdefghijk!"), vec!["un número"]);
        assert_eq!(problems("Abcdefghijk1"), vec!["un carácter especial"]);
        assert_eq!(problems("").len(), 5);
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // 11 caracteres, más de 12 bytes.
        assert!(!is_strong("Ññññññññ1!a"));
    }

    #[test]
    fn missing_rules_read_as_a_sentence() {
        assert_eq!(describe(&[]), "");
        assert_eq!(describe(&["un número"]), "Le falta un número");
        assert_eq!(
            describe(&["una mayúscula", "un número", "un carácter especial"]),
            "Le falta una mayúscula, un número y un carácter especial"
        );
    }
}
