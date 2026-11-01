//! Claves SSH nuevas, en el formato de OpenSSH, y la clave pública de una que ya existe.

use russh::keys::decode_secret_key;
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};

/// Tipos de clave que se pueden generar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    #[default]
    Ed25519,
    /// Con la curva NIST P-256, la que usa `ssh-keygen` por defecto.
    Ecdsa,
    /// De 4096 bits.
    Rsa,
}

impl KeyType {
    pub const ALL: [KeyType; 3] = [KeyType::Ed25519, KeyType::Ecdsa, KeyType::Rsa];

    pub fn label(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "Ed25519 (recomendada)",
            KeyType::Ecdsa => "ECDSA P-256",
            KeyType::Rsa => "RSA de 4096 bits",
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            KeyType::Ed25519 => Algorithm::Ed25519,
            KeyType::Ecdsa => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            KeyType::Rsa => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        }
    }
}

/// Una clave recién generada: la privada, cifrada si se dio frase de paso, y la pública
/// en una línea, lista para `authorized_keys`.
pub struct GeneratedKey {
    pub private_key: String,
    pub public_key: String,
}

impl std::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("No se pudo generar la clave: {0}")]
pub struct KeygenError(String);

fn failed(e: impl std::fmt::Display) -> KeygenError {
    KeygenError(e.to_string())
}

/// Genera una clave de tipo `kind` con el comentario `comment`. Con `passphrase`, la
/// privada va cifrada con ella, como `ssh-keygen -N`. Una RSA tarda unos segundos: mejor
/// llamarla fuera del hilo de la interfaz.
pub fn generate(
    kind: KeyType,
    comment: &str,
    passphrase: Option<&str>,
) -> Result<GeneratedKey, KeygenError> {
    let mut rng = rand10::rng();
    let mut key = PrivateKey::random(&mut rng, kind.algorithm()).map_err(failed)?;
    key.set_comment(comment);
    let public_key = key.public_key().to_openssh().map_err(failed)?;
    let key = match passphrase.filter(|p| !p.is_empty()) {
        Some(passphrase) => key.encrypt(&mut rng, passphrase).map_err(failed)?,
        None => key,
    };
    let private_key = key.to_openssh(LineEnding::LF).map_err(failed)?;
    Ok(GeneratedKey {
        private_key: private_key.to_string(),
        public_key,
    })
}

/// La clave pública de `private_key`, en una línea. Las de OpenSSH la llevan a la vista,
/// aunque estén cifradas (entonces sin el comentario); las PEM hay que descifrarlas con
/// `passphrase`.
pub fn public_key(private_key: &str, passphrase: Option<&str>) -> Option<String> {
    let text = private_key.trim();
    let public = match PrivateKey::from_openssh(text) {
        Ok(key) => key.public_key().clone(),
        Err(_) => decode_secret_key(text, passphrase)
            .ok()?
            .public_key()
            .clone(),
    };
    public.to_openssh().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_needs_its_passphrase() {
        let key = generate(KeyType::Ed25519, "ana@portatil", Some("secreta")).unwrap();
        assert!(key.public_key.starts_with("ssh-ed25519 "));
        assert!(key.public_key.ends_with(" ana@portatil"));
        assert!(decode_secret_key(&key.private_key, None).is_err());
        let decoded = decode_secret_key(&key.private_key, Some("secreta")).unwrap();
        assert_eq!(decoded.public_key().to_openssh().unwrap(), key.public_key);
        // Cifrada, el comentario va dentro: a la vista solo queda la clave.
        let visible = public_key(&key.private_key, None).unwrap();
        assert!(key.public_key.starts_with(&format!("{visible} ")));
    }

    #[test]
    fn without_passphrase_the_key_is_left_in_clear() {
        for passphrase in [None, Some("")] {
            let key = generate(KeyType::Ecdsa, "", passphrase).unwrap();
            assert!(key.public_key.starts_with("ecdsa-sha2-nistp256 "));
            assert!(decode_secret_key(&key.private_key, None).is_ok());
        }
    }

    #[test]
    fn rsa_keys_have_4096_bits() {
        let key = generate(KeyType::Rsa, "", None).unwrap();
        let decoded = decode_secret_key(&key.private_key, None).unwrap();
        let rsa = decoded.key_data().rsa().unwrap();
        assert_eq!(rsa.public().key_size(), 4096);
        assert!(key.public_key.starts_with("ssh-rsa "));
    }

    #[test]
    fn the_public_key_is_read_from_the_private_one() {
        let key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519).unwrap();
        let openssh = key.to_openssh(LineEnding::LF).unwrap();
        assert!(public_key(&openssh, None).is_some());
        assert_eq!(public_key("no es una clave", None), None);
    }
}
