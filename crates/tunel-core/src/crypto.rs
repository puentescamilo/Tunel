//! Cifrado de la bóveda: Argon2id para derivar la clave y XChaCha20-Poly1305 para sellar.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

/// Parámetros de Argon2id guardados junto al texto cifrado para poder subirlos en el futuro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Recomendación OWASP para Argon2id (64 MiB, 3 pasadas).
    pub const RECOMMENDED: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };
    /// Parámetros baratos, solo para tests.
    pub const FAST_FOR_TESTS: Self = Self {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("parámetros de derivación de clave no válidos")]
    InvalidKdfParams,
    #[error("contraseña incorrecta o datos dañados")]
    Decryption,
    #[error("longitud de nonce o sal no válida")]
    InvalidLength,
    #[error("no se pudo cifrar")]
    Encryption,
}

/// Clave derivada; se borra de la memoria al soltarse.
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    pub fn derive(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Self, CryptoError> {
        let argon_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::InvalidKdfParams)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon
            .hash_password_into(password, salt, key.as_mut())
            .map_err(|_| CryptoError::InvalidKdfParams)?;
        Ok(Self(key))
    }

    /// Clave aleatoria, para las que no salen de una contraseña.
    pub fn random() -> Self {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rand::rng().fill_bytes(key.as_mut());
        Self(key)
    }

    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.0.as_ref()).expect("la clave siempre mide KEY_LEN")
    }
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Resultado de sellar: nonce aleatorio + texto cifrado con etiqueta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn seal(key: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    let nonce = XNonce::generate();
    let ciphertext = key
        .cipher()
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce.as_slice());
    Ok(Sealed {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn open(
    key: &MasterKey,
    sealed: &Sealed,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce = XNonce::try_from(&sealed.nonce[..]).map_err(|_| CryptoError::InvalidLength)?;
    key.cipher()
        .decrypt(
            &nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(password: &str, salt: &[u8]) -> MasterKey {
        MasterKey::derive(password.as_bytes(), salt, KdfParams::FAST_FOR_TESTS).unwrap()
    }

    #[test]
    fn seal_then_open_returns_original_plaintext() {
        let salt = random_salt();
        let k = key("correcta", &salt);
        let sealed = seal(&k, b"secreto", b"v1").unwrap();
        assert_eq!(open(&k, &sealed, b"v1").unwrap().as_slice(), b"secreto");
    }

    #[test]
    fn open_fails_with_wrong_password() {
        let salt = random_salt();
        let sealed = seal(&key("correcta", &salt), b"secreto", b"").unwrap();
        assert_eq!(
            open(&key("otra", &salt), &sealed, b"").unwrap_err(),
            CryptoError::Decryption
        );
    }

    #[test]
    fn open_fails_when_aad_differs() {
        let salt = random_salt();
        let k = key("pw", &salt);
        let sealed = seal(&k, b"x", b"v1").unwrap();
        assert_eq!(
            open(&k, &sealed, b"v2").unwrap_err(),
            CryptoError::Decryption
        );
    }

    #[test]
    fn open_fails_when_ciphertext_is_tampered() {
        let salt = random_salt();
        let k = key("pw", &salt);
        let mut sealed = seal(&k, b"datos", b"").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert_eq!(open(&k, &sealed, b"").unwrap_err(), CryptoError::Decryption);
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let salt = random_salt();
        let k = key("pw", &salt);
        let a = seal(&k, b"x", b"").unwrap();
        let b = seal(&k, b"x", b"").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn derive_rejects_invalid_params() {
        let bad = KdfParams {
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
        };
        assert!(matches!(
            MasterKey::derive(b"pw", &random_salt(), bad),
            Err(CryptoError::InvalidKdfParams)
        ));
    }
}
