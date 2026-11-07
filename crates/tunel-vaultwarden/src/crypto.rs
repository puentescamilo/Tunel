//! El cifrado de Bitwarden, que es el que usan Vaultwarden y todos sus clientes.
//!
//! - La contraseña maestra da la **clave maestra** (PBKDF2 o Argon2id, con el correo como sal).
//!   De ella salen el hash con que se inicia sesión y, estirada con HKDF, la clave que descifra
//!   la **clave de usuario**.
//! - La clave de usuario (64 bytes: AES-256 y HMAC-SHA256) descifra los elementos personales y
//!   la clave privada RSA, que a su vez descifra la clave de cada organización.
//! - Cada valor cifrado viaja como un *EncString*: `2.iv|datos|mac` para AES o `4.datos` para
//!   RSA, en base64.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
const HALF: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("un valor cifrado no tiene el formato esperado")]
    Format,
    #[error("Túnel aún no sabe descifrar el formato {0} de Bitwarden")]
    Unsupported(String),
    #[error("un valor cifrado está alterado o no corresponde a esta clave")]
    Mac,
    #[error("no se pudo descifrar un valor")]
    Decrypt,
    #[error("una clave no tiene el tamaño o el formato esperado")]
    Key,
    #[error("parámetros de derivación de la contraseña no válidos")]
    Kdf,
}

/// Cómo deriva el servidor la clave maestra de esta cuenta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

/// Una clave simétrica de Bitwarden: 32 bytes para AES-256-CBC y 32 para HMAC-SHA256.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; HALF],
    mac: [u8; HALF],
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}

impl SymmetricKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 2 * HALF {
            return Err(CryptoError::Key);
        }
        let mut key = Self {
            enc: [0; HALF],
            mac: [0; HALF],
        };
        key.enc.copy_from_slice(&bytes[..HALF]);
        key.mac.copy_from_slice(&bytes[HALF..]);
        Ok(key)
    }

    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 2 * HALF]);
        rand::rng().fill_bytes(bytes.as_mut());
        Self::from_bytes(bytes.as_ref()).expect("64 bytes")
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new([self.enc, self.mac].concat())
    }

    fn mac(&self, iv: &[u8], data: &[u8]) -> Hmac<Sha256> {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&self.mac).expect("cualquier tamaño");
        mac.update(iv);
        mac.update(data);
        mac
    }
}

/// La clave maestra, derivada de la contraseña. Nunca sale del equipo.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; HALF]);

impl MasterKey {
    /// Deriva la clave maestra. Con Argon2id tarda y usa memoria: no llamar desde el hilo
    /// de la interfaz.
    pub fn derive(email: &str, password: &str, kdf: Kdf) -> Result<Self, CryptoError> {
        let email = normalize_email(email);
        let mut key = Self([0; HALF]);
        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                if iterations == 0 {
                    return Err(CryptoError::Kdf);
                }
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password.as_bytes(),
                    email.as_bytes(),
                    iterations,
                    &mut key.0,
                );
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let memory_kib = memory_mib.checked_mul(1024).ok_or(CryptoError::Kdf)?;
                let params = argon2::Params::new(memory_kib, iterations, parallelism, Some(HALF))
                    .map_err(|_| CryptoError::Kdf)?;
                let salt = Sha256::digest(email.as_bytes());
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt, &mut key.0)
                    .map_err(|_| CryptoError::Kdf)?;
            }
        }
        Ok(key)
    }

    /// Lo que se manda al servidor para iniciar sesión: no permite descifrar nada.
    pub fn password_hash(&self, password: &str) -> Zeroizing<String> {
        let mut hash = Zeroizing::new([0u8; HALF]);
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.0, password.as_bytes(), 1, hash.as_mut());
        Zeroizing::new(B64.encode(hash.as_ref()))
    }

    /// La clave que descifra la clave de usuario.
    pub fn stretch(&self) -> SymmetricKey {
        let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&self.0).expect("32 bytes es una PRK válida");
        let mut key = SymmetricKey {
            enc: [0; HALF],
            mac: [0; HALF],
        };
        hkdf.expand(b"enc", &mut key.enc).expect("32 bytes");
        hkdf.expand(b"mac", &mut key.mac).expect("32 bytes");
        key
    }
}

/// Bitwarden usa el correo sin espacios alrededor y en minúsculas como sal.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// La clave privada RSA de la cuenta, que descifra las claves de las organizaciones.
pub struct PrivateKey(RsaPrivateKey);

impl PrivateKey {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        RsaPrivateKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| CryptoError::Key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepHash {
    Sha1,
    Sha256,
}

/// Un valor cifrado tal como lo guarda Bitwarden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncString {
    /// Tipo 2: AES-256-CBC con HMAC-SHA256 sobre `iv || datos`.
    Aes {
        iv: [u8; IV_LEN],
        data: Vec<u8>,
        mac: [u8; MAC_LEN],
    },
    /// Tipos 3 a 6: RSA-2048 con OAEP. Los 5 y 6 añaden un HMAC que Bitwarden ya no usa.
    Rsa { hash: OaepHash, data: Vec<u8> },
}

fn base64(text: &str) -> Result<Vec<u8>, CryptoError> {
    B64.decode(text).map_err(|_| CryptoError::Format)
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(text: &str) -> Result<Self, CryptoError> {
        let (kind, body) = text.split_once('.').ok_or(CryptoError::Format)?;
        let parts: Vec<&str> = body.split('|').collect();
        match kind {
            "2" => {
                let [iv, data, mac] = parts[..] else {
                    return Err(CryptoError::Format);
                };
                Ok(Self::Aes {
                    iv: base64(iv)?.try_into().map_err(|_| CryptoError::Format)?,
                    data: base64(data)?,
                    mac: base64(mac)?.try_into().map_err(|_| CryptoError::Format)?,
                })
            }
            "3" | "4" | "5" | "6" => {
                let hash = if matches!(kind, "3" | "5") {
                    OaepHash::Sha256
                } else {
                    OaepHash::Sha1
                };
                Ok(Self::Rsa {
                    hash,
                    data: base64(parts[0])?,
                })
            }
            // El 0 y el 1 son AES sin MAC o con clave de 128 bits: formatos antiguos e
            // inseguros que no se aceptan. El 7 en adelante son los formatos nuevos (COSE).
            other => Err(CryptoError::Unsupported(other.chars().take(4).collect())),
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes { iv, data, mac } => write!(
                f,
                "2.{}|{}|{}",
                B64.encode(iv),
                B64.encode(data),
                B64.encode(mac)
            ),
            Self::Rsa { hash, data } => {
                let kind = match hash {
                    OaepHash::Sha256 => 3,
                    OaepHash::Sha1 => 4,
                };
                write!(f, "{kind}.{}", B64.encode(data))
            }
        }
    }
}

impl EncString {
    pub fn encrypt(key: &SymmetricKey, plain: &[u8]) -> Self {
        let mut iv = [0u8; IV_LEN];
        rand::rng().fill_bytes(&mut iv);
        let data = cbc::Encryptor::<Aes256>::new(&key.enc.into(), &iv.into())
            .encrypt_padded_vec::<Pkcs7>(plain);
        let mac = key.mac(&iv, &data).finalize().into_bytes().into();
        Self::Aes { iv, data, mac }
    }

    /// Descifra con una clave simétrica. Comprueba el MAC, en tiempo constante, antes de
    /// tocar los datos.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let Self::Aes { iv, data, mac } = self else {
            return Err(CryptoError::Format);
        };
        key.mac(iv, data)
            .verify_slice(mac)
            .map_err(|_| CryptoError::Mac)?;
        cbc::Decryptor::<Aes256>::new(&key.enc.into(), iv.into())
            .decrypt_padded_vec::<Pkcs7>(data)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }

    pub fn decrypt_text(&self, key: &SymmetricKey) -> Result<String, CryptoError> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CryptoError::Decrypt)
    }

    /// Descifra con la clave privada (las claves de las organizaciones).
    pub fn decrypt_rsa(&self, key: &PrivateKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let Self::Rsa { hash, data } = self else {
            return Err(CryptoError::Format);
        };
        let plain = match hash {
            OaepHash::Sha1 => key.0.decrypt(Oaep::<sha1::Sha1>::new(), data),
            OaepHash::Sha256 => key.0.decrypt(Oaep::<Sha256>::new(), data),
        };
        plain.map(Zeroizing::new).map_err(|_| CryptoError::Decrypt)
    }
}

/// Descifra un texto opcional de un elemento: `None` si no hay valor.
pub fn open_text(value: Option<&str>, key: &SymmetricKey) -> Result<Option<String>, CryptoError> {
    value
        .filter(|v| !v.is_empty())
        .map(|v| v.parse::<EncString>()?.decrypt_text(key))
        .transpose()
}

/// Cifra un texto para mandarlo al servidor.
pub fn seal_text(value: &str, key: &SymmetricKey) -> String {
    EncString::encrypt(key, value.as_bytes()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectores calculados aparte con Python (hashlib) y OpenSSL.
    const EMAIL: &str = " Prueba@Ejemplo.com ";
    const PASSWORD: &str = "caballo correcto bateria grapa";
    const MASTER: &str = "872376a61eedff5cef83d00236074d1de2dec348fe75e89ce7c023caf632567a";
    const HASH: &str = "rsoOWzq9mQSjZwLiPAdM92LGkfyBqqRtk8ILuhEKX9c=";
    const ENC: &str = "df7ab594291fc2895b11854aa89e6677270540fd58a5c0dc6e04e6aca705a611";
    const MAC: &str = "b5537b5c8fa4b7d2e550bb2878f6b0cd75a5dc595267da64b57acd70ddf21e3a";
    const SEALED: &str = "2.AAECAwQFBgcICQoLDA0ODw==|1nxvq3l+pOAi/8EXWmdrs4CZ7/mZcN9iVPn8tNdUD90=|\
                          VMAVD8IaxetYc9qITKQrB06mGbefxFKyuMkTCqTNaLM=";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn master() -> MasterKey {
        MasterKey::derive(EMAIL, PASSWORD, Kdf::Pbkdf2 { iterations: 5000 }).unwrap()
    }

    fn stretched() -> SymmetricKey {
        SymmetricKey::from_bytes(&[hex(ENC), hex(MAC)].concat()).unwrap()
    }

    #[test]
    fn the_master_key_its_hash_and_the_stretched_key_match_bitwarden() {
        let master = master();
        assert_eq!(master.0.to_vec(), hex(MASTER));
        assert_eq!(master.password_hash(PASSWORD).as_str(), HASH);
        assert_eq!(master.stretch(), stretched());
    }

    #[test]
    fn argon2id_derives_a_different_key_from_the_same_password() {
        let kdf = Kdf::Argon2id {
            iterations: 1,
            memory_mib: 1,
            parallelism: 1,
        };
        let key = MasterKey::derive(EMAIL, PASSWORD, kdf).unwrap();
        assert_ne!(key.0.to_vec(), hex(MASTER));
        let again = MasterKey::derive("prueba@ejemplo.com", PASSWORD, kdf).unwrap();
        assert_eq!(
            key.0, again.0,
            "el correo se normaliza antes de usarlo como sal"
        );
    }

    #[test]
    fn impossible_kdf_parameters_are_an_error() {
        assert_eq!(
            MasterKey::derive(EMAIL, PASSWORD, Kdf::Pbkdf2 { iterations: 0 }).err(),
            Some(CryptoError::Kdf)
        );
        let huge = Kdf::Argon2id {
            iterations: 1,
            memory_mib: u32::MAX,
            parallelism: 1,
        };
        assert_eq!(
            MasterKey::derive(EMAIL, PASSWORD, huge).err(),
            Some(CryptoError::Kdf)
        );
    }

    #[test]
    fn a_value_sealed_elsewhere_opens_and_round_trips() {
        let value: EncString = SEALED.parse().unwrap();
        assert_eq!(value.to_string(), SEALED);
        assert_eq!(
            value.decrypt_text(&stretched()).unwrap(),
            "contraseña del switch"
        );

        let key = SymmetricKey::generate();
        let sealed = seal_text("enable123", &key);
        assert_eq!(
            open_text(Some(&sealed), &key).unwrap().as_deref(),
            Some("enable123")
        );
        assert_eq!(open_text(None, &key).unwrap(), None);
        assert_eq!(open_text(Some(""), &key).unwrap(), None);
    }

    #[test]
    fn altered_values_or_other_keys_are_rejected_before_decrypting() {
        let EncString::Aes { iv, mut data, mac } = SEALED.parse().unwrap() else {
            unreachable!()
        };
        data[0] ^= 1;
        let altered = EncString::Aes { iv, data, mac };
        assert_eq!(altered.decrypt(&stretched()), Err(CryptoError::Mac));
        let other = SymmetricKey::generate();
        assert_eq!(
            SEALED.parse::<EncString>().unwrap().decrypt(&other),
            Err(CryptoError::Mac)
        );
    }

    #[test]
    fn old_insecure_and_new_unknown_formats_are_explicit_errors() {
        assert_eq!(
            "0.AAAA|AAAA".parse::<EncString>(),
            Err(CryptoError::Unsupported("0".into()))
        );
        assert_eq!(
            "7.AAAA".parse::<EncString>(),
            Err(CryptoError::Unsupported("7".into()))
        );
        for broken in [
            "",
            "2",
            "2.AAAA",
            "2.@@|AA|AA",
            "2.AAECAwQFBgcICQoLDA0ODw==|AA==|AA==",
        ] {
            assert_eq!(
                broken.parse::<EncString>(),
                Err(CryptoError::Format),
                "{broken}"
            );
        }
    }

    #[test]
    fn organization_keys_open_with_the_private_key() {
        // Clave RSA y claves de organización (0..64) cifradas aparte con OpenSSL.
        let key = PrivateKey::from_pkcs8_der(include_bytes!("../testdata/rsa-prueba.der")).unwrap();
        let expected: Vec<u8> = (0..64).collect();
        for sealed in [
            include_str!("../testdata/clave-org-sha1.txt"),
            include_str!("../testdata/clave-org-sha256.txt"),
        ] {
            let value: EncString = sealed.trim().parse().unwrap();
            assert_eq!(value.decrypt_rsa(&key).unwrap().to_vec(), expected);
        }
        let symmetric: EncString = SEALED.parse().unwrap();
        assert_eq!(symmetric.decrypt_rsa(&key), Err(CryptoError::Format));
        assert!(PrivateKey::from_pkcs8_der(b"no es una clave").is_err());
    }

    #[test]
    fn keys_must_have_sixty_four_bytes() {
        assert_eq!(SymmetricKey::from_bytes(&[0; 32]), Err(CryptoError::Key));
        let key = SymmetricKey::generate();
        assert_eq!(SymmetricKey::from_bytes(&key.to_bytes()).unwrap(), key);
        assert_eq!(format!("{key:?}"), "SymmetricKey(..)");
    }
}
