//! Llaves de seguridad FIDO2 (claves `sk-ssh-ed25519` y `sk-ecdsa-sha2-nistp256` de OpenSSH).
//!
//! El archivo de la clave solo guarda el identificador de la credencial: la firma la hace la
//! llave física. Igual que OpenSSH, se le pide una aserción con el hash SHA-256 del mensaje
//! como `clientDataHash`, y su respuesta se convierte al formato de firma `sk-*` de SSH.

use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::{Algorithm, Signature};
use russh::keys::{PrivateKey, PublicKey};
use std::sync::Arc;

/// La llave debe comprobar que hay alguien delante (tocarla).
pub const FLAG_USER_PRESENCE: u8 = 0x01;
/// La llave debe verificar al usuario (PIN o biometría).
pub const FLAG_USER_VERIFICATION: u8 = 0x04;
/// `authData` = hash del RP (32) + flags (1) + contador (4).
const AUTH_DATA_MIN_LEN: usize = 37;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FidoError {
    #[error("no se encontró ninguna llave de seguridad conectada")]
    NoDevice,
    #[error("la llave de seguridad no firmó: {0}")]
    Device(String),
    #[error("respuesta de la llave de seguridad no válida")]
    BadResponse,
    #[error("la llave de seguridad pide un PIN y no se introdujo")]
    PinRequired,
    #[error("las llaves de seguridad FIDO2 aún no funcionan en este sistema; usa el agente SSH")]
    Unsupported,
}

/// Tipo de clave `sk-*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkAlgorithm {
    Ed25519,
    EcdsaP256,
}

/// Lo que se necesita de una clave `sk-*` para pedir una firma a la llave.
#[derive(Debug, Clone)]
pub struct SkKey {
    pub algorithm: SkAlgorithm,
    /// Identificador de la aplicación (RP ID); casi siempre `ssh:`.
    pub application: String,
    pub key_handle: Vec<u8>,
    pub flags: u8,
    pub public: PublicKey,
}

impl SkKey {
    /// `None` si la clave no es de una llave de seguridad.
    pub fn from_private(private: &PrivateKey) -> Option<Self> {
        let (algorithm, application, key_handle, flags) = match private.key_data() {
            KeypairData::SkEd25519(k) => (
                SkAlgorithm::Ed25519,
                k.public().application(),
                k.key_handle(),
                k.flags(),
            ),
            KeypairData::SkEcdsaSha2NistP256(k) => (
                SkAlgorithm::EcdsaP256,
                k.public().application(),
                k.key_handle(),
                k.flags(),
            ),
            _ => return None,
        };
        Some(Self {
            algorithm,
            application: application.to_string(),
            key_handle: key_handle.to_vec(),
            flags,
            public: private.public_key().clone(),
        })
    }

    pub fn needs_touch(&self) -> bool {
        self.flags & FLAG_USER_PRESENCE != 0
    }

    pub fn needs_pin(&self) -> bool {
        self.flags & FLAG_USER_VERIFICATION != 0
    }
}

/// Si el texto es una clave privada OpenSSH de llave de seguridad. Funciona también con claves
/// cifradas, porque el tipo va en la parte pública del archivo.
pub fn is_security_key(private_key: &str) -> bool {
    PrivateKey::from_openssh(private_key.trim()).is_ok_and(|key| {
        matches!(
            key.algorithm(),
            Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
        )
    })
}

/// Petición de firma a la llave.
pub struct AssertionRequest<'a> {
    pub application: &'a str,
    /// Mensaje a firmar; la llave firma su SHA-256 (el `clientDataHash`).
    pub message: &'a [u8],
    pub key_handle: &'a [u8],
    pub user_presence: bool,
    pub pin: Option<&'a str>,
}

/// Respuesta de la llave: `authData` en bruto y la firma (Ed25519 en bruto, ECDSA en DER).
pub struct Assertion {
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Una llave de seguridad. Las llamadas bloquean hasta que el usuario la toca.
pub trait Authenticator: Send + Sync {
    fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, FidoError>;
}

/// Firma SSH codificada (`string alg, string firma, byte flags, uint32 contador`).
pub fn encode_signature(key: &SkKey, assertion: &Assertion) -> Result<Vec<u8>, FidoError> {
    let auth = &assertion.auth_data;
    if auth.len() < AUTH_DATA_MIN_LEN {
        return Err(FidoError::BadResponse);
    }
    let flags_and_counter = &auth[32..AUTH_DATA_MIN_LEN];
    let (algorithm, mut data) = match key.algorithm {
        SkAlgorithm::Ed25519 if assertion.signature.len() == ED25519_SIGNATURE_LEN => {
            (Algorithm::SkEd25519, assertion.signature.clone())
        }
        SkAlgorithm::Ed25519 => return Err(FidoError::BadResponse),
        SkAlgorithm::EcdsaP256 => (
            Algorithm::SkEcdsaSha2NistP256,
            der_to_ssh_ecdsa(&assertion.signature)?,
        ),
    };
    data.extend_from_slice(flags_and_counter);
    let signature = Signature::new(algorithm, data).map_err(|_| FidoError::BadResponse)?;
    signature.encode_vec().map_err(|_| FidoError::BadResponse)
}

/// `SEQUENCE { INTEGER r, INTEGER s }` en DER → `mpint r, mpint s` de SSH.
fn der_to_ssh_ecdsa(der: &[u8]) -> Result<Vec<u8>, FidoError> {
    let bad = || FidoError::BadResponse;
    let (tag, body, rest) = der_element(der).ok_or_else(bad)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(bad());
    }
    let (r_tag, r, after_r) = der_element(body).ok_or_else(bad)?;
    let (s_tag, s, after_s) = der_element(after_r).ok_or_else(bad)?;
    if r_tag != 0x02 || s_tag != 0x02 || !after_s.is_empty() {
        return Err(bad());
    }
    let mut out = Vec::new();
    for value in [r, s] {
        out.extend_from_slice(&ssh_mpint(value));
    }
    Ok(out)
}

/// (etiqueta, contenido, resto). Solo longitudes cortas o de un byte, que bastan para P-256.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (usize::from(len), rest)
        }
        _ => return None,
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Entero positivo como `mpint`: sin ceros sobrantes y con un 0 delante si el bit alto es 1.
fn ssh_mpint(value: &[u8]) -> Vec<u8> {
    let trimmed = match value.iter().position(|&b| b != 0) {
        Some(start) => &value[start..],
        None => &[],
    };
    let needs_zero = trimmed.first().is_some_and(|&b| b & 0x80 != 0);
    let len = trimmed.len() + usize::from(needs_zero);
    let mut out = (len as u32).to_be_bytes().to_vec();
    if needs_zero {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
    out
}

/// Firma de autenticación SSH hecha por una llave de seguridad.
pub struct SkSigner {
    pub key: SkKey,
    pub authenticator: Arc<dyn Authenticator>,
    pub pin: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SkSignError {
    #[error(transparent)]
    Fido(#[from] FidoError),
    #[error("la conexión se cerró mientras se firmaba")]
    Send(#[from] russh::SendError),
}

impl russh::Signer for SkSigner {
    type Error = SkSignError;

    #[allow(clippy::manual_async_fn)]
    fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<russh::keys::HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = self.key.clone();
        let authenticator = self.authenticator.clone();
        let pin = self.pin.clone();
        async move {
            // La llave bloquea hasta que la tocan: fuera del hilo del runtime.
            let (to_sign, assertion) = tokio::task::spawn_blocking(move || {
                let request = AssertionRequest {
                    application: &key.application,
                    message: &to_sign,
                    key_handle: &key.key_handle,
                    user_presence: key.needs_touch(),
                    pin: pin.as_deref(),
                };
                let assertion = authenticator.get_assertion(&request);
                (to_sign, assertion.map(|a| (key, a)))
            })
            .await
            .map_err(|e| FidoError::Device(e.to_string()))?;
            let (key, assertion) = assertion?;
            let blob = encode_signature(&key, &assertion)?;
            // Igual que el agente: el mensaje seguido de la firma como `string`.
            let mut signed = to_sign;
            blob.encode(&mut signed)
                .map_err(|_| FidoError::BadResponse)?;
            Ok(signed)
        }
    }
}

/// Llave de seguridad conectada por USB (CTAP2 sobre HID).
#[cfg(not(windows))]
pub struct UsbAuthenticator;

#[cfg(not(windows))]
impl Authenticator for UsbAuthenticator {
    fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, FidoError> {
        use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
        if ctap_hid_fido2::get_fidokey_devices().is_empty() {
            return Err(FidoError::NoDevice);
        }
        let device = ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
            .map_err(|e| FidoError::Device(e.to_string()))?;
        let builder = GetAssertionArgsBuilder::new(request.application, request.message)
            .credential_id(request.key_handle);
        let builder = match request.pin {
            Some(pin) => builder.pin(pin),
            None => builder.without_pin_and_uv(),
        };
        let builder = if request.user_presence {
            builder
        } else {
            builder.without_up()
        };
        let assertion = device
            .get_assertion_with_args(&builder.build())
            .map_err(|e| FidoError::Device(e.to_string()))?
            .into_iter()
            .next()
            .ok_or(FidoError::BadResponse)?;
        Ok(Assertion {
            auth_data: assertion.auth_data,
            signature: assertion.signature,
        })
    }
}

/// La llave del sistema, si este sistema la admite.
pub fn system_authenticator() -> Result<Arc<dyn Authenticator>, FidoError> {
    #[cfg(not(windows))]
    {
        Ok(Arc::new(UsbAuthenticator))
    }
    #[cfg(windows)]
    {
        Err(FidoError::Unsupported)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Llave de seguridad simulada que firma como una real.

    use super::*;
    use russh::keys::ssh_key::private::{self, KeypairData};
    use russh::keys::ssh_key::public;
    use sha2::{Digest, Sha256};

    pub const APPLICATION: &str = "ssh:";

    pub struct SoftKey {
        pub signing: ed25519_dalek::SigningKey,
        pub key_handle: Vec<u8>,
        pub counter: u32,
    }

    impl SoftKey {
        pub fn new(seed: u8) -> Self {
            Self {
                signing: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
                key_handle: vec![seed; 48],
                counter: 41,
            }
        }

        /// Clave privada `sk-ssh-ed25519` como la que genera `ssh-keygen -t ed25519-sk`.
        pub fn private_key(&self, flags: u8) -> PrivateKey {
            let verifying = self.signing.verifying_key().to_bytes();
            let public = public::SkEd25519::new(public::Ed25519PublicKey(verifying), APPLICATION);
            let keypair = private::SkEd25519::new(public, flags, self.key_handle.clone()).unwrap();
            PrivateKey::new(KeypairData::SkEd25519(keypair), "llave de prueba").unwrap()
        }
    }

    impl Authenticator for SoftKey {
        fn get_assertion(&self, request: &AssertionRequest) -> Result<Assertion, FidoError> {
            use ed25519_dalek::Signer as _;
            if request.key_handle != self.key_handle {
                return Err(FidoError::Device("credencial desconocida".into()));
            }
            let flags = if request.user_presence { 0x01 } else { 0x00 };
            let mut auth_data = Sha256::digest(request.application.as_bytes()).to_vec();
            auth_data.push(flags);
            auth_data.extend_from_slice(&self.counter.to_be_bytes());
            let client_data_hash = Sha256::digest(request.message);
            let signed = [auth_data.as_slice(), client_data_hash.as_slice()].concat();
            Ok(Assertion {
                auth_data,
                signature: self.signing.sign(&signed).to_bytes().to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use russh::keys::signature::Verifier;
    use russh::keys::ssh_encoding::Decode;

    #[test]
    fn sk_key_is_recognised_with_its_flags() {
        let soft = SoftKey::new(3);
        let key = SkKey::from_private(&soft.private_key(FLAG_USER_PRESENCE)).unwrap();
        assert_eq!(key.algorithm, SkAlgorithm::Ed25519);
        assert_eq!(key.application, APPLICATION);
        assert_eq!(key.key_handle, soft.key_handle);
        assert!(key.needs_touch() && !key.needs_pin());
        let pin_key = SkKey::from_private(&soft.private_key(FLAG_USER_VERIFICATION)).unwrap();
        assert!(!pin_key.needs_touch() && pin_key.needs_pin());
    }

    #[test]
    fn ordinary_keys_are_not_security_keys() {
        let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]);
        let key = PrivateKey::from(keypair);
        assert!(SkKey::from_private(&key).is_none());
        let text = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        assert!(!is_security_key(&text));
    }

    #[test]
    fn security_key_files_are_detected() {
        let text = SoftKey::new(2)
            .private_key(FLAG_USER_PRESENCE)
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        assert!(is_security_key(&text));
        assert!(!is_security_key("no es una clave"));
    }

    #[test]
    fn signature_from_soft_key_verifies_as_openssh_would() {
        let soft = SoftKey::new(5);
        let key = SkKey::from_private(&soft.private_key(FLAG_USER_PRESENCE)).unwrap();
        let message = b"datos de autenticacion";
        let request = AssertionRequest {
            application: &key.application,
            message,
            key_handle: &key.key_handle,
            user_presence: true,
            pin: None,
        };
        let blob = encode_signature(&key, &soft.get_assertion(&request).unwrap()).unwrap();
        let signature = Signature::decode(&mut blob.as_slice()).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::SkEd25519);
        key.public.key_data().verify(message, &signature).unwrap();
        assert!(
            key.public
                .key_data()
                .verify(b"otro mensaje", &signature)
                .is_err()
        );
    }

    #[test]
    fn short_auth_data_or_signature_is_rejected() {
        let key = SkKey::from_private(&SoftKey::new(1).private_key(FLAG_USER_PRESENCE)).unwrap();
        let short = Assertion {
            auth_data: vec![0; 10],
            signature: vec![0; 64],
        };
        assert_eq!(encode_signature(&key, &short), Err(FidoError::BadResponse));
        let bad_sig = Assertion {
            auth_data: vec![0; 37],
            signature: vec![0; 10],
        };
        assert_eq!(
            encode_signature(&key, &bad_sig),
            Err(FidoError::BadResponse)
        );
    }

    #[test]
    fn der_ecdsa_signature_becomes_ssh_mpints() {
        // r con el bit alto (necesita 0 delante) y s con un cero sobrante.
        let r = [0x80u8; 32];
        let s = [0x00u8, 0x01, 0x02];
        let mut der = vec![0x30, (2 + 1 + r.len() + 2 + s.len()) as u8];
        der.extend_from_slice(&[0x02, 33, 0x00]);
        der.extend_from_slice(&r);
        der.extend_from_slice(&[0x02, s.len() as u8]);
        der.extend_from_slice(&s);
        let ssh = der_to_ssh_ecdsa(&der).unwrap();
        let mut expected = 33u32.to_be_bytes().to_vec();
        expected.push(0);
        expected.extend_from_slice(&r);
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&[0x01, 0x02]);
        assert_eq!(ssh, expected);
    }

    #[test]
    fn malformed_der_is_rejected() {
        for der in [
            &[][..],
            &[0x30],
            &[0x30, 0x05, 0x02],
            &[0x31, 0x00],
            &[0x30, 0x00, 0xff],
        ] {
            assert_eq!(
                der_to_ssh_ecdsa(der),
                Err(FidoError::BadResponse),
                "{der:?}"
            );
        }
    }

    #[tokio::test]
    async fn signer_appends_signature_like_the_agent() {
        use russh::Signer as _;
        let soft = Arc::new(SoftKey::new(9));
        let key = SkKey::from_private(&soft.private_key(FLAG_USER_PRESENCE)).unwrap();
        let identity = russh::keys::agent::AgentIdentity::PublicKey {
            key: key.public.clone(),
            comment: String::new(),
        };
        let mut signer = SkSigner {
            key: key.clone(),
            authenticator: soft,
            pin: None,
        };
        let message = b"sesion".to_vec();
        let signed = signer
            .auth_sign(&identity, None, message.clone())
            .await
            .unwrap();
        assert!(signed.starts_with(&message));
        let mut rest = &signed[message.len()..];
        let blob = Vec::<u8>::decode(&mut rest).unwrap();
        let signature = Signature::decode(&mut blob.as_slice()).unwrap();
        key.public.key_data().verify(&message, &signature).unwrap();
    }
}
