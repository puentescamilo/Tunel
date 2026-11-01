//! Firmas con el par de claves X25519 de la cuenta, con XEdDSA: la misma clave que envuelve
//! las claves de los Teams firma, así basta con la huella que las personas ya comparan.
//!
//! La clave privada X25519 se pasa a su punto de Edwards con el signo en 0, como manda
//! XEdDSA, y se firma con Ed25519 sobre ese punto. Cualquiera verifica la firma con la
//! clave pública X25519, que lleva a ese mismo punto, con la verificación estricta de
//! Ed25519.

use super::team::{AccountKeypair, PublicKey};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// Bytes de una firma.
pub const SIGNATURE_LEN: usize = 64;
/// Separa el número aleatorio de la firma de cualquier otro uso de la clave privada.
const NONCE_DOMAIN: &[u8] = b"tunel-firma-nonce-v1";

impl AccountKeypair {
    /// Firma `message`. Con la misma clave y el mismo mensaje sale la misma firma.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let clamped = Zeroizing::new(clamp_integer(*self.secret()));
        let k = Scalar::from_bytes_mod_order(*clamped);
        let point = EdwardsPoint::mul_base(&k);
        // XEdDSA: el punto público va siempre con el signo en 0.
        let (scalar, point) = if point.compress().as_bytes()[31] & 0x80 == 0 {
            (k, point)
        } else {
            (-k, -point)
        };
        let digest = Sha512::new()
            .chain_update(NONCE_DOMAIN)
            .chain_update(self.secret())
            .finalize();
        let mut hash_prefix = [0u8; 32];
        hash_prefix.copy_from_slice(&digest[..32]);
        let secret = ExpandedSecretKey {
            scalar,
            hash_prefix,
        };
        raw_sign::<Sha512>(&secret, message, &VerifyingKey::from(point)).to_bytes()
    }
}

impl PublicKey {
    /// `signature` es una firma de `message` hecha con la clave privada de esta.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Some(point) = MontgomeryPoint(*self.as_bytes()).to_edwards(0) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        VerifyingKey::from(point)
            .verify_strict(message, &signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_with_the_x25519_public_key() {
        // Varias claves: la mitad necesitan cambiar el signo del punto.
        for _ in 0..32 {
            let pair = AccountKeypair::generate();
            let signature = pair.sign(b"mensaje");
            assert!(pair.public().verify(b"mensaje", &signature));
            assert_eq!(signature, pair.sign(b"mensaje"), "determinista");
        }
    }

    #[test]
    fn another_key_a_changed_message_or_a_bad_signature_fail() {
        let pair = AccountKeypair::generate();
        let signature = pair.sign(b"mensaje");
        assert!(
            !AccountKeypair::generate()
                .public()
                .verify(b"mensaje", &signature)
        );
        assert!(!pair.public().verify(b"mensajE", &signature));
        let mut flipped = signature;
        flipped[10] ^= 1;
        assert!(!pair.public().verify(b"mensaje", &flipped));
        assert!(!pair.public().verify(b"mensaje", &signature[..63]));
        assert!(!PublicKey::from_bytes([0; 32]).verify(b"mensaje", &signature));
    }
}
