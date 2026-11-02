//! Firmas de archivos de `ssh-keygen -Y sign`: la de un archivo `x` queda en `x.sig`.

use russh::keys::ssh_key::{PublicKey, SshSig};

/// Comprueba que `signature` firma `message` con la clave `public_key` (una línea de
/// `authorized_keys`) y para el uso `namespace`, como `ssh-keygen -Y verify`.
pub fn verify(
    public_key: &str,
    namespace: &str,
    message: &[u8],
    signature: &str,
) -> Result<(), String> {
    let key = PublicKey::from_openssh(public_key.trim())
        .map_err(|e| format!("clave pública no válida ({e})"))?;
    let signature =
        SshSig::from_pem(signature.trim()).map_err(|e| format!("firma no válida ({e})"))?;
    key.verify(namespace, message, &signature)
        .map_err(|_| "la firma no corresponde a la clave".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Firma de `MESSAGE` hecha con `ssh-keygen -Y sign -n tunel-versiones`.
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9M0eaptTdxLAKAcvMfVy62otNzXcsUEOC/Ot6M6ln/ prueba";
    const MESSAGE: &[u8] = b"abc123  tunel_0.9.0_amd64.deb\n";
    const SIGNATURE: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgH0zR5qm1N3EsAoBy8x9XLrai03
NdyxQQ4L863ozqWf8AAAAPdHVuZWwtdmVyc2lvbmVzAAAAAAAAAAZzaGE1MTIAAABTAAAA
C3NzaC1lZDI1NTE5AAAAQHqNBkckIWEAqEsmrCxoygQfwODatC98IQah/GmucWy8IazJQR
cpQjU8ZF1XiQu4OgS0a2xGYyHxIolkPtF/mQQ=
-----END SSH SIGNATURE-----
";

    #[test]
    fn a_signature_from_ssh_keygen_is_accepted() {
        assert_eq!(verify(KEY, "tunel-versiones", MESSAGE, SIGNATURE), Ok(()));
    }

    #[test]
    fn a_changed_message_namespace_or_key_is_rejected() {
        assert!(verify(KEY, "tunel-versiones", b"otra cosa\n", SIGNATURE).is_err());
        assert!(verify(KEY, "file", MESSAGE, SIGNATURE).is_err());
        let other = crate::keygen::generate(Default::default(), "", None).unwrap();
        assert!(verify(&other.public_key, "tunel-versiones", MESSAGE, SIGNATURE).is_err());
        assert!(verify(KEY, "tunel-versiones", MESSAGE, "no es una firma").is_err());
        assert!(verify("no es una clave", "tunel-versiones", MESSAGE, SIGNATURE).is_err());
    }
}
