//! Claves débiles, y claves privadas sin frase de paso en `~/.ssh`.
//!
//! Lo que hace falta se lee de la parte pública de la clave, que el formato de OpenSSH
//! guarda a la vista aunque la privada esté cifrada: así no hace falta la frase de paso, y
//! se reconocen también las DSA, que `ssh-key` no sabe leer.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::path::{Path, PathBuf};

/// Por debajo de esto, una RSA ya no se considera segura (NIST, a partir de 2030).
pub const MIN_RSA_BITS: usize = 3072;
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const OPENSSH_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// Las claves privadas son pequeñas: lo que pase de esto en `~/.ssh` no se lee.
const MAX_KEY_FILE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weakness {
    /// DSA: solo 1024 bits, y OpenSSH ya no la acepta.
    Dsa,
    /// RSA de menos de [`MIN_RSA_BITS`]; lleva los bits que tiene.
    ShortRsa(usize),
}

impl Weakness {
    pub fn describe(self) -> String {
        match self {
            Weakness::Dsa => "DSA: insegura, y OpenSSH ya no la acepta".into(),
            Weakness::ShortRsa(bits) => {
                format!("RSA de {bits} bits: usa al menos {MIN_RSA_BITS}, o mejor Ed25519")
            }
        }
    }
}

/// Lee los campos `string` del formato de SSH: longitud de 4 bytes y contenido.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = (self.0.get(..len)?, self.0.get(len..)?);
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.bytes(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }
}

/// Bits de un entero `mpint` de SSH, sin contar los ceros de delante.
fn mpint_bits(value: &[u8]) -> usize {
    let digits: Vec<u8> = value.iter().copied().skip_while(|b| *b == 0).collect();
    match digits.first() {
        Some(first) => digits.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

/// Lo débil de la clave pública `blob`, en el formato de SSH.
fn blob_weakness(blob: &[u8]) -> Option<Weakness> {
    let mut reader = Reader(blob);
    match reader.string()? {
        b"ssh-dss" => Some(Weakness::Dsa),
        b"ssh-rsa" => {
            let _exponent = reader.string()?;
            let bits = mpint_bits(reader.string()?);
            (bits < MIN_RSA_BITS).then_some(Weakness::ShortRsa(bits))
        }
        _ => None,
    }
}

/// El cuerpo en base64 de un bloque PEM, decodificado.
fn pem_body(text: &str) -> Option<Vec<u8>> {
    let body: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----") && !l.contains(':'))
        .collect();
    B64.decode(body).ok()
}

/// Una clave privada en el formato de OpenSSH: si va cifrada y su clave pública.
struct OpensshKey {
    encrypted: bool,
    public: Vec<u8>,
}

fn parse_openssh(text: &str) -> Option<OpensshKey> {
    if !text.trim_start().starts_with(OPENSSH_HEADER) {
        return None;
    }
    let body = pem_body(text)?;
    let mut reader = Reader(body.strip_prefix(OPENSSH_MAGIC)?);
    let cipher = reader.string()?;
    let _kdf = reader.string()?;
    let _kdf_options = reader.string()?;
    let _count = reader.u32()?;
    Some(OpensshKey {
        encrypted: cipher != b"none",
        public: reader.string()?.to_vec(),
    })
}

/// Lo débil de una clave del llavero. Si su clave pública no se puede leer (una PEM cuya
/// frase de paso no está), no se avisa de nada.
pub fn weakness(
    private_key: &str,
    passphrase: Option<&str>,
    public_key: Option<&str>,
) -> Option<Weakness> {
    if private_key.contains("BEGIN DSA PRIVATE KEY") {
        return Some(Weakness::Dsa);
    }
    if let Some(key) = parse_openssh(private_key) {
        return blob_weakness(&key.public);
    }
    let line = public_key
        .map(str::to_string)
        .or_else(|| crate::keygen::public_key(private_key, passphrase))?;
    let blob = B64.decode(line.split_whitespace().nth(1)?).ok()?;
    blob_weakness(&blob)
}

/// `Some(true)` si `text` es una clave privada cifrada, `Some(false)` si va sin cifrar y
/// `None` si no es una clave privada.
fn encrypted(text: &str) -> Option<bool> {
    if let Some(key) = parse_openssh(text) {
        return Some(key.encrypted);
    }
    let header = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    if !(header.starts_with("-----BEGIN ") && header.ends_with("PRIVATE KEY-----")) {
        return None;
    }
    Some(header.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED"))
}

/// Una clave privada sin frase de paso en el disco, fuera de la bóveda cifrada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprotectedKey {
    pub path: PathBuf,
    pub weakness: Option<Weakness>,
}

/// Las claves privadas sin frase de paso de `dir` (normalmente `~/.ssh`), por nombre.
/// Cualquiera que lea el archivo puede usarlas.
pub fn unprotected_keys(dir: &Path) -> Vec<UnprotectedKey> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut keys: Vec<UnprotectedKey> = entries
        .filter_map(Result::ok)
        .filter(|e| {
            e.metadata()
                .is_ok_and(|m| m.is_file() && m.len() <= MAX_KEY_FILE)
        })
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path()).ok()?;
            (encrypted(&text) == Some(false)).then(|| UnprotectedKey {
                weakness: weakness(&text, None, None),
                path: e.path(),
            })
        })
        .collect();
    keys.sort_by(|a, b| a.path.cmp(&b.path));
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyType, generate};

    /// Una clave privada de OpenSSH con la clave pública `public`, sin la parte privada:
    /// basta para lo que se lee aquí.
    fn openssh_with(public: &[u8], cipher: &str) -> String {
        let string = |b: &[u8]| [&(b.len() as u32).to_be_bytes()[..], b].concat();
        let body = [
            OPENSSH_MAGIC.to_vec(),
            string(cipher.as_bytes()),
            string(b"none"),
            string(b""),
            1u32.to_be_bytes().to_vec(),
            string(public),
            string(b"privada"),
        ]
        .concat();
        format!(
            "{OPENSSH_HEADER}\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            B64.encode(body)
        )
    }

    fn rsa_blob(bits: usize) -> Vec<u8> {
        let string = |b: &[u8]| [&(b.len() as u32).to_be_bytes()[..], b].concat();
        let mut modulus = vec![0u8; bits / 8 + 1];
        modulus[1] = 0x80;
        [string(b"ssh-rsa"), string(&[1, 0, 1]), string(&modulus)].concat()
    }

    #[test]
    fn short_rsa_and_dsa_keys_are_weak() {
        let short = openssh_with(&rsa_blob(2048), "aes256-ctr");
        assert_eq!(weakness(&short, None, None), Some(Weakness::ShortRsa(2048)));
        let long = openssh_with(&rsa_blob(3072), "none");
        assert_eq!(weakness(&long, None, None), None);
        let dsa_blob = [&7u32.to_be_bytes()[..], b"ssh-dss", &[0; 8]].concat();
        let dsa = openssh_with(&dsa_blob, "none");
        assert_eq!(weakness(&dsa, None, None), Some(Weakness::Dsa));
        let pem = "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----";
        assert_eq!(weakness(pem, None, None), Some(Weakness::Dsa));
    }

    #[test]
    fn generated_keys_are_not_weak_even_when_encrypted() {
        for kind in KeyType::ALL {
            let key = generate(kind, "", Some("frase")).unwrap();
            assert_eq!(weakness(&key.private_key, None, None), None, "{kind:?}");
        }
    }

    #[test]
    fn the_public_key_line_is_used_for_other_formats() {
        let line = format!("ssh-rsa {} ana", B64.encode(rsa_blob(1024)));
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";
        assert_eq!(
            weakness(pem, None, Some(&line)),
            Some(Weakness::ShortRsa(1024))
        );
        assert_eq!(
            weakness(pem, None, None),
            None,
            "sin poder leerla, no se avisa"
        );
    }

    #[test]
    fn only_private_keys_without_passphrase_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let clear = generate(KeyType::Ed25519, "", None).unwrap();
        let locked = generate(KeyType::Ed25519, "", Some("frase")).unwrap();
        let files = [
            ("id_ed25519", clear.private_key.clone()),
            ("id_ed25519.pub", clear.public_key.clone()),
            ("cifrada", locked.private_key),
            ("vieja", openssh_with(&rsa_blob(1024), "none")),
            (
                "pem_cifrada",
                "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n\
                 -----END RSA PRIVATE KEY-----"
                    .into(),
            ),
            (
                "pkcs8",
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".into(),
            ),
            ("config", "Host *\n  User ana\n".into()),
            ("known_hosts", "github.com ssh-ed25519 AAAA\n".into()),
        ];
        for (name, text) in &files {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        let found = unprotected_keys(dir.path());
        let names: Vec<&str> = found
            .iter()
            .map(|k| k.path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["id_ed25519", "pkcs8", "vieja"]);
        assert_eq!(found[2].weakness, Some(Weakness::ShortRsa(1024)));
        assert!(unprotected_keys(&dir.path().join("no-existe")).is_empty());
    }

    /// Con claves de `ssh-keygen`, si está instalado.
    #[test]
    fn keys_made_by_ssh_keygen_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let keygen = |name: &str, args: &[&str]| {
            std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "rsa", "-b", "2048", "-C", "", "-f"])
                .arg(dir.path().join(name))
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        };
        if !keygen("clara", &["-N", ""]) {
            return;
        }
        assert!(keygen("cifrada", &["-N", "frase"]));
        assert!(keygen("pem", &["-N", "frase", "-m", "PEM"]));
        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap();
        for name in ["clara", "cifrada"] {
            assert_eq!(
                weakness(&read(name), None, None),
                Some(Weakness::ShortRsa(2048)),
                "{name}"
            );
        }
        assert_eq!(
            weakness(&read("pem"), Some("frase"), None),
            Some(Weakness::ShortRsa(2048))
        );
        let found = unprotected_keys(dir.path());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].path.ends_with("clara"));
    }

    #[test]
    fn rsa_bits_ignore_the_leading_zero() {
        assert_eq!(mpint_bits(&[0, 0x80, 0]), 16);
        assert_eq!(mpint_bits(&[0x01, 0xff]), 9);
        assert_eq!(mpint_bits(&[]), 0);
    }
}
