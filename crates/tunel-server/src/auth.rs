//! Comprobación de la clave de acceso, tokens de sesión y límites de intentos.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tunel_core::crypto::KdfParams;
use zeroize::Zeroizing;

/// Longitud de la clave de acceso que deriva el cliente.
pub const AUTH_LEN: usize = 32;
const HASH_LEN: usize = 32;
const SALT_LEN: usize = 16;
/// Longitud de un token de sesión: 32 bytes en base64 URL sin relleno.
const TOKEN_LEN: usize = 43;

/// Decodifica la clave de acceso que envía el cliente.
pub fn decode_auth(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    if text.len() > AUTH_LEN * 2 {
        return None;
    }
    let bytes = Zeroizing::new(B64.decode(text).ok()?);
    (bytes.len() == AUTH_LEN).then_some(bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Demasiados hashes en cola: mejor rechazar que dejar esperando a todos.
    #[error("servidor ocupado")]
    Busy,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Hash Argon2id de las claves de acceso. Limita cuántos se calculan a la vez y cuánto se
/// espera turno, porque cada uno ocupa memoria y CPU y un atacante podría saturar el
/// servidor con inicios de sesión.
pub struct AuthHasher {
    /// Parámetros para los hashes nuevos; los existentes usan los suyos guardados.
    kdf: KdfParams,
    permits: Semaphore,
    queue_wait: Duration,
}

/// Hash guardado de una clave de acceso.
pub struct StoredHash {
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub kdf: KdfParams,
}

impl AuthHasher {
    pub fn new(kdf: KdfParams, concurrent: usize, queue_wait: Duration) -> anyhow::Result<Self> {
        argon_params(kdf)?;
        Ok(Self {
            kdf,
            permits: Semaphore::new(concurrent.max(1)),
            queue_wait,
        })
    }

    async fn hash(
        &self,
        auth: &[u8],
        salt: &[u8],
        kdf: KdfParams,
    ) -> Result<[u8; HASH_LEN], HashError> {
        let _permit = tokio::time::timeout(self.queue_wait, self.permits.acquire())
            .await
            .map_err(|_| HashError::Busy)?
            .map_err(|e| HashError::Internal(e.into()))?;
        let params = argon_params(kdf)?;
        let (auth, salt) = (Zeroizing::new(auth.to_vec()), salt.to_vec());
        let hashed = tokio::task::spawn_blocking(move || {
            let mut out = [0u8; HASH_LEN];
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(&auth, &salt, &mut out)
                .map_err(|e| anyhow::anyhow!("Argon2: {e}"))?;
            Ok::<_, anyhow::Error>(out)
        })
        .await
        .map_err(|e| HashError::Internal(e.into()))??;
        Ok(hashed)
    }

    /// Hash nuevo con su sal y sus parámetros, para guardarlo al crear la cuenta.
    pub async fn hash_new(&self, auth: &[u8]) -> Result<StoredHash, HashError> {
        let salt: [u8; SALT_LEN] = rand::random();
        let hash = self.hash(auth, &salt, self.kdf).await?;
        Ok(StoredHash {
            salt: salt.to_vec(),
            hash: hash.to_vec(),
            kdf: self.kdf,
        })
    }

    /// Compara en tiempo constante.
    pub async fn verify(&self, auth: &[u8], stored: &StoredHash) -> Result<bool, HashError> {
        let hash = self.hash(auth, &stored.salt, stored.kdf).await?;
        Ok(hash.ct_eq(&stored.hash).into())
    }

    /// Hace el mismo trabajo que una comprobación real, para que una cuenta inexistente
    /// no se distinga por lo que tarda en responder.
    pub async fn burn(&self, auth: &[u8]) -> Result<(), HashError> {
        self.hash(auth, &[0u8; SALT_LEN], self.kdf)
            .await
            .map(|_| ())
    }
}

fn argon_params(kdf: KdfParams) -> anyhow::Result<Params> {
    Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(HASH_LEN),
    )
    .map_err(|e| anyhow::anyhow!("parámetros de Argon2 no válidos: {e}"))
}

/// Token de sesión nuevo y el hash que se guarda en la base de datos.
pub fn new_token() -> (String, [u8; 32]) {
    let raw: [u8; 32] = rand::random();
    let token = B64_URL.encode(raw);
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Un token que no tiene la forma de los que emite el servidor se rechaza sin consultar
/// la base de datos.
pub fn token_looks_valid(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Intentos de inicio de sesión por cuenta. El intento se cuenta antes de comprobar la
/// clave, así que lanzar muchas peticiones a la vez no permite probar más claves.
pub struct LoginLimiter {
    max_attempts: u32,
    window: Duration,
    max_tracked: usize,
    attempts: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginLimiter {
    pub fn new(max_attempts: u32, window: Duration, max_tracked: usize) -> Self {
        Self {
            max_attempts,
            window,
            max_tracked,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Reserva un intento. Devuelve `false` si la cuenta agotó los suyos o si se están
    /// vigilando demasiadas cuentas a la vez (alguien prueba correos al azar).
    pub fn try_begin(&self, email: &str) -> bool {
        let Ok(mut map) = self.attempts.lock() else {
            return false;
        };
        let window = self.window;
        if map.len() >= self.max_tracked {
            map.retain(|_, (_, since)| since.elapsed() < window);
        }
        if let Some((_, since)) = map.get(email)
            && since.elapsed() >= window
        {
            map.remove(email);
        }
        if !map.contains_key(email) && map.len() >= self.max_tracked {
            return false;
        }
        let entry = map.entry(email.to_string()).or_insert((0, Instant::now()));
        if entry.0 >= self.max_attempts {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// El inicio de sesión fue bien: se olvidan sus intentos.
    pub fn succeeded(&self, email: &str) {
        if let Ok(mut map) = self.attempts.lock() {
            map.remove(email);
        }
    }
}

/// Cubeta de fichas global para las rutas sin sesión: limita cuántas peticiones por
/// segundo pueden obligar al servidor a calcular un Argon2 o a crear cuentas.
pub struct RateBucket {
    capacity: f64,
    per_second: f64,
    state: Mutex<(f64, Instant)>,
}

impl RateBucket {
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self {
            capacity: f64::from(burst.max(1)),
            per_second: f64::from(per_second),
            state: Mutex::new((f64::from(burst.max(1)), Instant::now())),
        }
    }

    pub fn try_take(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let (tokens, last) = *state;
        let refilled = (tokens + last.elapsed().as_secs_f64() * self.per_second).min(self.capacity);
        if refilled < 1.0 {
            *state = (refilled, Instant::now());
            return false;
        }
        *state = (refilled - 1.0, Instant::now());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> AuthHasher {
        AuthHasher::new(KdfParams::FAST_FOR_TESTS, 2, Duration::from_secs(5)).unwrap()
    }

    #[tokio::test]
    async fn verify_accepts_only_the_original_auth_key() {
        let h = hasher();
        let stored = h.hash_new(&[1; AUTH_LEN]).await.unwrap();
        assert!(h.verify(&[1; AUTH_LEN], &stored).await.unwrap());
        assert!(!h.verify(&[2; AUTH_LEN], &stored).await.unwrap());
    }

    #[tokio::test]
    async fn stored_hashes_keep_verifying_after_the_parameters_change() {
        let stored = hasher().hash_new(&[1; AUTH_LEN]).await.unwrap();
        let stronger = KdfParams {
            memory_kib: 128,
            iterations: 2,
            parallelism: 1,
        };
        let h = AuthHasher::new(stronger, 2, Duration::from_secs(5)).unwrap();
        assert!(h.verify(&[1; AUTH_LEN], &stored).await.unwrap());
    }

    #[tokio::test]
    async fn a_full_queue_answers_busy_instead_of_waiting() {
        let h = AuthHasher::new(KdfParams::FAST_FOR_TESTS, 1, Duration::ZERO).unwrap();
        let _held = h.permits.acquire().await.unwrap();
        assert!(matches!(h.burn(&[0; AUTH_LEN]).await, Err(HashError::Busy)));
    }

    #[test]
    fn auth_keys_must_be_32_bytes_of_base64() {
        assert!(decode_auth(&B64.encode([0u8; AUTH_LEN])).is_some());
        assert!(decode_auth(&B64.encode([0u8; 16])).is_none());
        assert!(decode_auth("no es base64").is_none());
        assert!(decode_auth(&"A".repeat(10_000)).is_none());
    }

    #[test]
    fn tokens_are_unique_hashed_and_recognisable() {
        let (a, hash_a) = new_token();
        let (b, _) = new_token();
        assert_ne!(a, b);
        assert_eq!(token_hash(&a), hash_a);
        assert!(token_looks_valid(&a));
        assert!(!token_looks_valid("inventado"));
        assert!(!token_looks_valid(&format!("{}=", &a[1..])));
    }

    #[test]
    fn attempts_are_reserved_before_checking_and_reset_on_success() {
        let limiter = LoginLimiter::new(2, Duration::from_secs(60), 100);
        assert!(limiter.try_begin("ana@x"));
        assert!(limiter.try_begin("ana@x"));
        assert!(!limiter.try_begin("ana@x"));
        assert!(limiter.try_begin("otra@x"));
        limiter.succeeded("ana@x");
        assert!(limiter.try_begin("ana@x"));
    }

    #[test]
    fn attempts_expire_after_the_window() {
        let limiter = LoginLimiter::new(1, Duration::ZERO, 100);
        assert!(limiter.try_begin("ana@x"));
        assert!(limiter.try_begin("ana@x"));
    }

    #[test]
    fn too_many_tracked_accounts_are_refused() {
        let limiter = LoginLimiter::new(5, Duration::from_secs(60), 2);
        assert!(limiter.try_begin("a@x"));
        assert!(limiter.try_begin("b@x"));
        assert!(!limiter.try_begin("c@x"));
        assert!(limiter.try_begin("a@x"));
    }

    #[test]
    fn bucket_allows_a_burst_then_refuses() {
        let bucket = RateBucket::new(0, 2);
        assert!(bucket.try_take());
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }
}
