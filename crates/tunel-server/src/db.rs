//! Almacén SQLite: cuentas, sesiones y registros cifrados.
//!
//! El servidor nunca ve datos en claro: guarda la clave de bóveda envuelta, el manifiesto
//! y los registros tal como los manda el cliente, y solo conoce sus identificadores opacos.

use crate::auth::StoredHash;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tunel_core::crypto::KdfParams;
use tunel_core::sync::protocol::ManifestBlob;
use tunel_core::sync::{SealedBlob, SealedRecord};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("base de datos: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("datos guardados no válidos: {0}")]
    Json(#[from] serde_json::Error),
    #[error("la tarea de base de datos terminó con un error")]
    Task,
    #[error("ya existe una cuenta con ese correo")]
    AccountExists,
    #[error("otro equipo subió cambios antes")]
    Conflict,
    #[error("este servidor no admite cuentas nuevas")]
    RegistrationClosed,
    #[error("la cuenta alcanzó su espacio máximo")]
    QuotaExceeded,
    #[error("versión de manifiesto no válida")]
    BadVersion,
    #[error("el secreto del servidor guardado está dañado")]
    CorruptSecret,
}

/// Límites de almacenamiento de cada cuenta.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    pub records: u64,
    /// Suma del texto cifrado de todos los registros, en bytes de base64.
    pub bytes: u64,
}

const SCHEMA: &str = "
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    kdf TEXT NOT NULL,
    salt TEXT NOT NULL,
    auth_salt BLOB NOT NULL,
    auth_hash BLOB NOT NULL,
    auth_kdf TEXT NOT NULL,
    vault_key TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    manifest_version INTEGER NOT NULL DEFAULT 0,
    manifest TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX IF NOT EXISTS records_by_seq ON records (account_id, seq);
CREATE INDEX IF NOT EXISTS sessions_by_expiry ON sessions (expires_at);
";

/// Datos de una cuenta necesarios para iniciar sesión.
pub struct Account {
    pub id: i64,
    pub kdf: KdfParams,
    pub salt: String,
    pub auth: StoredHash,
    pub vault_key: SealedBlob,
}

pub struct NewAccount {
    pub email: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub auth: StoredHash,
    pub vault_key: SealedBlob,
    pub created_at: i64,
}

pub struct Page {
    pub records: Vec<SealedRecord>,
    pub cursor: u64,
    pub more: bool,
    pub manifest: Option<ManifestBlob>,
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, DbError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, DbError> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Ejecuta `f` en un hilo aparte para no bloquear el runtime de tokio.
    async fn call<T, F>(&self, f: F) -> Result<T, DbError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, DbError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| DbError::Task)?;
            f(&mut guard)
        })
        .await
        .map_err(|_| DbError::Task)?
    }

    /// Secreto propio del servidor, creado la primera vez.
    pub async fn server_secret(&self) -> Result<[u8; 32], DbError> {
        self.call(|conn| {
            let existing: Option<Vec<u8>> = conn
                .query_row("SELECT value FROM meta WHERE key = 'secret'", [], |row| {
                    row.get(0)
                })
                .optional()?;
            // Si estuviera dañado, regenerarlo cambiaría todas las sales inventadas del
            // prelogin, lo que delataría qué correos no tienen cuenta: mejor detenerse.
            if let Some(stored) = existing {
                return <[u8; 32]>::try_from(stored).map_err(|_| DbError::CorruptSecret);
            }
            let secret: [u8; 32] = rand::random();
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('secret', ?1)",
                params![secret.to_vec()],
            )?;
            Ok(secret)
        })
        .await
    }

    /// Crea la cuenta. Con `only_if_first`, solo si todavía no hay ninguna, comprobado en
    /// la misma sentencia para que dos registros simultáneos no creen dos.
    pub async fn insert_account(
        &self,
        account: NewAccount,
        only_if_first: bool,
    ) -> Result<i64, DbError> {
        self.call(move |conn| {
            let inserted = conn.execute(
                "INSERT INTO accounts
                     (email, kdf, salt, auth_salt, auth_hash, auth_kdf, vault_key, created_at)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
                 WHERE NOT ?9 OR NOT EXISTS (SELECT 1 FROM accounts)",
                params![
                    account.email,
                    serde_json::to_string(&account.kdf)?,
                    account.salt,
                    account.auth.salt,
                    account.auth.hash,
                    serde_json::to_string(&account.auth.kdf)?,
                    serde_json::to_string(&account.vault_key)?,
                    account.created_at,
                    only_if_first,
                ],
            );
            match inserted {
                Ok(0) => Err(DbError::RegistrationClosed),
                Ok(_) => Ok(conn.last_insert_rowid()),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(DbError::AccountExists)
                }
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    pub async fn account_by_email(&self, email: String) -> Result<Option<Account>, DbError> {
        self.call(move |conn| {
            let row = conn
                .query_row(
                    "SELECT id, kdf, salt, auth_salt, auth_hash, auth_kdf, vault_key
                     FROM accounts WHERE email = ?1",
                    params![email],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                        ))
                    },
                )
                .optional()?;
            row.map(
                |(id, kdf, salt, auth_salt, auth_hash, auth_kdf, vault_key)| {
                    Ok(Account {
                        id,
                        kdf: serde_json::from_str(&kdf)?,
                        salt,
                        auth: StoredHash {
                            salt: auth_salt,
                            hash: auth_hash,
                            kdf: serde_json::from_str(&auth_kdf)?,
                        },
                        vault_key: serde_json::from_str(&vault_key)?,
                    })
                },
            )
            .transpose()
        })
        .await
    }

    pub async fn insert_session(
        &self,
        token_hash: [u8; 32],
        account: i64,
        expires_at: i64,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
                params![token_hash.to_vec(), account, expires_at],
            )?;
            Ok(())
        })
        .await
    }

    /// Cuenta de una sesión vigente.
    pub async fn session_account(
        &self,
        token_hash: [u8; 32],
        now: i64,
    ) -> Result<Option<i64>, DbError> {
        self.call(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT account_id FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
                    params![token_hash.to_vec(), now],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .await
    }

    /// Borra las sesiones caducadas; se llama de vez en cuando, no en cada petición.
    pub async fn purge_sessions(&self, now: i64) -> Result<usize, DbError> {
        self.call(move |conn| {
            Ok(conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?)
        })
        .await
    }

    pub async fn delete_session(&self, token_hash: [u8; 32]) -> Result<(), DbError> {
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                params![token_hash.to_vec()],
            )?;
            Ok(())
        })
        .await
    }

    /// Registros cambiados después de `since`, en orden. El manifiesto actual solo va en
    /// la última página, que es cuando el cliente puede comprobarlo.
    pub async fn pull(&self, account: i64, since: u64, limit: usize) -> Result<Page, DbError> {
        let since = since.min(i64::MAX as u64);
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let mut records = Vec::new();
            let mut cursor = since;
            {
                let mut stmt = tx.prepare(
                    "SELECT id, seq, nonce, ciphertext FROM records
                     WHERE account_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![account, since as i64, limit as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?;
                for row in rows {
                    let (id, seq, nonce, ciphertext) = row?;
                    cursor = seq as u64;
                    records.push(SealedRecord {
                        id,
                        blob: SealedBlob { nonce, ciphertext },
                    });
                }
            }
            let more = {
                let total: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM records WHERE account_id = ?1 AND seq > ?2",
                    params![account, cursor as i64],
                    |row| row.get(0),
                )?;
                total > 0
            };
            let (version, manifest): (i64, Option<String>) = if more {
                (0, None)
            } else {
                tx.query_row(
                    "SELECT manifest_version, manifest FROM accounts WHERE id = ?1",
                    params![account],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?
            };
            let manifest = manifest
                .map(|m| -> Result<ManifestBlob, DbError> {
                    Ok(ManifestBlob {
                        version: version as u64,
                        blob: serde_json::from_str(&m)?,
                    })
                })
                .transpose()?;
            tx.commit()?;
            Ok(Page {
                records,
                cursor,
                more,
                manifest,
            })
        })
        .await
    }

    /// Guarda los registros y el manifiesto nuevo en una sola transacción, solo si nadie
    /// ha cambiado el manifiesto desde `base_version` y si la cuenta no supera su cuota.
    /// Devuelve el cursor nuevo.
    pub async fn push(
        &self,
        account: i64,
        base_version: u64,
        manifest: ManifestBlob,
        records: Vec<SealedRecord>,
        quota: Quota,
    ) -> Result<u64, DbError> {
        if base_version.checked_add(1) != Some(manifest.version)
            || manifest.version > i64::MAX as u64
        {
            return Err(DbError::BadVersion);
        }
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let (current, mut seq): (i64, i64) = tx.query_row(
                "SELECT manifest_version, seq FROM accounts WHERE id = ?1",
                params![account],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if current as u64 != base_version {
                return Err(DbError::Conflict);
            }
            for record in &records {
                seq += 1;
                tx.execute(
                    "INSERT INTO records (account_id, id, seq, nonce, ciphertext)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (account_id, id) DO UPDATE
                     SET seq = excluded.seq, nonce = excluded.nonce, ciphertext = excluded.ciphertext",
                    params![
                        account,
                        record.id,
                        seq,
                        record.blob.nonce,
                        record.blob.ciphertext
                    ],
                )?;
            }
            let (count, bytes): (i64, i64) = tx.query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(ciphertext)), 0)
                 FROM records WHERE account_id = ?1",
                params![account],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if count as u64 > quota.records || bytes as u64 > quota.bytes {
                // Al salir sin `commit`, la transacción se deshace.
                return Err(DbError::QuotaExceeded);
            }
            tx.execute(
                "UPDATE accounts SET seq = ?1, manifest_version = ?2, manifest = ?3 WHERE id = ?4",
                params![
                    seq,
                    manifest.version as i64,
                    serde_json::to_string(&manifest.blob)?,
                    account
                ],
            )?;
            tx.commit()?;
            Ok(seq as u64)
        })
        .await
    }
}
