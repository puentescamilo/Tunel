//! Almacén SQLite: cuentas, sesiones, equipos y registros cifrados.
//!
//! El servidor nunca ve datos en claro: guarda la clave de bóveda envuelta, el manifiesto
//! y los registros tal como los manda el cliente, y solo conoce sus identificadores opacos.
//! De los equipos sabe quién es miembro y con qué rol, pero no su nombre ni su contenido.

use crate::auth::StoredHash;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tunel_core::crypto::KdfParams;
use tunel_core::sync::protocol::{
    AccountKeysBlob, ManifestBlob, MemberKey, TeamMember, TeamRole, TeamSummary,
};
use tunel_core::sync::{PublicKey, SealedBlob, SealedRecord};

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
    #[error("la cuenta ya tiene un par de claves")]
    KeysExist,
    #[error("la cuenta todavía no tiene claves para equipos")]
    NoKeys,
    #[error("no existe")]
    NotFound,
    #[error("ya existe un equipo con ese identificador")]
    TeamExists,
    #[error("ya es miembro del equipo")]
    AlreadyMember,
    #[error("el equipo se quedaría sin administradores")]
    LastAdmin,
    #[error("la clave nueva tiene que llegar a todos los miembros, y solo a ellos")]
    MembersMismatch,
    #[error("se alcanzó el máximo de {0}")]
    Limit(&'static str),
    #[error("hay que renovar la clave del equipo antes de seguir")]
    RekeyNeeded,
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
CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 0,
    seq INTEGER NOT NULL DEFAULT 0,
    manifest_version INTEGER NOT NULL DEFAULT 0,
    manifest TEXT,
    -- Se sacó a alguien y todavía no se ha renovado la clave.
    rekey_needed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS team_members (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    key TEXT NOT NULL,
    wrapped_by INTEGER NOT NULL REFERENCES accounts(id),
    -- Una invitación no cuenta hasta que el invitado la acepta.
    accepted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, account_id)
);
CREATE INDEX IF NOT EXISTS team_members_by_account ON team_members (account_id);
CREATE TABLE IF NOT EXISTS team_records (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (team_id, id)
);
CREATE INDEX IF NOT EXISTS team_records_by_seq ON team_records (team_id, seq);
";

/// Columnas añadidas a `accounts` después de la primera versión, con su tipo.
const ACCOUNT_COLUMNS: [(&str, &str); 2] = [("public_key", "TEXT"), ("private_key", "TEXT")];

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
    pub epoch: Option<u64>,
}

/// Dónde viven unos registros: la bóveda personal de una cuenta o la de un equipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Space {
    Account(i64),
    Team(String),
}

impl Space {
    /// Tabla con el manifiesto, tabla de registros y su columna de propietario. Son
    /// nombres fijos, así que se pueden escribir en el SQL sin riesgo.
    fn tables(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Account(_) => ("accounts", "records", "account_id"),
            Self::Team(_) => ("teams", "team_records", "team_id"),
        }
    }

    fn owner(&self) -> rusqlite::types::Value {
        match self {
            Self::Account(id) => (*id).into(),
            Self::Team(id) => id.clone().into(),
        }
    }
}

/// Cambios que pide una renovación de la clave de un equipo.
pub struct Rotation {
    pub epoch: u64,
    pub base_version: u64,
    pub name: SealedBlob,
    pub keys: Vec<MemberKey>,
    pub manifest: ManifestBlob,
    pub records: Vec<SealedRecord>,
}

fn role_name(role: TeamRole) -> &'static str {
    match role {
        TeamRole::Admin => "admin",
        TeamRole::Member => "member",
    }
}

fn parse_role(name: &str) -> Result<TeamRole, DbError> {
    match name {
        "admin" => Ok(TeamRole::Admin),
        "member" => Ok(TeamRole::Member),
        other => Err(DbError::Json(serde::de::Error::custom(format!(
            "rol desconocido: {other}"
        )))),
    }
}

fn parse_public_key(text: &str) -> Result<PublicKey, DbError> {
    PublicKey::from_base64(text)
        .ok_or_else(|| DbError::Json(serde::de::Error::custom("clave pública dañada")))
}

/// Guarda registros con números de secuencia a partir de `seq` y devuelve el último.
fn insert_records(
    tx: &rusqlite::Transaction<'_>,
    space: &Space,
    mut seq: i64,
    records: &[SealedRecord],
) -> Result<i64, DbError> {
    let (_, table, owner_col) = space.tables();
    let mut stmt = tx.prepare(&format!(
        "INSERT INTO {table} ({owner_col}, id, seq, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT ({owner_col}, id) DO UPDATE
         SET seq = excluded.seq, nonce = excluded.nonce, ciphertext = excluded.ciphertext"
    ))?;
    for record in records {
        seq += 1;
        stmt.execute(params![
            space.owner(),
            record.id,
            seq,
            record.blob.nonce,
            record.blob.ciphertext
        ])?;
    }
    Ok(seq)
}

fn check_quota(tx: &rusqlite::Transaction<'_>, space: &Space, quota: Quota) -> Result<(), DbError> {
    let (_, table, owner_col) = space.tables();
    let (count, bytes): (i64, i64) = tx.query_row(
        &format!(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(ciphertext)), 0)
             FROM {table} WHERE {owner_col} = ?1"
        ),
        params![space.owner()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count as u64 > quota.records || bytes as u64 > quota.bytes {
        return Err(DbError::QuotaExceeded);
    }
    Ok(())
}

/// Equipos de los que la cuenta ya es miembro, sin contar invitaciones pendientes.
fn accepted_teams(tx: &rusqlite::Transaction<'_>, account: i64) -> Result<u64, DbError> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM team_members WHERE account_id = ?1 AND accepted = 1",
        params![account],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// Administradores que ya aceptaron; una invitación pendiente no cuenta.
fn team_admins(tx: &rusqlite::Transaction<'_>, team: &str) -> Result<i64, DbError> {
    Ok(tx.query_row(
        "SELECT COUNT(*) FROM team_members
         WHERE team_id = ?1 AND role = 'admin' AND accepted = 1",
        params![team],
        |row| row.get(0),
    )?)
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
        Self::migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Añade las columnas que faltan a una base de datos de una versión anterior.
    fn migrate(conn: &Connection) -> Result<(), DbError> {
        let existing: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('accounts')")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for (name, kind) in ACCOUNT_COLUMNS {
            if !existing.iter().any(|c| c == name) {
                conn.execute_batch(&format!("ALTER TABLE accounts ADD COLUMN {name} {kind}"))?;
            }
        }
        Ok(())
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
    pub async fn pull(&self, space: Space, since: u64, limit: usize) -> Result<Page, DbError> {
        let since = since.min(i64::MAX as u64);
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let (header, table, owner_col) = space.tables();
            let mut records = Vec::new();
            let mut cursor = since;
            {
                let mut stmt = tx.prepare(&format!(
                    "SELECT id, seq, nonce, ciphertext FROM {table}
                     WHERE {owner_col} = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3"
                ))?;
                let rows =
                    stmt.query_map(params![space.owner(), since as i64, limit as i64], |row| {
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
                    &format!("SELECT COUNT(*) FROM {table} WHERE {owner_col} = ?1 AND seq > ?2"),
                    params![space.owner(), cursor as i64],
                    |row| row.get(0),
                )?;
                total > 0
            };
            let (version, manifest): (i64, Option<String>) = if more {
                (0, None)
            } else {
                tx.query_row(
                    &format!("SELECT manifest_version, manifest FROM {header} WHERE id = ?1"),
                    params![space.owner()],
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
            let epoch = match &space {
                Space::Account(_) => None,
                Space::Team(team) => Some(tx.query_row(
                    "SELECT epoch FROM teams WHERE id = ?1",
                    params![team],
                    |row| row.get::<_, i64>(0),
                )? as u64),
            };
            tx.commit()?;
            Ok(Page {
                records,
                cursor,
                more,
                manifest,
                epoch,
            })
        })
        .await
    }

    /// Guarda los registros y el manifiesto nuevo en una sola transacción, solo si nadie
    /// ha cambiado el manifiesto desde `base_version`, si en un equipo la clave sigue en
    /// la época `epoch`, y si el espacio no supera su cuota. Devuelve el cursor nuevo.
    pub async fn push(
        &self,
        space: Space,
        base_version: u64,
        epoch: Option<u64>,
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
            let (header, _, _) = space.tables();
            let (current, seq): (i64, i64) = tx.query_row(
                &format!("SELECT manifest_version, seq FROM {header} WHERE id = ?1"),
                params![space.owner()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if current as u64 != base_version {
                return Err(DbError::Conflict);
            }
            if let Space::Team(team) = &space {
                let (current_epoch, rekey_needed): (i64, bool) = tx.query_row(
                    "SELECT epoch, rekey_needed FROM teams WHERE id = ?1",
                    params![team],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if rekey_needed {
                    return Err(DbError::RekeyNeeded);
                }
                if epoch != Some(current_epoch as u64) {
                    return Err(DbError::Conflict);
                }
            }
            let seq = insert_records(&tx, &space, seq, &records)?;
            // Al salir sin `commit`, la transacción se deshace.
            check_quota(&tx, &space, quota)?;
            tx.execute(
                &format!(
                    "UPDATE {header} SET seq = ?1, manifest_version = ?2, manifest = ?3
                     WHERE id = ?4"
                ),
                params![
                    seq,
                    manifest.version as i64,
                    serde_json::to_string(&manifest.blob)?,
                    space.owner()
                ],
            )?;
            tx.commit()?;
            Ok(seq as u64)
        })
        .await
    }

    /// Guarda el par de claves de la cuenta. No se puede sustituir: los equipos ya tienen
    /// claves envueltas para la pública.
    pub async fn set_account_keys(
        &self,
        account: i64,
        keys: AccountKeysBlob,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let updated = conn.execute(
                "UPDATE accounts SET public_key = ?1, private_key = ?2
                 WHERE id = ?3 AND public_key IS NULL",
                params![
                    keys.public_key.to_base64(),
                    serde_json::to_string(&keys.private_key)?,
                    account
                ],
            )?;
            if updated == 0 {
                return Err(DbError::KeysExist);
            }
            Ok(())
        })
        .await
    }

    /// Par de claves de la cuenta, si ya subió uno.
    pub async fn account_keys(&self, account: i64) -> Result<Option<AccountKeysBlob>, DbError> {
        self.call(move |conn| {
            let (public, private): (Option<String>, Option<String>) = conn.query_row(
                "SELECT public_key, private_key FROM accounts WHERE id = ?1",
                params![account],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            match (public, private) {
                (Some(public), Some(private)) => Ok(Some(AccountKeysBlob {
                    public_key: parse_public_key(&public)?,
                    private_key: serde_json::from_str(&private)?,
                })),
                _ => Ok(None),
            }
        })
        .await
    }

    pub async fn account_email(&self, account: i64) -> Result<String, DbError> {
        self.call(move |conn| {
            Ok(conn.query_row(
                "SELECT email FROM accounts WHERE id = ?1",
                params![account],
                |row| row.get(0),
            )?)
        })
        .await
    }

    pub async fn public_key_by_email(&self, email: String) -> Result<Option<PublicKey>, DbError> {
        self.call(move |conn| {
            let key: Option<Option<String>> = conn
                .query_row(
                    "SELECT public_key FROM accounts WHERE email = ?1",
                    params![email],
                    |row| row.get(0),
                )
                .optional()?;
            key.flatten().as_deref().map(parse_public_key).transpose()
        })
        .await
    }

    /// Crea el equipo con `account` como administrador.
    pub async fn create_team(
        &self,
        account: i64,
        id: String,
        name: SealedBlob,
        key: SealedBlob,
        created_at: i64,
        max_teams: u64,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let has_keys: bool = tx.query_row(
                "SELECT public_key IS NOT NULL FROM accounts WHERE id = ?1",
                params![account],
                |row| row.get(0),
            )?;
            if !has_keys {
                return Err(DbError::NoKeys);
            }
            if accepted_teams(&tx, account)? >= max_teams {
                return Err(DbError::Limit("equipos por cuenta"));
            }
            let inserted = tx.execute(
                "INSERT INTO teams (id, name, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (id) DO NOTHING",
                params![id, serde_json::to_string(&name)?, created_at],
            )?;
            if inserted == 0 {
                return Err(DbError::TeamExists);
            }
            tx.execute(
                "INSERT INTO team_members (team_id, account_id, role, key, wrapped_by, accepted)
                 VALUES (?1, ?2, 'admin', ?3, ?2, 1)",
                params![id, account, serde_json::to_string(&key)?],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Equipos de los que la cuenta es miembro.
    pub async fn teams_of(&self, account: i64) -> Result<Vec<TeamSummary>, DbError> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT t.id, t.name, m.role, t.epoch, m.key, a.email, a.public_key, m.accepted,
                        t.rekey_needed
                 FROM team_members m
                 JOIN teams t ON t.id = m.team_id
                 JOIN accounts a ON a.id = m.wrapped_by
                 WHERE m.account_id = ?1
                 ORDER BY t.created_at, t.id",
            )?;
            let rows = stmt.query_map(params![account], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, bool>(8)?,
                ))
            })?;
            rows.map(|row| {
                let (id, name, role, epoch, key, wrapped_by, wrapped_by_key, accepted, rekey) =
                    row?;
                let (name, key) = if accepted {
                    (
                        Some(serde_json::from_str(&name)?),
                        Some(serde_json::from_str(&key)?),
                    )
                } else {
                    (None, None)
                };
                Ok(TeamSummary {
                    id,
                    name,
                    role: parse_role(&role)?,
                    epoch: epoch as u64,
                    key,
                    wrapped_by,
                    wrapped_by_key: parse_public_key(&wrapped_by_key)?,
                    pending: !accepted,
                    rekey_needed: accepted && rekey,
                })
            })
            .collect()
        })
        .await
    }

    /// Rol de la cuenta en el equipo y si ya aceptó la invitación; `None` si no es
    /// miembro ni está invitada, o si el equipo no existe.
    pub async fn membership(
        &self,
        team: String,
        account: i64,
    ) -> Result<Option<(TeamRole, bool)>, DbError> {
        self.call(move |conn| {
            let row: Option<(String, bool)> = conn
                .query_row(
                    "SELECT role, accepted FROM team_members
                     WHERE team_id = ?1 AND account_id = ?2",
                    params![team, account],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            row.map(|(role, accepted)| Ok((parse_role(&role)?, accepted)))
                .transpose()
        })
        .await
    }

    /// Acepta una invitación pendiente.
    pub async fn accept_invitation(
        &self,
        team: String,
        account: i64,
        max_teams: u64,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            if accepted_teams(&tx, account)? >= max_teams {
                return Err(DbError::Limit("equipos por cuenta"));
            }
            let updated = tx.execute(
                "UPDATE team_members SET accepted = 1
                 WHERE team_id = ?1 AND account_id = ?2 AND accepted = 0",
                params![team, account],
            )?;
            if updated == 0 {
                return Err(DbError::NotFound);
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn team_members(&self, team: String) -> Result<Vec<TeamMember>, DbError> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT a.email, m.role, a.public_key, m.accepted
                 FROM team_members m JOIN accounts a ON a.id = m.account_id
                 WHERE m.team_id = ?1 ORDER BY a.email",
            )?;
            let rows = stmt.query_map(params![team], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            })?;
            rows.map(|row| {
                let (email, role, public_key, accepted) = row?;
                Ok(TeamMember {
                    email,
                    role: parse_role(&role)?,
                    public_key: parse_public_key(&public_key)?,
                    pending: !accepted,
                })
            })
            .collect()
        })
        .await
    }

    /// Invita a la cuenta de `email` con la clave del equipo envuelta por `wrapped_by`.
    /// No es miembro hasta que acepta. Una cuenta sin claves se trata como inexistente,
    /// para no revelar qué correos tienen cuenta.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_member(
        &self,
        team: String,
        email: String,
        role: TeamRole,
        epoch: u64,
        key: SealedBlob,
        wrapped_by: i64,
        max_members: u64,
        max_pending: u64,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let (account, _): (i64, bool) = tx
                .query_row(
                    "SELECT id, public_key IS NOT NULL FROM accounts WHERE email = ?1",
                    params![email],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .filter(|(_, has_keys)| *has_keys)
                .ok_or(DbError::NotFound)?;
            let (current, rekey_needed): (i64, bool) = tx.query_row(
                "SELECT epoch, rekey_needed FROM teams WHERE id = ?1",
                params![team],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if rekey_needed {
                return Err(DbError::RekeyNeeded);
            }
            if current as u64 != epoch {
                return Err(DbError::Conflict);
            }
            let members: i64 = tx.query_row(
                "SELECT COUNT(*) FROM team_members WHERE team_id = ?1",
                params![team],
                |row| row.get(0),
            )?;
            if members as u64 >= max_members {
                return Err(DbError::Limit("miembros por equipo"));
            }
            let pending: i64 = tx.query_row(
                "SELECT COUNT(*) FROM team_members WHERE account_id = ?1 AND accepted = 0",
                params![account],
                |row| row.get(0),
            )?;
            if pending as u64 >= max_pending {
                return Err(DbError::Limit("invitaciones pendientes"));
            }
            let inserted = tx.execute(
                "INSERT INTO team_members (team_id, account_id, role, key, wrapped_by)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (team_id, account_id) DO NOTHING",
                params![
                    team,
                    account,
                    role_name(role),
                    serde_json::to_string(&key)?,
                    wrapped_by
                ],
            )?;
            if inserted == 0 {
                return Err(DbError::AlreadyMember);
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Cambia el rol de un miembro; el equipo no puede quedarse sin administradores.
    pub async fn set_member_role(
        &self,
        team: String,
        email: String,
        role: TeamRole,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let updated = tx.execute(
                "UPDATE team_members SET role = ?1
                 WHERE team_id = ?2 AND account_id = (SELECT id FROM accounts WHERE email = ?3)",
                params![role_name(role), team, email],
            )?;
            if updated == 0 {
                return Err(DbError::NotFound);
            }
            if team_admins(&tx, &team)? == 0 {
                return Err(DbError::LastAdmin);
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Saca a un miembro o retira una invitación; el equipo no puede quedarse sin
    /// administradores. Si era miembro, el equipo queda pendiente de renovar la clave.
    pub async fn remove_member(&self, team: String, email: String) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let was_accepted: bool = tx
                .query_row(
                    "DELETE FROM team_members
                     WHERE team_id = ?1
                       AND account_id = (SELECT id FROM accounts WHERE email = ?2)
                     RETURNING accepted",
                    params![team, email],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(DbError::NotFound)?;
            if team_admins(&tx, &team)? == 0 {
                return Err(DbError::LastAdmin);
            }
            // Quien sale se lleva la clave: hasta que se renueve no se sube nada más. Una
            // invitación pendiente nunca la recibió.
            if was_accepted {
                tx.execute(
                    "UPDATE teams SET rekey_needed = 1 WHERE id = ?1",
                    params![team],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Borra el equipo con todos sus miembros y registros.
    pub async fn delete_team(&self, team: String) -> Result<(), DbError> {
        self.call(move |conn| {
            conn.execute("DELETE FROM teams WHERE id = ?1", params![team])?;
            Ok(())
        })
        .await
    }

    /// Sustituye la clave del equipo, su nombre y todos sus registros en una sola
    /// transacción. Los números de secuencia siguen creciendo para que los cursores de
    /// los clientes sigan valiendo, y el manifiesto sube de versión como en cualquier
    /// subida, así un cliente no lo confunde con uno antiguo.
    pub async fn rotate_team(
        &self,
        team: String,
        rotation: Rotation,
        wrapped_by: i64,
        quota: Quota,
    ) -> Result<u64, DbError> {
        if rotation.base_version.checked_add(1) != Some(rotation.manifest.version)
            || rotation.manifest.version > i64::MAX as u64
            || rotation.epoch > i64::MAX as u64
        {
            return Err(DbError::BadVersion);
        }
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let (epoch, version, seq): (i64, i64, i64) = tx.query_row(
                "SELECT epoch, manifest_version, seq FROM teams WHERE id = ?1",
                params![team],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if (epoch as u64).checked_add(1) != Some(rotation.epoch)
                || version as u64 != rotation.base_version
            {
                return Err(DbError::Conflict);
            }
            let mut members: Vec<(i64, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT a.id, a.email FROM team_members m
                     JOIN accounts a ON a.id = m.account_id WHERE m.team_id = ?1",
                )?;
                stmt.query_map(params![team], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<_, _>>()?
            };
            members.sort_by(|a, b| a.1.cmp(&b.1));
            let mut emails: Vec<&str> = rotation.keys.iter().map(|k| k.email.as_str()).collect();
            emails.sort_unstable();
            if !emails
                .iter()
                .copied()
                .eq(members.iter().map(|m| m.1.as_str()))
            {
                return Err(DbError::MembersMismatch);
            }
            for member_key in &rotation.keys {
                tx.execute(
                    "UPDATE team_members SET key = ?1, wrapped_by = ?2
                     WHERE team_id = ?3
                       AND account_id = (SELECT id FROM accounts WHERE email = ?4)",
                    params![
                        serde_json::to_string(&member_key.key)?,
                        wrapped_by,
                        team,
                        member_key.email
                    ],
                )?;
            }
            tx.execute("DELETE FROM team_records WHERE team_id = ?1", params![team])?;
            let space = Space::Team(team.clone());
            let seq = insert_records(&tx, &space, seq, &rotation.records)?;
            check_quota(&tx, &space, quota)?;
            tx.execute(
                "UPDATE teams SET name = ?1, epoch = ?2, seq = ?3, manifest_version = ?4,
                     manifest = ?5, rekey_needed = 0
                 WHERE id = ?6",
                params![
                    serde_json::to_string(&rotation.name)?,
                    rotation.epoch as i64,
                    seq,
                    rotation.manifest.version as i64,
                    serde_json::to_string(&rotation.manifest.blob)?,
                    team
                ],
            )?;
            tx.commit()?;
            Ok(seq as u64)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `accounts` tal como la creaba la primera versión del servidor.
    const OLD_ACCOUNTS: &str = "
        CREATE TABLE accounts (
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
        INSERT INTO accounts (email, kdf, salt, auth_salt, auth_hash, auth_kdf, vault_key,
                              created_at)
        VALUES ('ana@ejemplo.com', '{}', 'sal', x'00', x'00', '{}', '{}', 0);
    ";

    #[tokio::test]
    async fn an_old_database_gains_the_key_columns_and_keeps_its_accounts() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(OLD_ACCOUNTS).unwrap();
        let db = Db::init(conn).unwrap();
        assert_eq!(db.account_email(1).await.unwrap(), "ana@ejemplo.com");
        assert_eq!(
            db.public_key_by_email("ana@ejemplo.com".into())
                .await
                .unwrap(),
            None
        );
    }

    #[test]
    fn migrating_twice_is_harmless() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        Db::migrate(&conn).unwrap();
        Db::migrate(&conn).unwrap();
    }
}
