//! Registro de auditoría de los Teams (ver `tunel_core::sync::audit`). El servidor guarda
//! las entradas cifradas tal como llegan: cualquier miembro escribe, solo los admins leen.

use crate::api::{ApiError, ApiResult, AppState, Session, check_blob, now, team_role};
use crate::db::{Db, DbError};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{Transaction, params};
use serde::Deserialize;
use std::sync::Arc;
use tunel_core::sync::SealedBlob;
use tunel_core::sync::protocol::{
    AuditPage, AuditRecord, AuditUpload, MAX_AUDIT_PAGE, MAX_AUDIT_UPLOAD, PreviousKey, TeamRole,
};

/// Una entrada cifrada: la firmada ocupa como mucho 4 KiB, más JSON y base64.
const MAX_AUDIT_CIPHERTEXT: usize = 8 * 1024;
pub(crate) const MAX_PREVIOUS_KEY_CIPHERTEXT: usize = 256;

/// Cuánto guarda el servidor del registro. Cada cuenta tiene su cupo en cada Team y solo
/// se borran sus propias entradas, y solo las viejas: así nadie puede llenar el registro
/// para que desaparezca lo que hicieron los demás, ni lo que hizo él hace poco.
#[derive(Debug, Clone, Copy)]
pub struct AuditLimits {
    /// Entradas de una cuenta en un Team.
    pub per_author: i64,
    /// Segundos durante los que una entrada no se borra para hacer sitio.
    pub min_age: i64,
}

pub const AUDIT_LIMITS: AuditLimits = AuditLimits {
    per_author: 10_000,
    min_age: 90 * 24 * 60 * 60,
};
const DEFAULT_PAGE: usize = 200;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v1/teams/{team}/audit", get(read).post(append))
}

async fn append(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Json(upload): Json<AuditUpload>,
) -> ApiResult<StatusCode> {
    team_role(&state, &session, &team).await?;
    if upload.entries.is_empty() || upload.entries.len() > MAX_AUDIT_UPLOAD {
        return Err(ApiError::bad_request("número de entradas no válido"));
    }
    for entry in &upload.entries {
        check_blob(entry, MAX_AUDIT_CIPHERTEXT)?;
    }
    state
        .db
        .append_audit(team, session.account, upload, now(), AUDIT_LIMITS)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PageQuery {
    /// Entradas anteriores a esta; sin ella, las más nuevas.
    before: Option<u64>,
    limit: Option<usize>,
}

async fn read(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<AuditPage>> {
    if team_role(&state, &session, &team).await? != TeamRole::Admin {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "solo un administrador del equipo puede ver el registro",
        ));
    }
    let limit = query.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_AUDIT_PAGE);
    let before = query.before.unwrap_or(i64::MAX as u64).min(i64::MAX as u64);
    Ok(Json(state.db.audit_page(team, before, limit).await?))
}

/// Guarda la clave anterior cifrada con la de `epoch`, al renovar la clave del Team.
pub(crate) fn insert_previous_key(
    tx: &Transaction<'_>,
    team: &str,
    epoch: u64,
    blob: &SealedBlob,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO team_previous_keys (team_id, epoch, blob) VALUES (?1, ?2, ?3)",
        params![team, epoch as i64, serde_json::to_string(blob)?],
    )?;
    Ok(())
}

/// Hace sitio para `incoming` entradas de `author` borrando sus entradas más viejas que
/// `limits.min_age`. Si no basta, la cuenta ha llegado a su cupo.
fn make_room(
    tx: &Transaction<'_>,
    team: &str,
    author: &str,
    incoming: i64,
    now: i64,
    limits: AuditLimits,
) -> Result<(), DbError> {
    let count = |tx: &Transaction<'_>| -> Result<i64, DbError> {
        Ok(tx.query_row(
            "SELECT COUNT(*) FROM team_audit WHERE team_id = ?1 AND author = ?2",
            params![team, author],
            |row| row.get(0),
        )?)
    };
    let excess = count(tx)? + incoming - limits.per_author;
    if excess <= 0 {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM team_audit WHERE id IN (
             SELECT id FROM team_audit
             WHERE team_id = ?1 AND author = ?2 AND received_at < ?3
             ORDER BY id LIMIT ?4)",
        params![team, author, now - limits.min_age, excess],
    )?;
    if count(tx)? + incoming > limits.per_author {
        return Err(DbError::Limit("entradas del registro de actividad"));
    }
    Ok(())
}

/// Todas las claves anteriores guardadas del Team, de la más nueva a la más vieja.
pub(crate) fn previous_keys(
    conn: &rusqlite::Connection,
    team: &str,
) -> Result<Vec<PreviousKey>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT epoch, blob FROM team_previous_keys WHERE team_id = ?1 ORDER BY epoch DESC",
    )?;
    let rows = stmt.query_map(params![team], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (epoch, blob) = row?;
        Ok(PreviousKey {
            epoch: epoch as u64,
            blob: serde_json::from_str(&blob)?,
        })
    })
    .collect()
}

impl Db {
    pub async fn append_audit(
        &self,
        team: String,
        account: i64,
        upload: AuditUpload,
        received_at: i64,
        limits: AuditLimits,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let epoch: i64 = tx.query_row(
                "SELECT epoch FROM teams WHERE id = ?1",
                params![team],
                |row| row.get(0),
            )?;
            // Con otra clave, ningún admin podría leerlas: que la app las vuelva a cifrar.
            if epoch as u64 != upload.epoch {
                return Err(DbError::Conflict);
            }
            let author: String = tx.query_row(
                "SELECT email FROM accounts WHERE id = ?1",
                params![account],
                |row| row.get(0),
            )?;
            make_room(
                &tx,
                &team,
                &author,
                upload.entries.len() as i64,
                received_at,
                limits,
            )?;
            for entry in &upload.entries {
                tx.execute(
                    "INSERT INTO team_audit (team_id, epoch, author, received_at, blob)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        team,
                        epoch,
                        author,
                        received_at,
                        serde_json::to_string(entry)?
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn audit_page(
        &self,
        team: String,
        before: u64,
        limit: usize,
    ) -> Result<AuditPage, DbError> {
        self.call(move |conn| {
            let mut entries: Vec<AuditRecord> = {
                let mut stmt = conn.prepare(
                    "SELECT id, epoch, author, received_at, blob FROM team_audit
                     WHERE team_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
                )?;
                let rows =
                    stmt.query_map(params![team, before as i64, limit as i64 + 1], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })?;
                rows.map(|row| {
                    let (id, epoch, author, received_at, blob) = row?;
                    Ok(AuditRecord {
                        id: id as u64,
                        epoch: epoch as u64,
                        author,
                        received_at: received_at.max(0) as u64,
                        blob: serde_json::from_str(&blob)?,
                    })
                })
                .collect::<Result<_, DbError>>()?
            };
            let more = entries.len() > limit;
            entries.truncate(limit);
            let previous_keys = previous_keys(conn, &team)?;
            Ok(AuditPage {
                entries,
                previous_keys,
                more,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn blob(n: u8) -> SealedBlob {
        SealedBlob {
            nonce: "AAAAAAAAAAAAAAAA".into(),
            ciphertext: format!("{n:02}"),
        }
    }

    async fn db_with_team(epoch: i64) -> (Db, i64) {
        let db = Db::open_in_memory().unwrap();
        let account = db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO accounts (email, kdf, salt, auth_salt, auth_hash, auth_kdf,
                         vault_key, created_at)
                     VALUES ('ana@ejemplo.com', '', '', x'', x'', '', '', 0)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO teams (id, name, epoch, created_at) VALUES (?1, '', ?2, 0)",
                    params![TEAM, epoch],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
            .unwrap();
        (db, account)
    }

    fn upload(epoch: u64, entries: std::ops::Range<u8>) -> AuditUpload {
        AuditUpload {
            epoch,
            entries: entries.map(blob).collect(),
        }
    }

    const LIMITS: AuditLimits = AuditLimits {
        per_author: 4,
        min_age: 100,
    };

    async fn add_account(db: &Db, email: &'static str) -> i64 {
        db.call(move |conn| {
            conn.execute(
                "INSERT INTO accounts (email, kdf, salt, auth_salt, auth_hash, auth_kdf,
                     vault_key, created_at)
                 VALUES (?1, '', '', x'', x'', '', '', 0)",
                params![email],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .unwrap()
    }

    fn texts(page: &AuditPage) -> Vec<&str> {
        page.entries
            .iter()
            .map(|e| e.blob.ciphertext.as_str())
            .collect()
    }

    #[tokio::test]
    async fn entries_are_paged_newest_first() {
        let (db, ana) = db_with_team(0).await;
        db.append_audit(TEAM.into(), ana, upload(0, 0..4), 10, LIMITS)
            .await
            .unwrap();
        let page = db.audit_page(TEAM.into(), u64::MAX >> 1, 3).await.unwrap();
        assert_eq!(texts(&page), ["03", "02", "01"]);
        assert!(page.more);
        assert_eq!(page.entries[0].author, "ana@ejemplo.com");
        assert_eq!(page.entries[0].received_at, 10);
        let rest = db
            .audit_page(TEAM.into(), page.entries[2].id, 3)
            .await
            .unwrap();
        assert_eq!(texts(&rest), ["00"]);
        assert!(!rest.more);
    }

    #[tokio::test]
    async fn a_full_quota_only_makes_room_with_the_authors_old_entries() {
        let (db, ana) = db_with_team(0).await;
        let eva = add_account(&db, "eva@ejemplo.com").await;
        db.append_audit(TEAM.into(), ana, upload(0, 0..2), 0, LIMITS)
            .await
            .unwrap();
        db.append_audit(TEAM.into(), eva, upload(0, 10..14), 0, LIMITS)
            .await
            .unwrap();
        // Recientes: Eva no puede hacer sitio, y menos borrando lo de Ana.
        assert!(matches!(
            db.append_audit(TEAM.into(), eva, upload(0, 20..21), 50, LIMITS)
                .await,
            Err(DbError::Limit(_))
        ));
        // Ya viejas: se borran las suyas más antiguas.
        db.append_audit(TEAM.into(), eva, upload(0, 20..22), 200, LIMITS)
            .await
            .unwrap();
        let page = db
            .audit_page(TEAM.into(), u64::MAX >> 1, 100)
            .await
            .unwrap();
        assert_eq!(texts(&page), ["21", "20", "13", "12", "01", "00"]);
    }

    #[tokio::test]
    async fn entries_with_an_old_key_are_refused() {
        let (db, ana) = db_with_team(2).await;
        assert!(matches!(
            db.append_audit(TEAM.into(), ana, upload(1, 0..1), 0, LIMITS)
                .await,
            Err(DbError::Conflict)
        ));
        db.append_audit(TEAM.into(), ana, upload(2, 0..1), 0, LIMITS)
            .await
            .unwrap();
    }
}
