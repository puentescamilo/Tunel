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
const MAX_PREVIOUS_KEY_CIPHERTEXT: usize = 256;
/// Entradas que se conservan por Team; al pasarse, se borran las más viejas.
pub const MAX_AUDIT_PER_TEAM: i64 = 20_000;
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
        .append_audit(team, session.account, upload, now(), MAX_AUDIT_PER_TEAM)
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
    if blob.ciphertext.len() > MAX_PREVIOUS_KEY_CIPHERTEXT {
        return Err(DbError::BadVersion);
    }
    tx.execute(
        "INSERT OR REPLACE INTO team_previous_keys (team_id, epoch, blob) VALUES (?1, ?2, ?3)",
        params![team, epoch as i64, serde_json::to_string(blob)?],
    )?;
    Ok(())
}

impl Db {
    pub async fn append_audit(
        &self,
        team: String,
        account: i64,
        upload: AuditUpload,
        received_at: i64,
        keep: i64,
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
            tx.execute(
                "DELETE FROM team_audit WHERE team_id = ?1 AND id <= (
                     SELECT id FROM team_audit WHERE team_id = ?1
                     ORDER BY id DESC LIMIT 1 OFFSET ?2)",
                params![team, keep],
            )?;
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
            let previous_keys = {
                let mut stmt = conn.prepare(
                    "SELECT epoch, blob FROM team_previous_keys WHERE team_id = ?1
                     ORDER BY epoch DESC",
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
                .collect::<Result<_, DbError>>()?
            };
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

    #[tokio::test]
    async fn entries_are_paged_newest_first_and_the_oldest_are_trimmed() {
        let (db, ana) = db_with_team(0).await;
        db.append_audit(TEAM.into(), ana, upload(0, 0..5), 10, 4)
            .await
            .unwrap();
        let page = db.audit_page(TEAM.into(), u64::MAX >> 1, 3).await.unwrap();
        let texts: Vec<_> = page
            .entries
            .iter()
            .map(|e| e.blob.ciphertext.as_str())
            .collect();
        assert_eq!(texts, ["04", "03", "02"]);
        assert!(page.more);
        assert_eq!(page.entries[0].author, "ana@ejemplo.com");
        assert_eq!(page.entries[0].received_at, 10);
        let rest = db
            .audit_page(TEAM.into(), page.entries[2].id, 3)
            .await
            .unwrap();
        let texts: Vec<_> = rest
            .entries
            .iter()
            .map(|e| e.blob.ciphertext.as_str())
            .collect();
        assert_eq!(texts, ["01"], "la más vieja se borró");
        assert!(!rest.more);
    }

    #[tokio::test]
    async fn entries_with_an_old_key_are_refused() {
        let (db, ana) = db_with_team(2).await;
        assert!(matches!(
            db.append_audit(TEAM.into(), ana, upload(1, 0..1), 0, 10)
                .await,
            Err(DbError::Conflict)
        ));
        db.append_audit(TEAM.into(), ana, upload(2, 0..1), 0, 10)
            .await
            .unwrap();
    }
}
