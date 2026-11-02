//! Grabaciones de sesiones de los Teams (ver `tunel_core::sync::recording`). El servidor
//! guarda los trozos cifrados tal como llegan: los sube quien graba, de uno en uno y en
//! orden; solo los admins las listan, las descargan y las borran.

use crate::api::{ApiError, ApiResult, AppState, Session, check_blob, now, team_role};
use crate::db::{Db, DbError};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
use tunel_core::sync::protocol::{RecordingChunk, RecordingDownload, RecordingSummary, TeamRole};

/// Un trozo cifrado: la app los corta a 512 KiB de eventos sin comprimir.
const MAX_CHUNK_CIPHERTEXT: usize = 2 * 1024 * 1024;
const MAX_LISTED: i64 = 500;

/// Cuánto ocupan las grabaciones como mucho.
#[derive(Debug, Clone, Copy)]
pub struct RecordingLimits {
    /// Bytes cifrados de una grabación; al llegar, la app deja de grabar esa sesión.
    pub per_recording: u64,
    /// Bytes cifrados de todas las grabaciones de un Team.
    pub per_team: u64,
    /// Segundos que se guardan desde el último trozo.
    pub retention: i64,
}

impl Default for RecordingLimits {
    fn default() -> Self {
        Self {
            per_recording: 64 * 1024 * 1024,
            per_team: 2 * 1024 * 1024 * 1024,
            retention: 90 * 24 * 60 * 60,
        }
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/teams/{team}/recordings", get(list))
        .route(
            "/v1/teams/{team}/recordings/{id}",
            get(download).post(append).delete(remove),
        )
        .layer(DefaultBodyLimit::max(MAX_CHUNK_CIPHERTEXT + 64 * 1024))
}

/// Identificadores UUID en minúsculas, como los genera la app.
fn check_id(id: &str) -> ApiResult<()> {
    let ok = id.len() == 36
        && id
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "identificador de grabación no válido",
        ))
    }
}

async fn require_admin(state: &AppState, session: &Session, team: &str) -> ApiResult<()> {
    match team_role(state, session, team).await? {
        TeamRole::Admin => Ok(()),
        TeamRole::Member => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "solo un administrador del equipo puede ver las grabaciones",
        )),
    }
}

async fn append(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
    Json(chunk): Json<RecordingChunk>,
) -> ApiResult<StatusCode> {
    check_id(&id)?;
    team_role(&state, &session, &team).await?;
    check_blob(&chunk.blob, MAX_CHUNK_CIPHERTEXT)?;
    let limits = state.config.recordings;
    state
        .db
        .append_recording(team, id, session.account, chunk, now(), limits)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path(team): Path<String>,
) -> ApiResult<Json<Vec<RecordingSummary>>> {
    require_admin(&state, &session, &team).await?;
    Ok(Json(state.db.recordings(team).await?))
}

async fn download(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
) -> ApiResult<Json<RecordingDownload>> {
    check_id(&id)?;
    require_admin(&state, &session, &team).await?;
    Ok(Json(state.db.recording(team, id).await?))
}

async fn remove(
    State(state): State<Arc<AppState>>,
    session: Session,
    Path((team, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    check_id(&id)?;
    require_admin(&state, &session, &team).await?;
    state.db.delete_recording(team, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecordingSummary> {
    Ok(RecordingSummary {
        id: row.get(0)?,
        author: row.get(1)?,
        started_at: row.get::<_, i64>(2)?.max(0) as u64,
        updated_at: row.get::<_, i64>(3)?.max(0) as u64,
        bytes: row.get::<_, i64>(4)?.max(0) as u64,
        chunks: row.get::<_, i64>(5)?.max(0) as u64,
        finished: row.get(6)?,
    })
}

impl Db {
    /// Añade el trozo siguiente de una grabación; el primero la crea. Repetir el último
    /// trozo ya guardado, igual, no es un error: la app reintenta si no supo si llegó.
    pub async fn append_recording(
        &self,
        team: String,
        id: String,
        account: i64,
        chunk: RecordingChunk,
        now: i64,
        limits: RecordingLimits,
    ) -> Result<(), DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let epoch: i64 = tx.query_row(
                "SELECT epoch FROM teams WHERE id = ?1",
                params![team],
                |row| row.get(0),
            )?;
            // Un trozo con una clave posterior a la del Team no lo podría leer nadie.
            if chunk.epoch > epoch as u64 {
                return Err(DbError::Conflict);
            }
            let author: String = tx.query_row(
                "SELECT email FROM accounts WHERE id = ?1",
                params![account],
                |row| row.get(0),
            )?;
            let blob = serde_json::to_string(&chunk.blob)?;
            let existing: Option<(String, i64, i64, bool)> = tx
                .query_row(
                    "SELECT author, bytes, chunks, finished FROM team_recordings
                     WHERE team_id = ?1 AND id = ?2",
                    params![team, id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let (bytes, chunks) = match existing {
                None if chunk.seq == 0 => {
                    tx.execute(
                        "INSERT INTO team_recordings (team_id, id, author, started_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?4)",
                        params![team, id, author, now],
                    )?;
                    (0, 0)
                }
                None => return Err(DbError::NotFound),
                // La de otra cuenta no se puede tocar ni saber que existe.
                Some((owner, ..)) if owner != author => return Err(DbError::NotFound),
                Some((_, bytes, chunks, finished)) => {
                    if (chunk.seq as i64) < chunks {
                        let stored: Option<String> = tx
                            .query_row(
                                "SELECT blob FROM team_recording_chunks
                                 WHERE team_id = ?1 AND recording_id = ?2 AND seq = ?3",
                                params![team, id, chunk.seq as i64],
                                |row| row.get(0),
                            )
                            .optional()?;
                        return if stored.as_deref() == Some(blob.as_str()) {
                            Ok(())
                        } else {
                            Err(DbError::Conflict)
                        };
                    }
                    if finished {
                        return Err(DbError::Conflict);
                    }
                    (bytes, chunks)
                }
            };
            if chunk.seq as i64 != chunks {
                return Err(DbError::Conflict);
            }
            let size = blob.len() as i64;
            if (bytes + size) as u64 > limits.per_recording {
                return Err(DbError::Limit("tamaño de una grabación"));
            }
            let team_bytes: i64 = tx.query_row(
                "SELECT COALESCE(SUM(bytes), 0) FROM team_recordings WHERE team_id = ?1",
                params![team],
                |row| row.get(0),
            )?;
            if (team_bytes + size) as u64 > limits.per_team {
                return Err(DbError::QuotaExceeded);
            }
            tx.execute(
                "INSERT INTO team_recording_chunks (team_id, recording_id, seq, epoch, blob)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![team, id, chunk.seq as i64, chunk.epoch as i64, blob],
            )?;
            tx.execute(
                "UPDATE team_recordings SET bytes = bytes + ?1, chunks = chunks + 1,
                     updated_at = ?2, finished = ?3
                 WHERE team_id = ?4 AND id = ?5",
                params![size, now, chunk.last, team, id],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn recordings(&self, team: String) -> Result<Vec<RecordingSummary>, DbError> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, author, started_at, updated_at, bytes, chunks, finished
                 FROM team_recordings WHERE team_id = ?1
                 ORDER BY started_at DESC, id LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![team, MAX_LISTED], summary)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    pub async fn recording(&self, team: String, id: String) -> Result<RecordingDownload, DbError> {
        self.call(move |conn| {
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM team_recordings WHERE team_id = ?1 AND id = ?2",
                    params![team, id],
                    |row| row.get(0),
                )
                .optional()?;
            exists.ok_or(DbError::NotFound)?;
            let mut stmt = conn.prepare(
                "SELECT seq, epoch, blob FROM team_recording_chunks
                 WHERE team_id = ?1 AND recording_id = ?2 ORDER BY seq",
            )?;
            let rows = stmt.query_map(params![team, id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let chunks = rows
                .map(|row| {
                    let (seq, epoch, blob) = row?;
                    Ok(RecordingChunk {
                        seq: seq as u64,
                        epoch: epoch as u64,
                        last: false,
                        blob: serde_json::from_str(&blob)?,
                    })
                })
                .collect::<Result<_, DbError>>()?;
            Ok(RecordingDownload {
                chunks,
                previous_keys: crate::audit::previous_keys(conn, &team)?,
            })
        })
        .await
    }

    pub async fn delete_recording(&self, team: String, id: String) -> Result<(), DbError> {
        self.call(move |conn| {
            let deleted = conn.execute(
                "DELETE FROM team_recordings WHERE team_id = ?1 AND id = ?2",
                params![team, id],
            )?;
            if deleted == 0 {
                return Err(DbError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Borra las grabaciones sin trozos nuevos desde hace más de `retention` segundos.
    pub async fn purge_recordings(&self, now: i64, retention: i64) -> Result<usize, DbError> {
        self.call(move |conn| {
            Ok(conn.execute(
                "DELETE FROM team_recordings WHERE updated_at < ?1",
                params![now - retention],
            )?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::sync::SealedBlob;

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";
    const REC: &str = "0f8b2c1e-1111-4222-8333-944455556666";
    const LIMITS: RecordingLimits = RecordingLimits {
        per_recording: 150,
        per_team: 250,
        retention: 1000,
    };

    async fn db() -> (Db, i64, i64) {
        let db = Db::open_in_memory().unwrap();
        let ids = db
            .call(|conn| {
                let mut ids = Vec::new();
                for email in ["ana@ejemplo.com", "eva@ejemplo.com"] {
                    conn.execute(
                        "INSERT INTO accounts (email, kdf, salt, auth_salt, auth_hash, auth_kdf,
                             vault_key, created_at)
                         VALUES (?1, '', '', x'', x'', '', '', 0)",
                        params![email],
                    )?;
                    ids.push(conn.last_insert_rowid());
                }
                conn.execute(
                    "INSERT INTO teams (id, name, epoch, created_at) VALUES (?1, '', 3, 0)",
                    params![TEAM],
                )?;
                Ok(ids)
            })
            .await
            .unwrap();
        (db, ids[0], ids[1])
    }

    fn chunk(seq: u64, text: &str, last: bool) -> RecordingChunk {
        RecordingChunk {
            seq,
            epoch: 3,
            last,
            blob: SealedBlob {
                nonce: "AAAAAAAAAAAAAAAA".into(),
                ciphertext: text.into(),
            },
        }
    }

    async fn append(db: &Db, account: i64, id: &str, chunk: RecordingChunk) -> Result<(), DbError> {
        db.append_recording(TEAM.into(), id.into(), account, chunk, 10, LIMITS)
            .await
    }

    #[tokio::test]
    async fn chunks_go_in_order_retries_are_idempotent_and_the_last_closes_it() {
        let (db, ana, _) = db().await;
        assert!(matches!(
            append(&db, ana, REC, chunk(1, "b", false)).await,
            Err(DbError::NotFound)
        ));
        append(&db, ana, REC, chunk(0, "a", false)).await.unwrap();
        append(&db, ana, REC, chunk(0, "a", false)).await.unwrap();
        assert!(matches!(
            append(&db, ana, REC, chunk(0, "x", false)).await,
            Err(DbError::Conflict)
        ));
        assert!(matches!(
            append(&db, ana, REC, chunk(2, "c", false)).await,
            Err(DbError::Conflict)
        ));
        append(&db, ana, REC, chunk(1, "b", true)).await.unwrap();
        assert!(matches!(
            append(&db, ana, REC, chunk(2, "c", false)).await,
            Err(DbError::Conflict)
        ));
        let listed = db.recordings(TEAM.into()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].finished);
        assert_eq!(listed[0].chunks, 2);
        assert_eq!(listed[0].author, "ana@ejemplo.com");
        let download = db.recording(TEAM.into(), REC.into()).await.unwrap();
        let texts: Vec<_> = download
            .chunks
            .iter()
            .map(|c| c.blob.ciphertext.as_str())
            .collect();
        assert_eq!(texts, ["a", "b"]);
    }

    #[tokio::test]
    async fn only_the_author_continues_a_recording() {
        let (db, ana, eva) = db().await;
        append(&db, ana, REC, chunk(0, "a", false)).await.unwrap();
        assert!(matches!(
            append(&db, eva, REC, chunk(1, "b", false)).await,
            Err(DbError::NotFound)
        ));
    }

    #[tokio::test]
    async fn size_limits_and_retention_apply() {
        let (db, ana, _) = db().await;
        let big = "x".repeat(60);
        append(&db, ana, REC, chunk(0, &big, false)).await.unwrap();
        // Esta grabación pasaría de 150 bytes.
        assert!(matches!(
            append(&db, ana, REC, chunk(1, &big, false)).await,
            Err(DbError::Limit(_))
        ));
        let other = "0f8b2c1e-1111-4222-8333-944455550000";
        append(&db, ana, other, chunk(0, &big, false))
            .await
            .unwrap();
        // Y el Team, de 250.
        let third = "0f8b2c1e-1111-4222-8333-944455551111";
        assert!(matches!(
            append(&db, ana, third, chunk(0, &big, false)).await,
            Err(DbError::QuotaExceeded)
        ));
        assert_eq!(db.purge_recordings(500, 1000).await.unwrap(), 0);
        assert_eq!(db.purge_recordings(2000, 1000).await.unwrap(), 2);
        assert!(db.recordings(TEAM.into()).await.unwrap().is_empty());
    }
}
