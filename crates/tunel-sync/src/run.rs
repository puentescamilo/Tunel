//! Una ronda de sincronización: para la bóveda personal y después para cada Team,
//! descargar, fusionar, comprobar y subir.

use crate::session::{Session, call};
use crate::{SyncError, keypair, now_millis, teams};
use tunel_core::sync::protocol::{MAX_PUSH_RECORDS, ManifestBlob, PushRequest, TeamRole};
use tunel_core::sync::space::{Space, absorb, partition};
use tunel_core::sync::state::Rejected;
use tunel_core::sync::{Manifest, ManifestError, SyncLocal, SyncState, VaultKey};
use tunel_core::vault::VaultData;

/// Rondas de descargar y subir antes de rendirse si otros equipos suben a la vez.
pub(crate) const MAX_ROUNDS: usize = 5;
/// Páginas que se descargan como mucho en una ronda; con la cuota del servidor bastan 40.
const MAX_PAGES: usize = 1000;
/// Tiempo máximo de una ronda entera, para que un servidor lento no la deje colgada.
const ROUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Resultado de una ronda: la bóveda y la configuración nuevas, y lo que se apartó.
#[derive(Debug)]
pub struct SyncOutcome {
    pub data: VaultData,
    pub local: SyncLocal,
    /// Registros del servidor que no se aplicaron (marca demasiado adelantada o contenido
    /// que no encaja con esta versión de Túnel).
    pub rejected: Vec<Rejected>,
    pub downloaded: usize,
    pub uploaded: usize,
    /// Teams que no se pudieron sincronizar en esta ronda. No impiden sincronizar la
    /// bóveda personal ni los demás Teams.
    pub team_problems: Vec<TeamProblem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamProblem {
    /// Identificador del Team, o vacío si falló la lista de Teams.
    pub team: String,
    pub message: String,
}

/// Un espacio a sincronizar: la bóveda personal (`team` es `None`) o un Team.
pub(crate) struct SpaceSync<'a> {
    pub team: Option<&'a str>,
    pub key: &'a VaultKey,
    /// Época de la clave de un Team.
    pub epoch: Option<u64>,
    pub state: SyncState,
}

/// Lo que deja una ronda en un espacio.
#[derive(Default)]
pub(crate) struct Counters {
    pub rejected: Vec<Rejected>,
    pub downloaded: usize,
    pub uploaded: usize,
}

/// Descarga todo lo nuevo desde el cursor, lo fusiona y comprueba el manifiesto.
/// Devuelve el manifiesto actual, sobre el que se construye la siguiente subida.
pub(crate) async fn pull(
    session: &mut Session,
    space: &mut SpaceSync<'_>,
    data: &mut VaultData,
    counters: &mut Counters,
) -> Result<Manifest, SyncError> {
    let mut retried_from_start = false;
    loop {
        let manifest_blob = pull_pages(session, space, data, counters).await?;
        match check_manifest(space, manifest_blob, &counters.rejected) {
            Ok(manifest) => {
                space.state.manifest_version = manifest.version;
                return Ok(manifest);
            }
            // El cursor puede estar por delante del servidor (por ejemplo, si se restauró
            // de una copia) o el manifiesto puede no corresponder a lo descargado: se
            // descarga todo una vez más antes de dar la alarma.
            Err(SyncError::Integrity(ManifestError::Incomplete(_)) | SyncError::Crypto(_))
                if !retried_from_start && space.state.cursor > 0 =>
            {
                retried_from_start = true;
                space.state.cursor = 0;
                counters.rejected.clear();
            }
            Err(e) => return Err(e),
        }
    }
}

async fn pull_pages(
    session: &mut Session,
    space: &mut SpaceSync<'_>,
    data: &mut VaultData,
    counters: &mut Counters,
) -> Result<Option<ManifestBlob>, SyncError> {
    let team = space.team;
    for _ in 0..MAX_PAGES {
        let since = space.state.cursor;
        let page = call!(session, |api, token| api.pull(token, team, since))?;
        if page.more && page.cursor <= since {
            return Err(SyncError::Misbehaving("la descarga no avanza"));
        }
        // Se renovó la clave del Team desde que este equipo la recibió.
        if space.epoch.is_some() && page.epoch != space.epoch {
            return Err(SyncError::StaleKey);
        }
        // Un registro que no se puede descifrar no se ignora: sería una forma de que el
        // servidor ocultara datos sin que el manifiesto lo delatara.
        let envelopes = page
            .records
            .iter()
            .map(|r| space.key.open_record(r))
            .collect::<Result<Vec<_>, _>>()?;
        counters.downloaded += envelopes.len();
        let merged = space
            .state
            .merge_remote(data, &envelopes, page.cursor, now_millis())?;
        *data = merged.data;
        space.state = merged.state;
        counters.rejected.extend(merged.rejected);
        if !page.more {
            return Ok(page.manifest);
        }
    }
    Err(SyncError::Misbehaving("demasiadas páginas en una descarga"))
}

fn check_manifest(
    space: &SpaceSync<'_>,
    blob: Option<ManifestBlob>,
    rejected: &[Rejected],
) -> Result<Manifest, SyncError> {
    let Some(blob) = blob else {
        // Nadie ha subido nada. Si este equipo ya había visto un manifiesto, el servidor
        // está devolviendo un estado anterior.
        if space.state.manifest_version > 0 {
            return Err(ManifestError::Rollback {
                got: 0,
                seen: space.state.manifest_version,
            }
            .into());
        }
        return Ok(Manifest::empty());
    };
    let manifest = Manifest::open(&blob.blob, blob.version, space.key)?;
    let ignored: Vec<_> = rejected
        .iter()
        .map(|r| (space.key.record_id(&r.key), r.hlc))
        .collect();
    manifest.verify(&space.state, space.key, &ignored)?;
    Ok(manifest)
}

/// Sube lo pendiente por lotes. Devuelve `false` si otro equipo subió antes y hay que
/// volver a descargar.
async fn push(
    session: &mut Session,
    space: &mut SpaceSync<'_>,
    data: &VaultData,
    mut manifest: Manifest,
    counters: &mut Counters,
) -> Result<bool, SyncError> {
    let outgoing = space.state.outgoing(data)?;
    let key = space.key;
    for chunk in outgoing.chunks(MAX_PUSH_RECORDS) {
        let next = manifest.with_pushed(chunk.iter().map(|e| (key.record_id(&e.key), e.hlc)));
        let request = PushRequest {
            epoch: space.epoch,
            base_version: manifest.version,
            manifest: ManifestBlob {
                version: next.version,
                blob: next.seal(key)?,
            },
            records: chunk
                .iter()
                .map(|e| key.seal_record(e))
                .collect::<Result<_, _>>()?,
        };
        let team = space.team;
        let pushed = call!(session, |api, token| api.push(token, team, &request));
        match pushed {
            Ok(response) if response.cursor < space.state.cursor => {
                return Err(SyncError::Misbehaving("el servidor retrocedió al guardar"));
            }
            Ok(_) => {
                space.state = space.state.acknowledge(chunk);
                space.state.manifest_version = next.version;
                counters.uploaded += chunk.len();
                manifest = next;
            }
            Err(SyncError::Conflict(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Sincroniza un espacio: `data` son solo sus elementos. Devuelve sus elementos y su
/// estado nuevos.
pub(crate) async fn sync_space(
    session: &mut Session,
    mut space: SpaceSync<'_>,
    mut data: VaultData,
    counters: &mut Counters,
) -> Result<(VaultData, SyncState), SyncError> {
    for _ in 0..MAX_ROUNDS {
        let manifest = pull(session, &mut space, &mut data, counters).await?;
        if push(session, &mut space, &data, manifest, counters).await? {
            return Ok((data, space.state));
        }
    }
    Err(SyncError::TooManyConflicts)
}

/// Sincroniza una vez la bóveda `data` con el servidor de `local`.
///
/// Trabaja sobre copias: si falla a medias, la bóveda y la configuración originales no
/// cambian, y lo pendiente se vuelve a intentar en la siguiente ronda. Un Team que falla
/// no impide sincronizar lo demás; queda anotado en [`SyncOutcome::team_problems`].
pub async fn sync_once(local: &SyncLocal, data: &VaultData) -> Result<SyncOutcome, SyncError> {
    tokio::time::timeout(ROUND_TIMEOUT, run_round(local, data))
        .await
        .map_err(|_| SyncError::Timeout)?
}

async fn run_round(local: &SyncLocal, data: &VaultData) -> Result<SyncOutcome, SyncError> {
    let mut local = local.clone();
    let mut session = Session::new(&local)?;
    let mut counters = Counters::default();

    // La bóveda personal va primero: así, si algo se mueve a un Team, el borrado del
    // espacio personal llega a los demás equipos antes que el alta en el Team.
    let personal = partition(data, Space::Personal);
    let space = SpaceSync {
        team: None,
        key: &local.vault_key,
        epoch: None,
        state: local.state.clone(),
    };
    let (merged, state) = sync_space(&mut session, space, personal.clone(), &mut counters).await?;
    let mut data = absorb(data, Space::Personal, &personal, &merged)?;
    local.state = state;

    if local.keypair.is_none() {
        let token = session.token().await?;
        local.keypair = keypair::try_fetch_or_create(&session.api, &token, &local.vault_key).await;
    }
    let team_problems = sync_teams(&mut session, &mut local, &mut data, &mut counters).await;
    local.token = session.into_token();
    Ok(SyncOutcome {
        data,
        local,
        rejected: counters.rejected,
        downloaded: counters.downloaded,
        uploaded: counters.uploaded,
        team_problems,
    })
}

/// Actualiza la lista de Teams y sincroniza cada uno.
async fn sync_teams(
    session: &mut Session,
    local: &mut SyncLocal,
    data: &mut VaultData,
    counters: &mut Counters,
) -> Vec<TeamProblem> {
    if local.keypair.is_none() {
        return Vec::new();
    }
    let mut problems = match teams::refresh(session, local, data).await {
        Ok((next, new_data, problems)) => {
            *local = next;
            *data = new_data;
            problems
        }
        Err(e) => {
            return vec![TeamProblem {
                team: String::new(),
                message: e.to_string(),
            }];
        }
    };
    let ids: Vec<String> = local
        .teams
        .iter()
        .map(|t| t.id.clone())
        .filter(|id| !problems.iter().any(|p| &p.team == id))
        .collect();
    for id in ids {
        if let Err(e) = sync_team(session, local, data, &id, counters).await {
            problems.push(TeamProblem {
                team: id,
                message: e.to_string(),
            });
        }
    }
    problems
}

async fn sync_team(
    session: &mut Session,
    local: &mut SyncLocal,
    data: &mut VaultData,
    id: &str,
    counters: &mut Counters,
) -> Result<(), SyncError> {
    let team = local
        .team(id)
        .cloned()
        .ok_or(SyncError::NotFound(id.into()))?;
    if team.rekey_needed && team.role == TeamRole::Admin {
        let (next, new_data) = teams::rotate_with(session, local, data, id).await?;
        *local = next;
        *data = new_data;
        return Ok(());
    }
    let part = partition(data, Space::Team(id));
    let space = SpaceSync {
        team: Some(id),
        key: &team.key,
        epoch: Some(team.epoch),
        state: team.state.clone(),
    };
    match sync_space(session, space, part.clone(), counters).await {
        Ok((merged, state)) => {
            *data = absorb(data, Space::Team(id), &part, &merged)?;
            if let Some(t) = local.teams.iter_mut().find(|t| t.id == id) {
                t.state = state;
            }
            Ok(())
        }
        // Alguien salió del Team y aún no se renovó la clave: lo hace cualquier admin.
        Err(SyncError::RekeyNeeded) if team.role == TeamRole::Admin => {
            let (next, new_data) = teams::rotate_with(session, local, data, id).await?;
            *local = next;
            *data = new_data;
            Ok(())
        }
        Err(e) => Err(e),
    }
}
