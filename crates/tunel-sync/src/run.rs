//! Una ronda de sincronización: descargar, fusionar, comprobar y subir.

use crate::api::Api;
use crate::{SyncError, check_server_url, now_millis};
use tunel_core::sync::protocol::{
    MAX_PUSH_RECORDS, ManifestBlob, PullResponse, PushRequest, PushResponse,
};
use tunel_core::sync::state::Rejected;
use tunel_core::sync::{Manifest, ManifestError, SyncLocal};
use tunel_core::vault::VaultData;
use zeroize::Zeroizing;

/// Rondas de descargar y subir antes de rendirse si otros equipos suben a la vez.
const MAX_ROUNDS: usize = 5;
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
}

/// Sesión con el servidor que se renueva sola con la clave de acceso guardada.
struct Session<'a> {
    api: Api,
    local: &'a mut SyncLocal,
}

impl Session<'_> {
    async fn token(&mut self) -> Result<Zeroizing<String>, SyncError> {
        if let Some(token) = &self.local.token {
            return Ok(token.clone());
        }
        let session = self.api.login(&self.local.email, &self.local.auth).await?;
        let token = Zeroizing::new(session.token);
        self.local.token = Some(token.clone());
        Ok(token)
    }

    /// El token caducó o se revocó: se inicia sesión de nuevo con la clave guardada.
    async fn renew(&mut self) -> Result<Zeroizing<String>, SyncError> {
        self.local.token = None;
        self.token().await
    }

    async fn pull(&mut self, since: u64) -> Result<PullResponse, SyncError> {
        let token = self.token().await?;
        match self.api.pull(&token, since).await {
            Err(SyncError::Unauthorized) => {
                let token = self.renew().await?;
                self.api.pull(&token, since).await
            }
            other => other,
        }
    }

    async fn push(&mut self, request: &PushRequest) -> Result<PushResponse, SyncError> {
        let token = self.token().await?;
        match self.api.push(&token, request).await {
            Err(SyncError::Unauthorized) => {
                let token = self.renew().await?;
                self.api.push(&token, request).await
            }
            other => other,
        }
    }
}

/// Descarga todo lo nuevo desde el cursor, lo fusiona y comprueba el manifiesto.
/// Devuelve el manifiesto actual, sobre el que se construye la siguiente subida.
async fn pull(
    session: &mut Session<'_>,
    data: &mut VaultData,
    rejected: &mut Vec<Rejected>,
    downloaded: &mut usize,
) -> Result<Manifest, SyncError> {
    let mut retried_from_start = false;
    loop {
        let manifest_blob = pull_pages(session, data, rejected, downloaded).await?;
        let checked = check_manifest(session.local, manifest_blob, rejected);
        match checked {
            Ok(manifest) => {
                session.local.state.manifest_version = manifest.version;
                return Ok(manifest);
            }
            // El cursor puede estar por delante del servidor (por ejemplo, si se restauró
            // de una copia) o el manifiesto puede no corresponder a lo descargado: se
            // descarga todo una vez más antes de dar la alarma.
            Err(SyncError::Integrity(ManifestError::Incomplete(_)) | SyncError::Crypto(_))
                if !retried_from_start && session.local.state.cursor > 0 =>
            {
                retried_from_start = true;
                session.local.state.cursor = 0;
                rejected.clear();
            }
            Err(e) => return Err(e),
        }
    }
}

async fn pull_pages(
    session: &mut Session<'_>,
    data: &mut VaultData,
    rejected: &mut Vec<Rejected>,
    downloaded: &mut usize,
) -> Result<Option<ManifestBlob>, SyncError> {
    for _ in 0..MAX_PAGES {
        let since = session.local.state.cursor;
        let page = session.pull(since).await?;
        if page.more && page.cursor <= since {
            return Err(SyncError::Misbehaving("la descarga no avanza"));
        }
        // Un registro que no se puede descifrar no se ignora: sería una forma de que el
        // servidor ocultara datos sin que el manifiesto lo delatara.
        let envelopes = page
            .records
            .iter()
            .map(|r| session.local.vault_key.open_record(r))
            .collect::<Result<Vec<_>, _>>()?;
        *downloaded += envelopes.len();
        let merged =
            session
                .local
                .state
                .merge_remote(data, &envelopes, page.cursor, now_millis())?;
        *data = merged.data;
        session.local.state = merged.state;
        rejected.extend(merged.rejected);
        if !page.more {
            return Ok(page.manifest);
        }
    }
    Err(SyncError::Misbehaving("demasiadas páginas en una descarga"))
}

fn check_manifest(
    local: &SyncLocal,
    blob: Option<ManifestBlob>,
    rejected: &[Rejected],
) -> Result<Manifest, SyncError> {
    let Some(blob) = blob else {
        // Nadie ha subido nada. Si este equipo ya había visto un manifiesto, el servidor
        // está devolviendo un estado anterior.
        if local.state.manifest_version > 0 {
            return Err(ManifestError::Rollback {
                got: 0,
                seen: local.state.manifest_version,
            }
            .into());
        }
        return Ok(Manifest::empty());
    };
    let manifest = Manifest::open(&blob.blob, blob.version, &local.vault_key)?;
    let ignored: Vec<_> = rejected
        .iter()
        .map(|r| (local.vault_key.record_id(&r.key), r.hlc))
        .collect();
    manifest.verify(&local.state, &local.vault_key, &ignored)?;
    Ok(manifest)
}

/// Sube lo pendiente por lotes. Devuelve `false` si otro equipo subió antes y hay que
/// volver a descargar.
async fn push(
    session: &mut Session<'_>,
    data: &VaultData,
    mut manifest: Manifest,
    uploaded: &mut usize,
) -> Result<bool, SyncError> {
    let outgoing = session.local.state.outgoing(data)?;
    for chunk in outgoing.chunks(MAX_PUSH_RECORDS) {
        let vault_key = &session.local.vault_key;
        let next = manifest.with_pushed(chunk.iter().map(|e| (vault_key.record_id(&e.key), e.hlc)));
        let request = PushRequest {
            base_version: manifest.version,
            manifest: ManifestBlob {
                version: next.version,
                blob: next.seal(vault_key)?,
            },
            records: chunk
                .iter()
                .map(|e| vault_key.seal_record(e))
                .collect::<Result<_, _>>()?,
        };
        match session.push(&request).await {
            Ok(response) if response.cursor < session.local.state.cursor => {
                return Err(SyncError::Misbehaving("el servidor retrocedió al guardar"));
            }
            Ok(_) => {
                session.local.state = session.local.state.acknowledge(chunk);
                session.local.state.manifest_version = next.version;
                *uploaded += chunk.len();
                manifest = next;
            }
            Err(SyncError::Conflict(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Sincroniza una vez la bóveda `data` con el servidor de `local`.
///
/// Trabaja sobre copias: si falla a medias, la bóveda y la configuración originales no
/// cambian, y lo pendiente se vuelve a intentar en la siguiente ronda.
pub async fn sync_once(local: &SyncLocal, data: &VaultData) -> Result<SyncOutcome, SyncError> {
    tokio::time::timeout(ROUND_TIMEOUT, run_round(local, data))
        .await
        .map_err(|_| SyncError::Timeout)?
}

async fn run_round(local: &SyncLocal, data: &VaultData) -> Result<SyncOutcome, SyncError> {
    let server = check_server_url(&local.server)?;
    let mut local = local.clone();
    let mut data = data.clone();
    let mut rejected = Vec::new();
    let (mut downloaded, mut uploaded) = (0, 0);
    let mut session = Session {
        api: Api::new(&server)?,
        local: &mut local,
    };
    let mut done = false;
    for _ in 0..MAX_ROUNDS {
        let manifest = pull(&mut session, &mut data, &mut rejected, &mut downloaded).await?;
        if push(&mut session, &data, manifest, &mut uploaded).await? {
            done = true;
            break;
        }
    }
    if !done {
        return Err(SyncError::TooManyConflicts);
    }
    Ok(SyncOutcome {
        data,
        local,
        rejected,
        downloaded,
        uploaded,
    })
}
