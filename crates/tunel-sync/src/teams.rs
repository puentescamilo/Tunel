//! Teams: bóvedas compartidas con otras cuentas del mismo servidor.
//!
//! Cada operación recibe la configuración y, si hace falta, la bóveda, y devuelve las
//! nuevas; quien llama las guarda.
//!
//! Las claves públicas de los demás solo se fijan cuando la persona decide: al invitar
//! (tras ver la huella del invitado) o al aceptar una invitación (tras ver la de quien
//! invita). Después, cualquier clave que dé el servidor tiene que coincidir con la fijada;
//! una distinta o una nunca confirmada detiene la operación en lugar de envolver la clave
//! del Team para un impostor o aceptar una suya.

use crate::SyncError;
use crate::roster;
use crate::run::{Counters, MAX_ROUNDS, SpaceSync, TeamProblem, pull};
use crate::session::{Session, call};
use tunel_core::sync::audit;
use tunel_core::sync::local::normalize_email;
use tunel_core::sync::protocol::{
    AddMemberRequest, CreateTeamRequest, ManifestBlob, MemberKey, RosterEntry, RotateTeamRequest,
    TeamRole, TeamSummary,
};
use tunel_core::sync::record::records;
use tunel_core::sync::space::{Space, absorb, partition};
use tunel_core::sync::team::{open_team_name, seal_team_name, unwrap_team_key, wrap_team_key};
use tunel_core::sync::{
    AccountKeypair, Invitation, KeyProblem, Manifest, PublicKey, RecordEnvelope, Roster,
    RosterMember, SyncLocal, SyncState, TeamKeyContext, TeamLocal, VaultKey,
};
use tunel_core::vault::VaultData;
use uuid::Uuid;

/// Tope del nombre de un Team, en caracteres.
pub const MAX_TEAM_NAME_CHARS: usize = 60;

/// Un miembro tal como lo muestra la interfaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    pub email: String,
    pub role: TeamRole,
    pub pending: bool,
    /// Clave que da el servidor, y su huella.
    pub public_key: PublicKey,
    pub fingerprint: String,
    pub key: KeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// La propia cuenta.
    Own,
    /// Coincide con la fijada y la persona comparó la huella.
    Verified,
    /// Coincide con la fijada, pero nadie comparó la huella.
    Pinned,
    /// Todavía no se había visto.
    New,
    /// No coincide con la fijada: posible suplantación.
    Changed,
}

fn keypair(local: &SyncLocal) -> Result<&AccountKeypair, SyncError> {
    local.keypair.as_ref().ok_or(SyncError::NoKeypair)
}

fn admin_team<'a>(local: &'a SyncLocal, team: &str) -> Result<&'a TeamLocal, SyncError> {
    match local.team(team) {
        Some(t) if t.role == TeamRole::Admin => Ok(t),
        Some(_) => Err(SyncError::Forbidden(
            "solo un administrador del Team puede hacerlo".into(),
        )),
        None => Err(SyncError::NotFound(team.into())),
    }
}

/// Quita de la bóveda los elementos de un Team del que ya no se es miembro.
fn without_team(data: &VaultData, team: &str) -> VaultData {
    let keep = |t: &Option<String>| t.as_deref() != Some(team);
    VaultData {
        hosts: data
            .hosts
            .iter()
            .filter(|x| keep(&x.team))
            .cloned()
            .collect(),
        groups: data
            .groups
            .iter()
            .filter(|x| keep(&x.team))
            .cloned()
            .collect(),
        identities: data
            .identities
            .iter()
            .filter(|x| keep(&x.team))
            .cloned()
            .collect(),
        keys: data
            .keys
            .iter()
            .filter(|x| keep(&x.team))
            .cloned()
            .collect(),
        snippets: data
            .snippets
            .iter()
            .filter(|x| keep(&x.team))
            .cloned()
            .collect(),
        forwards: data
            .forwards
            .iter()
            .filter(|x| keep(&x.team))
            .cloned()
            .collect(),
        ..data.clone()
    }
}

/// Recibe un Team de la lista del servidor con las versiones nuevas de su lista de
/// miembros (`rosters`): comprueba quién envolvió la clave, que la época no retrocede y,
/// si es nueva, la abre.
fn adopt(
    local: &SyncLocal,
    summary: &TeamSummary,
    rosters: &[RosterEntry],
) -> Result<TeamLocal, SyncError> {
    let existing = local.team(&summary.id);
    // Lo que se sabía de la lista al terminar la época que ya se tenía.
    let mut anchor = None;
    if let Some(team) = existing {
        if summary.epoch < team.epoch {
            return Err(SyncError::KeyRollback);
        }
        let roster = roster::follow(
            local,
            &team.id,
            &team.key,
            team.epoch,
            rosters,
            team.roster.clone(),
        )?;
        if summary.epoch == team.epoch {
            return Ok(TeamLocal {
                role: summary.role,
                rekey_needed: summary.rekey_needed,
                roster,
                ..team.clone()
            });
        }
        // La clave nueva de un Team que ya se tenía solo se acepta de un admin de su
        // lista de miembros.
        roster::check_new_key(
            local,
            roster.as_ref(),
            &summary.wrapped_by,
            summary.wrapped_by_key,
        )?;
        anchor = roster;
    } else {
        // La de uno nuevo, de alguien cuya clave ya se confirmó.
        local.check_key(&summary.wrapped_by, summary.wrapped_by_key)?;
    }
    let wrapped = summary
        .key
        .as_ref()
        .ok_or(SyncError::Misbehaving("un Team aceptado llegó sin clave"))?;
    let context = TeamKeyContext {
        team: &summary.id,
        epoch: summary.epoch,
    };
    let key = unwrap_team_key(wrapped, context, keypair(local)?, &summary.wrapped_by_key)?;
    let name = match &summary.name {
        Some(blob) => open_team_name(&key, &summary.id, blob)?,
        None => String::new(),
    };
    let roster = roster::follow(local, &summary.id, &key, summary.epoch, rosters, anchor)?;
    // Con una clave nueva el servidor volvió a cifrar todo: se descarga desde el
    // principio, conservando las versiones y lo pendiente de subir.
    let state = match existing {
        Some(team) => SyncState {
            cursor: 0,
            ..team.state.clone()
        },
        None => SyncState::new(local.state.device),
    };
    let team = TeamLocal {
        id: summary.id.clone(),
        name,
        role: summary.role,
        epoch: summary.epoch,
        key,
        state,
        rekey_needed: summary.rekey_needed,
        roster,
    };
    Ok(team)
}

/// Las versiones de la lista de miembros de `summary` que este equipo todavía no tiene.
async fn new_rosters(
    session: &mut Session,
    local: &SyncLocal,
    summary: &TeamSummary,
) -> Result<Vec<RosterEntry>, SyncError> {
    let Some(latest) = summary.roster_version else {
        return Ok(Vec::new());
    };
    let team = local.team(&summary.id);
    let have = team
        .and_then(|t| t.roster.as_ref())
        .map_or(0, |r| r.version);
    if team.is_some_and(|t| t.epoch == summary.epoch) && latest <= have {
        return Ok(Vec::new());
    }
    call!(session, |api, token| api.rosters(token, &summary.id, have))
}

/// Pone al día la lista de Teams e invitaciones. De los Teams que ya no aparecen (se
/// salió, lo sacaron o se borró) se quitan sus elementos de la bóveda. Un Team que no se
/// puede recibir (clave cambiada, época anterior) se conserva como estaba y se devuelve
/// entre los problemas, para no sincronizarlo en esta ronda.
pub(crate) async fn refresh(
    session: &mut Session,
    local: &SyncLocal,
    data: &VaultData,
) -> Result<(SyncLocal, VaultData, Vec<TeamProblem>), SyncError> {
    let summaries = call!(session, |api, token| api.teams(token))?;
    let mut next = SyncLocal {
        invitations: summaries
            .iter()
            .filter(|s| s.pending)
            .map(|s| Invitation {
                team: s.id.clone(),
                from: s.wrapped_by.clone(),
                from_key: s.wrapped_by_key,
            })
            .collect(),
        ..local.clone()
    };
    let mut teams = Vec::new();
    let mut problems = Vec::new();
    for summary in summaries.iter().filter(|s| !s.pending) {
        let adopted = match new_rosters(session, &next, summary).await {
            Ok(rosters) => adopt(&next, summary, &rosters),
            Err(e) => Err(e),
        };
        match adopted {
            Ok(team) => teams.push(team),
            Err(e) => {
                // Se conserva lo que había; el problema se muestra y no se sincroniza.
                if let Some(old) = local.team(&summary.id) {
                    teams.push(old.clone());
                }
                problems.push(TeamProblem {
                    team: summary.id.clone(),
                    message: e.to_string(),
                });
            }
        }
    }
    // Un Team que falta de la lista se borra solo si el servidor confirma que ya no se es
    // miembro; si no, se conserva y se avisa, para no perder cambios por un error.
    let mut data = data.clone();
    for team in &local.teams {
        if summaries.iter().any(|s| !s.pending && s.id == team.id) {
            continue;
        }
        match call!(session, |api, token| api.members(token, &team.id)) {
            Err(SyncError::NotFound(_)) => data = without_team(&data, &team.id),
            _ => {
                teams.push(team.clone());
                problems.push(TeamProblem {
                    team: team.id.clone(),
                    message: "el servidor no lista este Team pero no confirma que se haya salido"
                        .into(),
                });
            }
        }
    }
    next.teams = teams;
    Ok((next, data, problems))
}

/// Guarda en la configuración el token con el que terminó la sesión.
pub(crate) fn finish(session: Session, local: SyncLocal) -> SyncLocal {
    SyncLocal {
        token: session.into_token(),
        ..local
    }
}

fn without_team_config(local: &SyncLocal, team: &str) -> SyncLocal {
    SyncLocal {
        teams: local
            .teams
            .iter()
            .filter(|t| t.id != team)
            .cloned()
            .collect(),
        invitations: local
            .invitations
            .iter()
            .filter(|i| i.team != team)
            .cloned()
            .collect(),
        ..local.clone()
    }
}

/// Crea un Team con esta cuenta como administradora. Devuelve su identificador.
pub async fn create_team(local: &SyncLocal, name: &str) -> Result<(SyncLocal, String), SyncError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_TEAM_NAME_CHARS {
        return Err(SyncError::InvalidName);
    }
    let pair = keypair(local)?;
    let mut session = Session::new(local)?;
    let id = Uuid::new_v4().to_string();
    let key = VaultKey::generate();
    let context = TeamKeyContext {
        team: &id,
        epoch: 0,
    };
    let me = RosterMember {
        key: pair.public(),
        role: TeamRole::Admin,
    };
    let (author, _) = roster::author(local)?;
    let roster = Roster::default().with(&author, me);
    let request = CreateTeamRequest {
        id: id.clone(),
        name: seal_team_name(&key, &id, name)?,
        key: wrap_team_key(&key, context, pair, &pair.public())?,
        roster: Some(roster.seal(&key, &id, 0, &author, pair)?),
    };
    call!(&mut session, |api, token| api.create_team(token, &request))?;
    let team = TeamLocal {
        id: id.clone(),
        name: name.to_string(),
        role: TeamRole::Admin,
        epoch: 0,
        key,
        state: SyncState::new(local.state.device),
        rekey_needed: false,
        roster: Some(roster),
    };
    let teams = [local.teams.clone(), vec![team]].concat();
    let next = SyncLocal {
        teams,
        ..local.clone()
    };
    Ok((finish(session, next), id))
}

/// Clave pública que da el servidor para `email`, para mostrar su huella antes de
/// invitarlo. No fija nada.
pub async fn lookup_key(
    local: &SyncLocal,
    email: &str,
) -> Result<(SyncLocal, PublicKey), SyncError> {
    let email = normalize_email(email);
    let mut session = Session::new(local)?;
    let found = call!(&mut session, |api, token| api.user_key(token, &email))?;
    Ok((finish(session, local.clone()), found.public_key))
}

/// Invita a `email` con la clave `confirmed`, cuya huella vio la persona (ver
/// [`lookup_key`]). Si el servidor da ahora otra, o ya había otra fijada, falla.
pub async fn invite(
    local: &SyncLocal,
    team: &str,
    email: &str,
    role: TeamRole,
    confirmed: PublicKey,
) -> Result<SyncLocal, SyncError> {
    let email = normalize_email(email);
    let pair = keypair(local)?;
    let team = admin_team(local, team)?;
    let mut session = Session::new(local)?;
    let found = call!(&mut session, |api, token| api.user_key(token, &email))?;
    if found.public_key != confirmed {
        return Err(KeyProblem::Changed(email).into());
    }
    let next = local.pin(&email, confirmed)?;
    // Primero la lista: si la invitación falla después, que sobre alguien en ella no
    // da acceso a nadie.
    let member = RosterMember {
        key: confirmed,
        role,
    };
    let listed = roster::put_member(&mut session, &next, team, &email, member).await?;
    let next = with_team(&next, listed);
    let context = TeamKeyContext {
        team: &team.id,
        epoch: team.epoch,
    };
    let request = AddMemberRequest {
        email: email.clone(),
        role,
        epoch: team.epoch,
        key: wrap_team_key(&team.key, context, pair, &confirmed)?,
    };
    call!(&mut session, |api, token| api
        .add_member(token, &team.id, &request))?;
    Ok(finish(session, next))
}

/// Acepta una invitación, fijando la clave de quien invita, cuya huella vio la persona;
/// el Team se recibe en la siguiente sincronización.
pub async fn accept_invitation(local: &SyncLocal, team: &str) -> Result<SyncLocal, SyncError> {
    let invitation = local
        .invitations
        .iter()
        .find(|i| i.team == team)
        .ok_or_else(|| SyncError::NotFound(team.into()))?;
    let pinned = local.pin(&invitation.from, invitation.from_key)?;
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api.accept(token, team))?;
    let next = SyncLocal {
        invitations: local
            .invitations
            .iter()
            .filter(|i| i.team != team)
            .cloned()
            .collect(),
        ..pinned
    };
    Ok(finish(session, next))
}

/// Rechaza una invitación o sale de un Team; sus elementos desaparecen de la bóveda.
pub async fn leave_team(
    local: &SyncLocal,
    data: &VaultData,
    team: &str,
) -> Result<(SyncLocal, VaultData), SyncError> {
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api.remove_member(
        token,
        team,
        &local.email
    ))?;
    let next = without_team_config(local, team);
    Ok((finish(session, next), without_team(data, team)))
}

/// Borra el Team para todos; solo un administrador.
pub async fn delete_team(
    local: &SyncLocal,
    data: &VaultData,
    team: &str,
) -> Result<(SyncLocal, VaultData), SyncError> {
    admin_team(local, team)?;
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api.delete_team(token, team))?;
    let next = without_team_config(local, team);
    Ok((finish(session, next), without_team(data, team)))
}

pub async fn set_role(
    local: &SyncLocal,
    team: &str,
    email: &str,
    role: TeamRole,
) -> Result<SyncLocal, SyncError> {
    let team = admin_team(local, team)?.clone();
    let email = normalize_email(email);
    let mut session = Session::new(local)?;
    // Se comprueba antes de cambiar nada que la persona está en la lista, o que se
    // conoce su clave.
    let members = call!(&mut session, |api, token| api.members(token, &team.id))?;
    let changed = members
        .iter()
        .find(|m| m.email == email)
        .ok_or_else(|| SyncError::NotFound(email.clone()))?;
    let member = match roster::member_of(local, &team, &email, changed.public_key, role) {
        Ok(member) => Some(member),
        // Un Team sin lista sigue sin ella hasta que se puedan confirmar las claves.
        Err(_) if team.roster.is_none() => None,
        Err(e) => return Err(e),
    };
    call!(&mut session, |api, token| api
        .set_role(token, &team.id, &email, role))?;
    let listed = match member {
        Some(member) => roster::put_member(&mut session, local, &team, &email, member).await?,
        None => team,
    };
    Ok(finish(session, with_team(local, listed)))
}

/// Enciende o apaga la grabación de las sesiones con los hosts del Team. Va en su lista de
/// miembros, firmada por este admin.
pub async fn set_recording(
    local: &SyncLocal,
    team: &str,
    on: bool,
) -> Result<SyncLocal, SyncError> {
    let team = admin_team(local, team)?.clone();
    let mut session = Session::new(local)?;
    let changed = roster::put(&mut session, local, &team, |base| base.recording(on))
        .await?
        .ok_or(SyncError::NoRoster)?;
    Ok(finish(session, with_team(local, changed)))
}

/// `local` con `team` en lugar del Team con su mismo identificador.
fn with_team(local: &SyncLocal, team: TeamLocal) -> SyncLocal {
    let teams = local
        .teams
        .iter()
        .map(|t| {
            if t.id == team.id {
                team.clone()
            } else {
                t.clone()
            }
        })
        .collect();
    SyncLocal {
        teams,
        ..local.clone()
    }
}

pub(crate) fn key_status(local: &SyncLocal, email: &str, key: PublicKey) -> KeyStatus {
    let own = normalize_email(email) == normalize_email(&local.email);
    match local.check_key(email, key) {
        Ok(()) if own => KeyStatus::Own,
        Ok(()) if local.contacts[&normalize_email(email)].verified => KeyStatus::Verified,
        Ok(()) => KeyStatus::Pinned,
        Err(KeyProblem::Unconfirmed(_)) => KeyStatus::New,
        Err(KeyProblem::Changed(_)) => KeyStatus::Changed,
    }
}

/// Miembros del Team con el estado de su clave frente a la fijada.
pub async fn members(
    local: &SyncLocal,
    team: &str,
) -> Result<(SyncLocal, Vec<MemberView>), SyncError> {
    let mut session = Session::new(local)?;
    let members = call!(&mut session, |api, token| api.members(token, team))?;
    let views = members
        .into_iter()
        .map(|m| MemberView {
            public_key: m.public_key,
            fingerprint: m.public_key.fingerprint(),
            key: key_status(local, &m.email, m.public_key),
            email: m.email,
            role: m.role,
            pending: m.pending,
        })
        .collect();
    Ok((finish(session, local.clone()), views))
}

/// Saca a un miembro o retira una invitación, y renueva la clave del Team para que
/// quien sale no pueda leer lo que se guarde después.
pub async fn remove_member(
    local: &SyncLocal,
    data: &VaultData,
    team: &str,
    email: &str,
) -> Result<(SyncLocal, VaultData), SyncError> {
    admin_team(local, team)?;
    let mut session = Session::new(local)?;
    call!(&mut session, |api, token| api
        .remove_member(token, team, email))?;
    let (next, data) = rotate_with(&mut session, local, data, team).await?;
    Ok((finish(session, next), data))
}

/// Renueva la clave del Team: descarga lo último, lo vuelve a cifrar todo con una
/// clave nueva y la envuelve para cada miembro, comprobando sus claves fijadas.
pub(crate) async fn rotate_with(
    session: &mut Session,
    local: &SyncLocal,
    data: &VaultData,
    team_id: &str,
) -> Result<(SyncLocal, VaultData), SyncError> {
    let pair = keypair(local)?.clone();
    let (author, _) = roster::author(local)?;
    let team = admin_team(local, team_id)?.clone();
    for _ in 0..MAX_ROUNDS {
        // Lo último del servidor, para no perder lo que otros subieron.
        let part = partition(data, Space::Team(team_id));
        let mut space = SpaceSync {
            team: Some(team_id),
            key: &team.key,
            epoch: Some(team.epoch),
            state: team.state.clone(),
        };
        let mut merged = part.clone();
        let mut counters = Counters::default();
        let manifest = pull(session, &mut space, &mut merged, &mut counters).await?;
        // Lo apartado no está en el estado y no se volvería a subir: se perdería para todos.
        if !counters.rejected.is_empty() {
            return Err(SyncError::RejectedRecords);
        }
        let state = space.state;

        let members = call!(session, |api, token| api.members(token, team_id))?;
        // La clave nueva solo se envuelve para quien está en la lista de miembros (o, sin
        // lista, para claves ya confirmadas): el servidor podría haber vuelto a meter a
        // alguien que se sacó, o añadido a alguien con una clave suya.
        let current = roster::latest(session, local, &team).await?;
        let next_roster = roster::for_rotation(local, current.as_ref(), &members)?;
        let pinned = local.clone();

        let epoch = team.epoch + 1;
        let key = VaultKey::generate();
        let context = TeamKeyContext {
            team: team_id,
            epoch,
        };
        let current = records(&merged)?;
        let envelopes: Vec<RecordEnvelope> = state
            .versions
            .iter()
            .map(|(k, hlc)| RecordEnvelope {
                key: k.clone(),
                hlc: *hlc,
                value: current.get(k).cloned(),
            })
            .collect();
        let next_manifest = Manifest {
            version: manifest.version,
            entries: Default::default(),
        }
        .with_pushed(envelopes.iter().map(|e| (key.record_id(&e.key), e.hlc)));
        let request = RotateTeamRequest {
            epoch,
            base_version: manifest.version,
            name: seal_team_name(&key, team_id, &team.name)?,
            keys: members
                .iter()
                .map(|m| {
                    Ok(MemberKey {
                        email: m.email.clone(),
                        key: wrap_team_key(&key, context, &pair, &m.public_key)?,
                    })
                })
                .collect::<Result<_, SyncError>>()?,
            manifest: ManifestBlob {
                version: next_manifest.version,
                blob: next_manifest.seal(&key)?,
            },
            records: envelopes
                .iter()
                .map(|e| key.seal_record(e))
                .collect::<Result<_, _>>()?,
            roster: Some(next_roster.seal(&key, team_id, epoch, &author, &pair)?),
            previous_key: Some(audit::seal_previous_key(&key, &team.key, team_id, epoch)?),
        };
        let rotated = call!(session, |api, token| api
            .rotate_team(token, team_id, &request));
        match rotated {
            Ok(response) => {
                let state = SyncState {
                    cursor: response.cursor,
                    manifest_version: next_manifest.version,
                    ..state.acknowledge(&envelopes)
                };
                let renewed = TeamLocal {
                    epoch,
                    key,
                    state,
                    rekey_needed: false,
                    roster: Some(next_roster),
                    ..team.clone()
                };
                let data = absorb(data, Space::Team(team_id), &part, &merged)?;
                return Ok((with_team(&pinned, renewed), data));
            }
            // Otro miembro subió algo entretanto, o cambiaron los miembros: otra vez.
            Err(SyncError::Conflict(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(SyncError::TooManyConflicts)
}
