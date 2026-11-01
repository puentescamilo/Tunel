//! La lista de miembros de cada Team (ver [`tunel_core::sync::roster`]): de quién se
//! acepta una clave nueva, para quién se renueva y cómo se mantiene al día.

use crate::SyncError;
use crate::session::{Session, call};
use tunel_core::sync::local::normalize_email;
use tunel_core::sync::protocol::{RosterRequest, TeamMember};
use tunel_core::sync::{
    PublicKey, Roster, RosterMember, SealedBlob, SyncLocal, TeamLocal, VaultKey,
};

/// Comprueba que se puede aceptar la clave de una época nueva de `team` que envolvió
/// `from`: tiene que ser admin en la lista que ya se tiene. Sin lista, como antes: basta
/// con que su clave esté fijada.
pub(crate) fn check_new_key(
    local: &SyncLocal,
    team: &TeamLocal,
    from: &str,
    key: PublicKey,
) -> Result<(), SyncError> {
    match &team.roster {
        Some(roster) if roster.is_admin(&normalize_email(from), &key) => Ok(()),
        Some(_) => Err(SyncError::UntrustedTeamKey(from.to_string())),
        None => Ok(local.check_key(from, key)?),
    }
}

/// La lista que da el servidor, cifrada con `key` en la época `epoch`, o la que ya se
/// tenía (`current`) si no trae una o, en la misma época (`same_epoch`), no es más nueva.
pub(crate) fn received(
    blob: Option<&SealedBlob>,
    key: &VaultKey,
    team: &str,
    epoch: u64,
    current: Option<&Roster>,
    same_epoch: bool,
) -> Result<Option<Roster>, SyncError> {
    let Some(blob) = blob else {
        return Ok(current.cloned());
    };
    let roster = Roster::open(blob, key, team, epoch)?;
    let stale = same_epoch && current.is_some_and(|c| c.version >= roster.version);
    Ok(if stale {
        current.cloned()
    } else {
        Some(roster)
    })
}

/// La lista con la que renovar la clave: los miembros que da el servidor, con su rol en
/// la lista. Cada uno tiene que estar en ella con la misma clave; si no, el servidor
/// podría haber vuelto a meter a alguien que se sacó. Sin lista, como antes: las claves
/// tienen que estar fijadas, y la lista empieza con lo que da el servidor.
pub(crate) fn for_rotation(
    local: &SyncLocal,
    team: &TeamLocal,
    members: &[TeamMember],
) -> Result<Roster, SyncError> {
    let Some(roster) = &team.roster else {
        for member in members {
            local.check_key(&member.email, member.public_key)?;
        }
        return Ok(Roster::trusting(members));
    };
    let mut next = Roster {
        version: roster.version + 1,
        members: Default::default(),
    };
    for member in members {
        let listed = roster
            .members
            .get(&member.email)
            .filter(|m| m.key == member.public_key)
            .ok_or_else(|| SyncError::NotInRoster(member.email.clone()))?;
        next.members.insert(member.email.clone(), *listed);
    }
    Ok(next)
}

/// La lista más reciente de `team` en el servidor, si sigue en la misma época.
pub(crate) async fn latest(
    session: &mut Session,
    team: &TeamLocal,
) -> Result<Option<Roster>, SyncError> {
    let summaries = call!(session, |api, token| api.teams(token))?;
    let summary = summaries.iter().find(|s| s.id == team.id && !s.pending);
    match summary {
        Some(s) if s.epoch == team.epoch => received(
            s.roster.as_ref(),
            &team.key,
            &team.id,
            team.epoch,
            team.roster.as_ref(),
            true,
        ),
        _ => Err(SyncError::StaleKey),
    }
}

/// Guarda en el servidor la lista de `team` con `email` añadido o cambiado, y devuelve
/// `team` con ella. Un Team sin lista empieza una con los miembros que da el servidor
/// solo si todas sus claves están fijadas; si no, sigue sin lista.
pub(crate) async fn put_member(
    session: &mut Session,
    local: &SyncLocal,
    team: &TeamLocal,
    email: &str,
    member: RosterMember,
) -> Result<TeamLocal, SyncError> {
    let base = match latest(session, team).await? {
        Some(roster) => roster,
        None => {
            let members = call!(session, |api, token| api.members(token, &team.id))?;
            let pinned = members
                .iter()
                .all(|m| local.check_key(&m.email, m.public_key).is_ok());
            if !pinned {
                return Ok(team.clone());
            }
            Roster::trusting(&members)
        }
    };
    let roster = base.with(&normalize_email(email), member);
    let request = RosterRequest {
        epoch: team.epoch,
        roster: roster.seal(&team.key, &team.id, team.epoch)?,
    };
    call!(session, |api, token| api
        .set_roster(token, &team.id, &request))?;
    Ok(TeamLocal {
        roster: Some(roster),
        ..team.clone()
    })
}

/// Lo que dice la lista de `email`, o, si no está, su clave fijada con el rol `role`.
pub(crate) fn member_of(
    local: &SyncLocal,
    team: &TeamLocal,
    email: &str,
    key: PublicKey,
    role: tunel_core::sync::protocol::TeamRole,
) -> Result<RosterMember, SyncError> {
    let email = normalize_email(email);
    match team.roster.as_ref().and_then(|r| r.members.get(&email)) {
        Some(listed) => Ok(RosterMember { role, ..*listed }),
        None => {
            local.check_key(&email, key)?;
            Ok(RosterMember { key, role })
        }
    }
}
