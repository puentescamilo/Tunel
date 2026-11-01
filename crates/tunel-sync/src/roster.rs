//! La lista de miembros de cada Team (ver [`tunel_core::sync::roster`]): de quién se
//! acepta una clave nueva, para quién se renueva y cómo se mantiene al día.

use crate::SyncError;
use crate::session::{Session, call};
use tunel_core::sync::local::normalize_email;
use tunel_core::sync::protocol::{RosterEntry, RosterRequest, TeamMember, TeamRole};
use tunel_core::sync::roster::Unverified;
use tunel_core::sync::{
    AccountKeypair, PublicKey, Roster, RosterMember, SyncLocal, TeamLocal, VaultKey,
};

/// Veces que se reintenta guardar la lista si otro admin la cambió entretanto.
const MAX_ROSTER_TRIES: usize = 3;

/// La clave con la que tiene que estar firmada `opened`: la de un admin de `anchor`, la
/// lista que ya se tiene. Sin ella, la de un admin de la propia lista cuya clave esté
/// fijada, como la de quien invitó.
fn signer(local: &SyncLocal, anchor: Option<&Roster>, opened: &Unverified) -> Option<PublicKey> {
    match anchor {
        Some(anchor) => anchor.admin_key(&opened.author),
        None => opened
            .roster
            .admin_key(&opened.author)
            .filter(|key| local.check_key(&opened.author, *key).is_ok()),
    }
}

/// Recorre desde `anchor` las versiones `entries` de la lista de `team` cifradas con `key`
/// en la época `epoch`; las de otras épocas se saltan. Cada una tiene que ser más nueva y
/// estar firmada por un admin de la anterior. Sin `anchor` solo cuenta la última, firmada
/// por un admin fijado (ver [`signer`]). Devuelve la lista con la que quedarse.
pub(crate) fn follow(
    local: &SyncLocal,
    team: &str,
    key: &VaultKey,
    epoch: u64,
    entries: &[RosterEntry],
    anchor: Option<Roster>,
) -> Result<Option<Roster>, SyncError> {
    let in_epoch: Vec<&RosterEntry> = entries.iter().filter(|e| e.epoch == epoch).collect();
    let start = if anchor.is_some() {
        0
    } else {
        in_epoch.len().saturating_sub(1)
    };
    let mut current = anchor;
    for entry in &in_epoch[start..] {
        if current
            .as_ref()
            .is_some_and(|c| entry.roster.version <= c.version)
        {
            continue;
        }
        let opened = Roster::open(&entry.roster, key, team, epoch)?;
        match signer(local, current.as_ref(), &opened) {
            Some(signer) if opened.signed_by(&signer) => current = Some(opened.roster),
            _ => return Err(SyncError::UntrustedRoster(opened.author)),
        }
    }
    Ok(current)
}

/// Comprueba que se puede aceptar la clave de una época nueva que envolvió `from`: tiene
/// que ser admin en la lista `roster` que ya se tiene. Sin lista, como antes: basta con
/// que su clave esté fijada.
pub(crate) fn check_new_key(
    local: &SyncLocal,
    roster: Option<&Roster>,
    from: &str,
    key: PublicKey,
) -> Result<(), SyncError> {
    match roster {
        Some(roster) if roster.is_admin(&normalize_email(from), &key) => Ok(()),
        Some(_) => Err(SyncError::UntrustedTeamKey(from.to_string())),
        None => Ok(local.check_key(from, key)?),
    }
}

/// La lista con la que renovar la clave: los miembros que da el servidor, con su rol en
/// `roster`. Cada uno tiene que estar en ella con la misma clave; si no, el servidor
/// podría haber vuelto a meter a alguien que se sacó. Sin lista, como antes: las claves
/// tienen que estar fijadas, y la lista empieza con lo que da el servidor.
pub(crate) fn for_rotation(
    local: &SyncLocal,
    roster: Option<&Roster>,
    members: &[TeamMember],
) -> Result<Roster, SyncError> {
    let Some(roster) = roster else {
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

/// Quien firma las listas que escribe esta cuenta: su correo y su par de claves.
pub(crate) fn author(local: &SyncLocal) -> Result<(String, &AccountKeypair), SyncError> {
    let pair = local.keypair.as_ref().ok_or(SyncError::NoKeypair)?;
    Ok((normalize_email(&local.email), pair))
}

/// La lista más reciente de `team` en el servidor, comprobada desde la que ya se tiene.
pub(crate) async fn latest(
    session: &mut Session,
    local: &SyncLocal,
    team: &TeamLocal,
) -> Result<Option<Roster>, SyncError> {
    let since = team.roster.as_ref().map_or(0, |r| r.version);
    let entries = call!(session, |api, token| api.rosters(token, &team.id, since))?;
    follow(
        local,
        &team.id,
        &team.key,
        team.epoch,
        &entries,
        team.roster.clone(),
    )
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
    let (me, pair) = author(local)?;
    let team = team.clone();
    for _ in 0..MAX_ROSTER_TRIES {
        let base = match latest(session, local, &team).await? {
            Some(roster) => roster,
            None => {
                let members = call!(session, |api, token| api.members(token, &team.id))?;
                let pinned = members
                    .iter()
                    .all(|m| local.check_key(&m.email, m.public_key).is_ok());
                if !pinned {
                    return Ok(team);
                }
                Roster::trusting(&members)
            }
        };
        let roster = base.with(&normalize_email(email), member);
        let request = RosterRequest {
            epoch: team.epoch,
            roster: roster.seal(&team.key, &team.id, team.epoch, &me, pair)?,
        };
        let added = call!(session, |api, token| api
            .add_roster(token, &team.id, &request));
        match added {
            Ok(()) => {
                return Ok(TeamLocal {
                    roster: Some(roster),
                    ..team
                });
            }
            // Otro admin la cambió entretanto: se vuelve a leer y se parte de la suya.
            Err(SyncError::Conflict(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Err(SyncError::TooManyConflicts)
}

/// Lo que dice la lista de `email` con el rol `role`, o, si no está, su clave fijada.
pub(crate) fn member_of(
    local: &SyncLocal,
    team: &TeamLocal,
    email: &str,
    key: PublicKey,
    role: TeamRole,
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
