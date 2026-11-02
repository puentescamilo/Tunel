//! Registro de auditoría de los Teams (ver `tunel_core::sync::audit`): subir lo que espera
//! en la cola y leer el registro, que solo pueden los admins.

use crate::SyncError;
use crate::session::{Session, call};
use std::collections::BTreeMap;
use tunel_core::sync::audit::{AuditAction, SignedAuditEvent, clean_name, open_previous_key};
use tunel_core::sync::local::normalize_email;
use tunel_core::sync::protocol::{AuditPage, AuditUpload, MAX_AUDIT_UPLOAD, PreviousKey};
use tunel_core::sync::{PublicKey, SyncLocal, TeamLocal, VaultKey};

/// Lo que salió de una subida: los identificadores de lo que ya está en el servidor y,
/// si algo falló, el error; lo que falta sigue en la cola.
pub(crate) struct Flushed {
    pub sent: Vec<String>,
    pub error: Option<SyncError>,
}

/// Sube las entradas de la cola de `team`, de cien en cien.
pub(crate) async fn flush(session: &mut Session, local: &SyncLocal, team: &TeamLocal) -> Flushed {
    let pending: Vec<(String, &SignedAuditEvent)> = local
        .audit_queue
        .iter()
        .filter(|q| q.team == team.id)
        .filter_map(|q| Some((q.event.id()?, &q.event)))
        .collect();
    let mut sent = Vec::new();
    for chunk in pending.chunks(MAX_AUDIT_UPLOAD) {
        if let Err(error) = upload(session, team, chunk).await {
            // Un servidor anterior al registro no lo admite: la cola espera, con su tope.
            return Flushed {
                sent,
                error: Some(error),
            };
        }
        sent.extend(chunk.iter().map(|(id, _)| id.clone()));
    }
    Flushed { sent, error: None }
}

async fn upload(
    session: &mut Session,
    team: &TeamLocal,
    chunk: &[(String, &SignedAuditEvent)],
) -> Result<(), SyncError> {
    let upload = AuditUpload {
        epoch: team.epoch,
        entries: chunk
            .iter()
            .map(|(_, event)| event.seal(&team.key, &team.id, team.epoch))
            .collect::<Result<_, _>>()?,
    };
    call!(session, |api, token| api
        .add_audit(token, &team.id, &upload))
}

/// Anota `action` en el registro de `team` y la sube ya, sin esperar a la siguiente
/// ronda: para lo que cambia los miembros, como salir del Team, tras lo cual ya no se
/// podría. Si no se puede subir, queda en la cola. Devuelve también lo que se subió.
pub async fn record_now(
    local: &SyncLocal,
    team: &str,
    action: AuditAction,
) -> (SyncLocal, Vec<String>) {
    let Some(queued) = local.record_audit(team, action, crate::now_millis()) else {
        return (local.clone(), Vec::new());
    };
    let (Ok(mut session), Some(team)) = (Session::new(&queued), queued.team(team).cloned()) else {
        return (queued, Vec::new());
    };
    let Flushed { sent, error } = flush(&mut session, &queued, &team).await;
    if let Some(e) = error {
        tracing::info!(error = %e, "el registro de auditoría se subirá más tarde");
    }
    let next = crate::teams::finish(session, queued.without_audit(&sent));
    (next, sent)
}

/// Cuánto se puede fiar una entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Firmada por quien dice haberla hecho, con la clave que se le conoce.
    Verified,
    /// No se conoce la clave de esa persona para comprobarlo.
    Unknown,
    /// La firma no es de esa persona, o la subió otra cuenta.
    Forged,
    /// Firmada por esa persona, pero es algo que solo hace un admin y ahora no lo es.
    NotAdmin,
    /// Está cifrada con una clave del Team que este equipo no tiene.
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: u64,
    /// El del evento, igual en todas sus copias; `None` si no se pudo descifrar.
    pub event_id: Option<String>,
    /// Milisegundos desde 1970: los de quien la hizo o, si no se pudo leer, los del
    /// servidor.
    pub at: u64,
    pub actor: String,
    /// `None` si no se pudo descifrar.
    pub action: Option<AuditAction>,
    pub trust: Trust,
    /// La fecha que puso quien la hizo y la de llegada al servidor no cuadran.
    pub clock_skew: bool,
}

/// Diferencia entre la fecha de una entrada y su llegada al servidor a partir de la cual se
/// avisa: una entrada puede esperar en la cola sin conexión, pero no tanto ni al revés.
const MAX_QUEUE_DELAY_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_AHEAD_MS: u64 = 10 * 60 * 1000;

fn skewed(at: u64, received_at: u64) -> bool {
    let received = received_at.saturating_mul(1000);
    at > received.saturating_add(MAX_CLOCK_AHEAD_MS)
        || received.saturating_sub(at) > MAX_QUEUE_DELAY_MS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
    /// Hay entradas más viejas: se piden con el `id` de la última.
    pub more: bool,
}

/// Las claves del Team por época, desde la actual hacia atrás mientras la cadena siga.
pub(crate) fn keys_by_epoch(team: &TeamLocal, previous: &[PreviousKey]) -> BTreeMap<u64, VaultKey> {
    let blobs: BTreeMap<u64, _> = previous.iter().map(|p| (p.epoch, &p.blob)).collect();
    let mut keys = BTreeMap::new();
    let mut epoch = team.epoch;
    let mut key = team.key.clone();
    while let Some(older) = epoch
        .checked_sub(1)
        .and_then(|_| blobs.get(&epoch))
        .and_then(|blob| open_previous_key(&key, blob, &team.id, epoch).ok())
    {
        keys.insert(epoch, std::mem::replace(&mut key, older));
        epoch -= 1;
    }
    keys.insert(epoch, key);
    keys
}

/// La clave con la que firma `email`: la de la lista de miembros, la fijada al verla por
/// primera vez o, si es esta cuenta, la suya.
pub(crate) fn signer_key(local: &SyncLocal, team: &TeamLocal, email: &str) -> Option<PublicKey> {
    team.roster
        .as_ref()
        .and_then(|r| r.members.get(email))
        .map(|m| m.key)
        .or_else(|| local.contacts.get(email).map(|c| c.key))
        .or_else(|| {
            (normalize_email(&local.email) == email)
                .then(|| local.keypair.as_ref().map(|p| p.public()))
                .flatten()
        })
}

fn open_page(local: &SyncLocal, team: &TeamLocal, page: &AuditPage) -> AuditLog {
    let keys = keys_by_epoch(team, &page.previous_keys);
    let entries = page
        .entries
        .iter()
        .map(|record| {
            let unreadable = AuditEntry {
                id: record.id,
                event_id: None,
                at: record.received_at.saturating_mul(1000),
                actor: record.author.clone(),
                action: None,
                trust: Trust::Unreadable,
                clock_skew: false,
            };
            let Some(opened) = keys.get(&record.epoch).and_then(|key| {
                SignedAuditEvent::open(&record.blob, key, &team.id, record.epoch).ok()
            }) else {
                return unreadable;
            };
            let actor = clean_name(&normalize_email(&opened.event.actor));
            let action = opened.event.action.clone().cleaned();
            let not_admin = action.needs_admin()
                && team
                    .roster
                    .as_ref()
                    .is_some_and(|r| r.admin_key(&actor).is_none());
            let trust = match signer_key(local, team, &actor) {
                _ if actor != normalize_email(&record.author) => Trust::Forged,
                Some(key) if !opened.signed_by(&key) => Trust::Forged,
                Some(_) if not_admin => Trust::NotAdmin,
                Some(_) => Trust::Verified,
                None => Trust::Unknown,
            };
            AuditEntry {
                id: record.id,
                event_id: Some(opened.event.id.clone()),
                at: opened.event.at,
                actor,
                action: Some(action),
                trust,
                clock_skew: skewed(opened.event.at, record.received_at),
            }
        })
        .collect();
    let entries = without_repeats(entries);
    AuditLog {
        entries,
        more: page.more,
    }
}

/// Quita las copias repetidas de un mismo evento (reintentos o reenvíos del servidor) y
/// deja la que llegó primero, la más vieja: la página va de lo más nuevo a lo más viejo.
pub fn without_repeats(entries: Vec<AuditEntry>) -> Vec<AuditEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut kept: Vec<AuditEntry> = entries
        .into_iter()
        .rev()
        .filter(|e| e.event_id.as_ref().is_none_or(|id| seen.insert(id.clone())))
        .collect();
    kept.reverse();
    kept
}

/// Una página del registro de `team`, de lo más nuevo a lo más viejo, anterior a la
/// entrada `before` si se indica.
pub async fn read(
    local: &SyncLocal,
    team: &str,
    before: Option<u64>,
) -> Result<(SyncLocal, AuditLog), SyncError> {
    let team = local
        .team(team)
        .cloned()
        .ok_or_else(|| SyncError::NotFound(team.into()))?;
    let mut session = Session::new(local)?;
    let page = call!(&mut session, |api, token| api
        .audit(token, &team.id, before))?;
    let log = open_page(local, &team, &page);
    Ok((crate::teams::finish(session, local.clone()), log))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::sync::audit::{AuditEvent, seal_previous_key};
    use tunel_core::sync::protocol::{AuditRecord, TeamRole};
    use tunel_core::sync::{AccountKeypair, Contact, SyncState};

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn team(epoch: u64, key: VaultKey) -> TeamLocal {
        TeamLocal {
            id: TEAM.into(),
            name: "Infra".into(),
            role: TeamRole::Admin,
            epoch,
            key,
            state: SyncState::new(uuid::Uuid::from_u128(1)),
            rekey_needed: false,
            roster: None,
        }
    }

    fn local_with(contacts: &[(&str, PublicKey)]) -> SyncLocal {
        let mut local: SyncLocal = serde_json::from_value(serde_json::json!({
            "server": "https://tunel.ejemplo.com",
            "email": "admin@ejemplo.com",
            "auth": "",
            "vault_key": VaultKey::generate(),
            "token": null,
            "state": SyncState::new(uuid::Uuid::from_u128(1)),
        }))
        .unwrap();
        for (email, key) in contacts {
            local.contacts.insert(
                (*email).into(),
                Contact {
                    key: *key,
                    verified: true,
                },
            );
        }
        local
    }

    fn record(
        id: u64,
        epoch: u64,
        key: &VaultKey,
        author: &str,
        signer: &AccountKeypair,
    ) -> AuditRecord {
        let event = AuditEvent {
            id: format!("e{id}"),
            team: TEAM.into(),
            actor: "ana@ejemplo.com".into(),
            at: 1_700_000_000_000 + id,
            action: AuditAction::Connected { host: "web".into() },
        };
        AuditRecord {
            id,
            epoch,
            author: author.into(),
            received_at: 1_700_000_000,
            blob: SignedAuditEvent::sign(&event, signer)
                .unwrap()
                .seal(key, TEAM, epoch)
                .unwrap(),
        }
    }

    #[test]
    fn entries_of_older_epochs_are_read_through_the_key_chain() {
        let ana = AccountKeypair::generate();
        let keys: Vec<VaultKey> = (0..3).map(|_| VaultKey::generate()).collect();
        let previous_keys = (1..3)
            .map(|epoch| PreviousKey {
                epoch,
                blob: seal_previous_key(
                    &keys[epoch as usize],
                    &keys[epoch as usize - 1],
                    TEAM,
                    epoch,
                )
                .unwrap(),
            })
            .collect();
        let page = AuditPage {
            entries: (0..3)
                .map(|e| record(e + 1, e, &keys[e as usize], "ana@ejemplo.com", &ana))
                .collect(),
            previous_keys,
            more: false,
        };
        let local = local_with(&[("ana@ejemplo.com", ana.public())]);
        let log = open_page(&local, &team(2, keys[2].clone()), &page);
        assert!(
            log.entries.iter().all(|e| e.trust == Trust::Verified),
            "{log:?}"
        );
        assert_eq!(
            log.entries[0].action,
            Some(AuditAction::Connected { host: "web".into() })
        );
    }

    #[test]
    fn repeated_copies_of_an_event_are_shown_once() {
        let ana = AccountKeypair::generate();
        let key = VaultKey::generate();
        let copy = record(1, 0, &key, "ana@ejemplo.com", &ana);
        let page = AuditPage {
            entries: vec![
                AuditRecord {
                    id: 9,
                    ..copy.clone()
                },
                copy,
            ],
            previous_keys: Vec::new(),
            more: false,
        };
        let local = local_with(&[("ana@ejemplo.com", ana.public())]);
        let log = open_page(&local, &team(0, key), &page);
        let ids: Vec<u64> = log.entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, [1], "se queda la que llegó primero");
    }

    #[test]
    fn admin_actions_by_a_member_and_odd_dates_are_flagged() {
        use tunel_core::sync::{Roster, RosterMember};
        let ana = AccountKeypair::generate();
        let key = VaultKey::generate();
        let event = AuditEvent {
            id: "e1".into(),
            team: TEAM.into(),
            actor: "ana@ejemplo.com".into(),
            at: 1_700_000_000_000,
            action: AuditAction::MemberRemoved {
                email: "bob@ejemplo.com".into(),
            },
        };
        let page = AuditPage {
            entries: vec![AuditRecord {
                id: 1,
                epoch: 0,
                author: "ana@ejemplo.com".into(),
                // Llega un mes después de su fecha.
                received_at: 1_700_000_000 + 30 * 24 * 3600,
                blob: SignedAuditEvent::sign(&event, &ana)
                    .unwrap()
                    .seal(&key, TEAM, 0)
                    .unwrap(),
            }],
            previous_keys: Vec::new(),
            more: false,
        };
        let mut roster = Roster::default();
        roster.members.insert(
            "ana@ejemplo.com".into(),
            RosterMember {
                key: ana.public(),
                role: TeamRole::Member,
            },
        );
        let team = TeamLocal {
            roster: Some(roster),
            ..team(0, key)
        };
        let log = open_page(&local_with(&[]), &team, &page);
        assert_eq!(log.entries[0].trust, Trust::NotAdmin);
        assert!(log.entries[0].clock_skew);
        assert!(!skewed(1_000_000, 1_000));
        assert!(skewed(1_000_000 + MAX_CLOCK_AHEAD_MS + 1, 1_000));
    }

    #[test]
    fn a_broken_chain_leaves_old_entries_unreadable() {
        let ana = AccountKeypair::generate();
        let old = VaultKey::generate();
        let current = VaultKey::generate();
        let page = AuditPage {
            entries: vec![record(1, 0, &old, "ana@ejemplo.com", &ana)],
            previous_keys: Vec::new(),
            more: true,
        };
        let log = open_page(&local_with(&[]), &team(1, current), &page);
        assert_eq!(log.entries[0].trust, Trust::Unreadable);
        assert_eq!(log.entries[0].actor, "ana@ejemplo.com");
        assert!(log.more);
    }

    #[test]
    fn forged_or_relayed_entries_are_flagged() {
        let ana = AccountKeypair::generate();
        let eve = AccountKeypair::generate();
        let key = VaultKey::generate();
        let local = local_with(&[("ana@ejemplo.com", ana.public())]);
        let page = AuditPage {
            entries: vec![
                // Eva firma en nombre de Ana.
                record(1, 0, &key, "ana@ejemplo.com", &eve),
                // Eva sube una entrada auténtica de Ana como suya.
                record(2, 0, &key, "eva@ejemplo.com", &ana),
            ],
            previous_keys: Vec::new(),
            more: false,
        };
        let log = open_page(&local, &team(0, key.clone()), &page);
        assert_eq!(log.entries[0].trust, Trust::Forged);
        assert_eq!(log.entries[1].trust, Trust::Forged);
        let unknown = open_page(&local_with(&[]), &team(0, key), &page);
        assert_eq!(unknown.entries[0].trust, Trust::Unknown);
    }
}
