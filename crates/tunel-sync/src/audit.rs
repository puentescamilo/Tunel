//! Registro de auditoría de los Teams (ver `tunel_core::sync::audit`): subir lo que espera
//! en la cola y leer el registro, que solo pueden los admins.

use crate::SyncError;
use crate::session::{Session, call};
use std::collections::BTreeMap;
use tunel_core::sync::audit::{AuditAction, SignedAuditEvent, open_previous_key};
use tunel_core::sync::local::normalize_email;
use tunel_core::sync::protocol::{AuditPage, AuditUpload, MAX_AUDIT_UPLOAD, PreviousKey};
use tunel_core::sync::{PublicKey, SyncLocal, TeamLocal, VaultKey};

/// Sube las entradas de la cola de `team`. Devuelve los identificadores de las que ya no
/// hay que subir: las aceptadas y las que nunca se podrán subir.
pub(crate) async fn flush(
    session: &mut Session,
    local: &SyncLocal,
    team: &TeamLocal,
) -> Result<Vec<String>, SyncError> {
    let pending: Vec<(String, &SignedAuditEvent)> = local
        .audit_queue
        .iter()
        .filter(|q| q.team == team.id)
        .filter_map(|q| Some((q.event.id()?, &q.event)))
        .collect();
    let mut sent = Vec::new();
    for chunk in pending.chunks(MAX_AUDIT_UPLOAD) {
        let upload = AuditUpload {
            epoch: team.epoch,
            entries: chunk
                .iter()
                .map(|(_, event)| event.seal(&team.key, &team.id, team.epoch))
                .collect::<Result<_, _>>()?,
        };
        match call!(session, |api, token| api
            .add_audit(token, &team.id, &upload))
        {
            // Un servidor anterior al registro no tiene la ruta: no se guardarán nunca.
            Ok(()) | Err(SyncError::NotFound(_)) => {
                sent.extend(chunk.iter().map(|(id, _)| id.clone()));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(sent)
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
    match flush(&mut session, &queued, &team).await {
        Ok(sent) => {
            let next = crate::teams::finish(session, queued.without_audit(&sent));
            (next, sent)
        }
        Err(e) => {
            tracing::info!(error = %e, "el registro de auditoría se subirá más tarde");
            (queued, Vec::new())
        }
    }
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
    /// Está cifrada con una clave del Team que este equipo no tiene.
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: u64,
    /// Milisegundos desde 1970: los de quien la hizo o, si no se pudo leer, los del
    /// servidor.
    pub at: u64,
    pub actor: String,
    /// `None` si no se pudo descifrar.
    pub action: Option<AuditAction>,
    pub trust: Trust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
    /// Hay entradas más viejas: se piden con el `id` de la última.
    pub more: bool,
}

/// Las claves del Team por época, desde la actual hacia atrás mientras la cadena siga.
fn keys_by_epoch(team: &TeamLocal, previous: &[PreviousKey]) -> BTreeMap<u64, VaultKey> {
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
fn signer_key(local: &SyncLocal, team: &TeamLocal, email: &str) -> Option<PublicKey> {
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
                at: record.received_at.saturating_mul(1000),
                actor: record.author.clone(),
                action: None,
                trust: Trust::Unreadable,
            };
            let Some(opened) = keys.get(&record.epoch).and_then(|key| {
                SignedAuditEvent::open(&record.blob, key, &team.id, record.epoch).ok()
            }) else {
                return unreadable;
            };
            let actor = normalize_email(&opened.event.actor);
            let trust = match signer_key(local, team, &actor) {
                _ if actor != normalize_email(&record.author) => Trust::Forged,
                Some(key) if opened.signed_by(&key) => Trust::Verified,
                Some(_) => Trust::Forged,
                None => Trust::Unknown,
            };
            AuditEntry {
                id: record.id,
                at: opened.event.at,
                actor,
                action: Some(opened.event.action),
                trust,
            }
        })
        .collect();
    AuditLog {
        entries,
        more: page.more,
    }
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
