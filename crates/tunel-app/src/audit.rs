//! Lo que esta app anota en el registro de auditoría de los Teams (ver
//! `tunel_core::sync::audit`): conexiones a sus hosts, contraseñas vistas o cambiadas, y
//! quién entra o sale.

use crate::app::TunelApp;
use std::collections::HashMap;
use tunel_core::sync::audit::{AuditAction, clean_name};
use tunel_core::vault::VaultData;
use tunel_core::{HostId, Identity, KeyId, SshKey};

pub fn record(app: &mut TunelApp, team: &str, action: AuditAction) {
    crate::sync::record_audit(app, team, action);
}

/// Se abrió una sesión con `host`; si es de un Team, se anota.
pub fn connected(app: &mut TunelApp, data: &VaultData, host: HostId) {
    let Some(host) = data.host(host) else {
        return;
    };
    if let Some(team) = host.team.clone() {
        let host = clean_name(host.display_name());
        record(app, &team, AuditAction::Connected { host });
    }
}

/// Se mostró la contraseña guardada de `identity`; si es de un Team, se anota.
pub fn secret_viewed(app: &mut TunelApp, identity: &Identity) {
    if let Some(team) = identity.team.clone() {
        let item = clean_name(&identity.label);
        record(app, &team, AuditAction::SecretViewed { item });
    }
}

fn identity_secret(i: &Identity) -> (Option<&str>, Option<KeyId>) {
    (i.password.as_deref(), i.key)
}

fn key_secret(k: &SshKey) -> (&str, Option<&str>) {
    (&k.private_key, k.passphrase.as_deref())
}

/// Los elementos de Teams cuya contraseña o clave privada cambió de `old` a `new`: cada
/// uno con su Team. Un elemento que solo se mueve a un Team no cuenta.
pub fn secret_changes(old: &VaultData, new: &VaultData) -> Vec<(String, AuditAction)> {
    let old_identities: HashMap<_, _> = old.identities.iter().map(|i| (i.id, i)).collect();
    let old_keys: HashMap<_, _> = old.keys.iter().map(|k| (k.id, k)).collect();
    let identities = new.identities.iter().filter_map(|i| {
        let team = i.team.clone()?;
        let before = old_identities.get(&i.id).map(|o| identity_secret(o));
        let has_secret = i.password.is_some() || i.key.is_some();
        (has_secret && before != Some(identity_secret(i))).then_some((team, i.label.as_str()))
    });
    let keys = new.keys.iter().filter_map(|k| {
        let team = k.team.clone()?;
        let before = old_keys.get(&k.id).map(|o| key_secret(o));
        (before != Some(key_secret(k))).then_some((team, k.label.as_str()))
    });
    identities
        .chain(keys)
        .map(|(team, label)| {
            let item = clean_name(label);
            (team, AuditAction::SecretChanged { item })
        })
        .collect()
}

/// Anota los cambios de contraseñas de Teams de un cambio local recién guardado.
pub fn after_commit(app: &mut TunelApp, old: &VaultData, new: &VaultData) {
    for (team, action) in secret_changes(old, new) {
        record(app, &team, action);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "infra";

    fn shared(identity: Identity) -> Identity {
        identity.with_team(TEAM)
    }

    fn changed(item: &str) -> (String, AuditAction) {
        (
            TEAM.into(),
            AuditAction::SecretChanged { item: item.into() },
        )
    }

    #[test]
    fn a_new_password_on_a_team_identity_is_recorded() {
        let root = shared(Identity::new("root", "root"));
        let old = VaultData::default().with_identity(root.clone());
        let new = VaultData::default().with_identity(root.with_password("nueva"));
        assert_eq!(secret_changes(&old, &new), vec![changed("root")]);
        assert!(secret_changes(&new, &new).is_empty());
    }

    #[test]
    fn personal_items_and_moves_into_a_team_are_not_recorded() {
        let personal = Identity::new("mía", "ana").with_password("x");
        let old = VaultData::default().with_identity(personal.clone());
        let renamed = VaultData::default().with_identity(personal.with_password("y"));
        assert!(secret_changes(&old, &renamed).is_empty());
        let moved = VaultData::default().with_identity(shared(personal));
        assert!(secret_changes(&old, &moved).is_empty());
    }

    #[test]
    fn a_new_team_key_or_a_changed_passphrase_is_recorded() {
        let key = SshKey::new("deploy", "-----BEGIN OPENSSH PRIVATE KEY-----").with_team(TEAM);
        let added = VaultData::default().with_key(key.clone());
        assert_eq!(
            secret_changes(&VaultData::default(), &added),
            vec![changed("deploy")]
        );
        let passphrase = VaultData::default().with_key(key.with_passphrase("frase"));
        assert_eq!(secret_changes(&added, &passphrase), vec![changed("deploy")]);
    }
}
