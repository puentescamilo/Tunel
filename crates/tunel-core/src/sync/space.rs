//! Espacios de sincronización: la bóveda personal y la de cada Team.
//!
//! Localmente hay una sola bóveda. Cada elemento dice en su campo `team` a qué Team
//! pertenece, o a ninguno si es personal, y cada espacio sincroniza solo los suyos con su
//! propia clave. Mover algo a un Team es cambiar ese campo: el espacio de origen lo ve
//! como un borrado y el de destino como un alta.
//!
//! Lo que llega de un Team nunca toca elementos de otro espacio, así un miembro no puede
//! sobrescribir la bóveda personal de nadie aunque conozca el identificador de algo suyo.

use super::record::{self, Change, RecordKind};
use crate::vault::VaultData;
use serde_json::Value;

/// Espacio al que pertenece un elemento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space<'a> {
    Personal,
    Team(&'a str),
}

impl Space<'_> {
    fn owns(&self, team: Option<&str>) -> bool {
        match self {
            Self::Personal => team.is_none(),
            Self::Team(id) => team == Some(*id),
        }
    }

    fn tag(&self) -> Value {
        match self {
            Self::Personal => Value::Null,
            Self::Team(id) => Value::String((*id).to_string()),
        }
    }
}

/// Los elementos de la bóveda que pertenecen a `space`. Las claves de host conocidas
/// son siempre personales: cada persona decide de qué servidores se fía.
pub fn partition(data: &VaultData, space: Space<'_>) -> VaultData {
    let keep = |team: &Option<String>| space.owns(team.as_deref());
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
        known_hosts: match space {
            Space::Personal => data.known_hosts.clone(),
            Space::Team(_) => Vec::new(),
        },
        settings: data.settings.clone(),
    }
}

/// Lleva a la bóveda completa lo que cambió en un espacio, de `before` a `after`.
///
/// Cada elemento queda marcado con su espacio, diga lo que diga el registro. Un cambio
/// de un Team sobre un elemento que ahora es de otro espacio se ignora; uno de la bóveda
/// personal sí se aplica, porque solo la escriben los equipos de la propia cuenta, y así
/// sacar algo de un Team llega a los demás equipos aunque se adelante al borrado.
pub fn absorb(
    data: &VaultData,
    space: Space<'_>,
    before: &VaultData,
    after: &VaultData,
) -> Result<VaultData, serde_json::Error> {
    let everything = record::records(data)?;
    let mine = record::records(&partition(data, space))?;
    let changes: Vec<Change> = record::diff(before, after)?
        .into_iter()
        .filter(|c| match space {
            Space::Personal => true,
            // Las claves de host conocidas nunca vienen de un Team: un miembro podría
            // hacer que se confiara en el servidor de un atacante sin preguntar.
            Space::Team(_) => {
                c.key.kind != RecordKind::KnownHost
                    && (!everything.contains_key(&c.key) || mine.contains_key(&c.key))
            }
        })
        .filter(|c| c.value.is_some() || mine.contains_key(&c.key))
        .map(|c| Change {
            value: c.value.map(|v| tagged(v, space)),
            key: c.key,
        })
        .collect();
    record::apply(data, &changes)
}

fn tagged(mut value: Value, space: Space<'_>) -> Value {
    if let Some(object) = value.as_object_mut() {
        match space.tag() {
            Value::Null => {
                object.remove("team");
            }
            tag => {
                object.insert("team".into(), tag);
            }
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, Host, KnownHost};

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn in_team(mut host: Host, team: &str) -> Host {
        host.team = Some(team.into());
        host
    }

    fn labels(data: &VaultData) -> Vec<&str> {
        data.hosts.iter().map(|h| h.label.as_str()).collect()
    }

    fn mixed() -> VaultData {
        VaultData {
            hosts: vec![
                Host::new("personal", "1.1.1.1"),
                in_team(Host::new("compartido", "2.2.2.2"), TEAM),
                in_team(Host::new("otro-team", "3.3.3.3"), "otro"),
            ],
            groups: vec![Group {
                team: Some(TEAM.into()),
                ..Group::default()
            }],
            known_hosts: vec![KnownHost {
                host: "web".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:x".into(),
            }],
            ..VaultData::default()
        }
    }

    #[test]
    fn each_space_sees_only_its_own_items() {
        let data = mixed();
        let personal = partition(&data, Space::Personal);
        assert_eq!(labels(&personal), ["personal"]);
        assert!(personal.groups.is_empty());
        assert_eq!(personal.known_hosts.len(), 1);
        let team = partition(&data, Space::Team(TEAM));
        assert_eq!(labels(&team), ["compartido"]);
        assert_eq!(team.groups.len(), 1);
        assert!(team.known_hosts.is_empty());
    }

    #[test]
    fn remote_team_changes_are_tagged_with_their_team() {
        let data = mixed();
        let before = partition(&data, Space::Team(TEAM));
        // El registro llega sin marca, o con la de otro Team: da igual.
        let new = in_team(Host::new("nuevo", "4.4.4.4"), "otro");
        let after = VaultData {
            hosts: [before.hosts.clone(), vec![new.clone()]].concat(),
            ..before.clone()
        };
        let merged = absorb(&data, Space::Team(TEAM), &before, &after).unwrap();
        let added = merged.hosts.iter().find(|h| h.id == new.id).unwrap();
        assert_eq!(added.team.as_deref(), Some(TEAM));
        assert_eq!(merged.hosts.len(), 4);
    }

    #[test]
    fn a_team_cannot_overwrite_or_delete_items_of_other_spaces() {
        let data = mixed();
        let personal = data.hosts[0].clone();
        let other_team = data.hosts[2].clone();
        let before = partition(&data, Space::Team(TEAM));
        let hijack = |mut host: Host| {
            host.address = "6.6.6.6".into();
            host
        };
        let after = VaultData {
            hosts: [
                before.hosts.clone(),
                vec![hijack(personal.clone()), hijack(other_team.clone())],
            ]
            .concat(),
            ..before.clone()
        };
        let merged = absorb(&data, Space::Team(TEAM), &before, &after).unwrap();
        assert_eq!(merged.hosts[0], personal);
        assert_eq!(merged.hosts[2], other_team);

        // Un borrado tampoco alcanza a lo que no es del Team.
        let with_personal = VaultData {
            hosts: [before.hosts.clone(), vec![personal.clone()]].concat(),
            ..before.clone()
        };
        let merged = absorb(&data, Space::Team(TEAM), &with_personal, &before).unwrap();
        assert!(merged.hosts.contains(&personal));
    }

    #[test]
    fn a_team_cannot_add_trusted_host_keys() {
        let data = mixed();
        let before = partition(&data, Space::Team(TEAM));
        let planted = KnownHost {
            host: "banco.ejemplo.com".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:atacante".into(),
        };
        let after = VaultData {
            known_hosts: vec![planted],
            ..before.clone()
        };
        let merged = absorb(&data, Space::Team(TEAM), &before, &after).unwrap();
        assert_eq!(merged.known_hosts, data.known_hosts);
    }

    #[test]
    fn moving_an_item_out_of_a_team_reaches_other_devices_in_any_order() {
        // En otro equipo, el host aún es del Team cuando llega su versión personal.
        let data = mixed();
        let shared = data.hosts[1].clone();
        let before = partition(&data, Space::Personal);
        let moved = Host {
            team: None,
            ..shared.clone()
        };
        let after = VaultData {
            hosts: [before.hosts.clone(), vec![moved]].concat(),
            ..before.clone()
        };
        let merged = absorb(&data, Space::Personal, &before, &after).unwrap();
        let now = merged.hosts.iter().find(|h| h.id == shared.id).unwrap();
        assert_eq!(now.team, None);

        // Y el borrado que llega después desde el Team ya no lo toca.
        let team_before = partition(&data, Space::Team(TEAM));
        let team_after = VaultData {
            hosts: Vec::new(),
            ..team_before.clone()
        };
        let merged = absorb(&merged, Space::Team(TEAM), &team_before, &team_after).unwrap();
        assert!(merged.hosts.iter().any(|h| h.id == shared.id));
    }

    #[test]
    fn local_edits_round_trip_without_changing_other_spaces() {
        let data = mixed();
        let before = partition(&data, Space::Team(TEAM));
        let mut after = before.clone();
        after.hosts[0].address = "9.9.9.9".into();
        let merged = absorb(&data, Space::Team(TEAM), &before, &after).unwrap();
        assert_eq!(merged.hosts[1].address, "9.9.9.9");
        assert_eq!(merged.hosts[0], data.hosts[0]);
        assert_eq!(merged.hosts[2], data.hosts[2]);
        assert_eq!(merged.known_hosts, data.known_hosts);
    }
}
