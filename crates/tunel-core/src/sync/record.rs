//! La bóveda vista como registros independientes que se sincronizan uno a uno.
//!
//! Cada host, grupo, identidad, clave, snippet, túnel y clave de host conocida es un
//! registro. Los ajustes no se sincronizan: son propios de cada equipo.

use crate::model::KnownHost;
use crate::vault::VaultData;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    Host,
    Group,
    Identity,
    Key,
    Snippet,
    Forward,
    KnownHost,
}

impl RecordKind {
    const ALL: [Self; 7] = [
        Self::Host,
        Self::Group,
        Self::Identity,
        Self::Key,
        Self::Snippet,
        Self::Forward,
        Self::KnownHost,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Group => "group",
            Self::Identity => "identity",
            Self::Key => "key",
            Self::Snippet => "snippet",
            Self::Forward => "forward",
            Self::KnownHost => "known_host",
        }
    }
}

/// Identifica un registro: su tipo y su id dentro de ese tipo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct RecordKey {
    pub kind: RecordKind,
    pub id: String,
}

impl RecordKey {
    pub fn new(kind: RecordKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind.name(), self.id)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("identificador de registro no válido: {0}")]
pub struct InvalidRecordKey(String);

impl FromStr for RecordKey {
    type Err = InvalidRecordKey;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidRecordKey(text.to_string());
        let (name, id) = text.split_once('/').ok_or_else(invalid)?;
        let kind = RecordKind::ALL
            .into_iter()
            .find(|k| k.name() == name)
            .ok_or_else(invalid)?;
        if id.is_empty() {
            return Err(invalid());
        }
        Ok(Self::new(kind, id))
    }
}

impl From<RecordKey> for String {
    fn from(key: RecordKey) -> Self {
        key.to_string()
    }
}

impl TryFrom<String> for RecordKey {
    type Error = InvalidRecordKey;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

/// Cambio de un registro: su nuevo contenido o `None` si se borró.
#[derive(Clone, PartialEq)]
pub struct Change {
    pub key: RecordKey,
    pub value: Option<Value>,
}

/// El contenido puede llevar contraseñas y claves privadas: no se muestra.
impl fmt::Debug for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Change")
            .field("key", &self.key)
            .field("deleted", &self.value.is_none())
            .finish_non_exhaustive()
    }
}

/// Una clave de host conocida por host:puerto; confiar en otra sustituye a la anterior.
fn known_host_id(entry: &KnownHost) -> String {
    format!("{}:{}", entry.host.to_ascii_lowercase(), entry.port)
}

fn collect<T: Serialize>(
    out: &mut BTreeMap<RecordKey, Value>,
    kind: RecordKind,
    items: &[T],
    id_of: impl Fn(&T) -> String,
) -> Result<(), serde_json::Error> {
    for item in items {
        out.insert(
            RecordKey::new(kind, id_of(item)),
            serde_json::to_value(item)?,
        );
    }
    Ok(())
}

/// Todos los registros de la bóveda con su contenido.
pub fn records(data: &VaultData) -> Result<BTreeMap<RecordKey, Value>, serde_json::Error> {
    let mut out = BTreeMap::new();
    collect(&mut out, RecordKind::Host, &data.hosts, |h| {
        h.id.0.to_string()
    })?;
    collect(&mut out, RecordKind::Group, &data.groups, |g| {
        g.id.0.to_string()
    })?;
    collect(&mut out, RecordKind::Identity, &data.identities, |i| {
        i.id.0.to_string()
    })?;
    collect(&mut out, RecordKind::Key, &data.keys, |k| {
        k.id.0.to_string()
    })?;
    collect(&mut out, RecordKind::Snippet, &data.snippets, |s| {
        s.id.0.to_string()
    })?;
    collect(&mut out, RecordKind::Forward, &data.forwards, |f| {
        f.id.0.to_string()
    })?;
    collect(
        &mut out,
        RecordKind::KnownHost,
        &data.known_hosts,
        known_host_id,
    )?;
    Ok(out)
}

/// Registros que cambian de `old` a `new`, incluidos los borrados.
pub fn diff(old: &VaultData, new: &VaultData) -> Result<Vec<Change>, serde_json::Error> {
    let before = records(old)?;
    let after = records(new)?;
    let changed = after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
        .map(|(key, value)| Change {
            key: key.clone(),
            value: Some(value.clone()),
        });
    let deleted = before
        .keys()
        .filter(|key| !after.contains_key(*key))
        .map(|key| Change {
            key: key.clone(),
            value: None,
        });
    Ok(changed.chain(deleted).collect())
}

/// Lee el contenido de un registro y comprueba que es el elemento que dice ser: los
/// modelos admiten campos ausentes, así que sin esta comprobación cualquier JSON valdría.
fn decode<T: DeserializeOwned>(
    value: &Value,
    id: &str,
    id_of: &impl Fn(&T) -> String,
) -> Result<T, serde_json::Error> {
    let item: T = serde_json::from_value(value.clone())?;
    if id_of(&item) != id {
        return Err(serde::de::Error::custom(format!(
            "el registro {id} contiene otro elemento"
        )));
    }
    Ok(item)
}

/// Aplica los cambios de un tipo a su lista, conservando el orden de lo que ya estaba
/// y añadiendo al final lo nuevo.
fn apply_kind<T: Serialize + DeserializeOwned + Clone>(
    items: &[T],
    kind: RecordKind,
    changes: &[Change],
    id_of: impl Fn(&T) -> String,
) -> Result<Vec<T>, serde_json::Error> {
    let for_kind: HashMap<&str, &Option<Value>> = changes
        .iter()
        .filter(|c| c.key.kind == kind)
        .map(|c| (c.key.id.as_str(), &c.value))
        .collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let id = id_of(item);
        match for_kind.get(id.as_str()) {
            None => out.push(item.clone()),
            Some(None) => {}
            Some(Some(value)) => out.push(decode(value, &id, &id_of)?),
        }
        seen.insert(id);
    }
    for change in changes.iter().filter(|c| c.key.kind == kind) {
        if let (Some(value), false) = (&change.value, seen.contains(&change.key.id)) {
            out.push(decode(value, &change.key.id, &id_of)?);
            seen.insert(change.key.id.clone());
        }
    }
    Ok(out)
}

/// Devuelve la bóveda con los cambios aplicados; los ajustes se quedan como estaban.
pub fn apply(data: &VaultData, changes: &[Change]) -> Result<VaultData, serde_json::Error> {
    Ok(VaultData {
        hosts: apply_kind(&data.hosts, RecordKind::Host, changes, |h| {
            h.id.0.to_string()
        })?,
        groups: apply_kind(&data.groups, RecordKind::Group, changes, |g| {
            g.id.0.to_string()
        })?,
        identities: apply_kind(&data.identities, RecordKind::Identity, changes, |i| {
            i.id.0.to_string()
        })?,
        keys: apply_kind(&data.keys, RecordKind::Key, changes, |k| k.id.0.to_string())?,
        snippets: apply_kind(&data.snippets, RecordKind::Snippet, changes, |s| {
            s.id.0.to_string()
        })?,
        forwards: apply_kind(&data.forwards, RecordKind::Forward, changes, |f| {
            f.id.0.to_string()
        })?,
        known_hosts: apply_kind(
            &data.known_hosts,
            RecordKind::KnownHost,
            changes,
            known_host_id,
        )?,
        settings: data.settings.clone(),
    })
}

/// Comprueba que un cambio se puede aplicar, sin aplicarlo.
pub fn validate(change: &Change) -> Result<(), serde_json::Error> {
    apply(&VaultData::default(), std::slice::from_ref(change)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, Host, Settings};

    fn sample() -> VaultData {
        VaultData::default()
            .with_host(Host::new("web", "10.0.0.1"))
            .with_host(Host::new("db", "10.0.0.2"))
            .trust_host_key(KnownHost {
                host: "Web".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:a".into(),
            })
    }

    #[test]
    fn record_key_round_trips_through_text() {
        let key = RecordKey::new(RecordKind::KnownHost, "web:22");
        assert_eq!(key.to_string(), "known_host/web:22");
        assert_eq!("known_host/web:22".parse::<RecordKey>(), Ok(key));
        assert!("otro/1".parse::<RecordKey>().is_err());
        assert!("host/".parse::<RecordKey>().is_err());
        assert!("sin-barra".parse::<RecordKey>().is_err());
    }

    #[test]
    fn records_cover_every_kind_and_skip_settings() {
        let data = sample().with_group(Group::new("Prod"));
        let keys: Vec<String> = records(&data)
            .unwrap()
            .keys()
            .map(|k| k.kind.name().to_string())
            .collect();
        assert_eq!(keys.iter().filter(|k| *k == "host").count(), 2);
        assert!(keys.contains(&"group".to_string()));
        assert!(keys.contains(&"known_host".to_string()));
    }

    #[test]
    fn diff_reports_added_changed_and_deleted_records() {
        let old = sample();
        let web = old.hosts[0].clone();
        let db = old.hosts[1].id;
        let new = old
            .with_host(Host {
                label: "web-nuevo".into(),
                ..web.clone()
            })
            .without_host(db)
            .with_host(Host::new("cache", "10.0.0.3"));
        let changes = diff(&old, &new).unwrap();
        let summary: Vec<(String, bool)> = changes
            .iter()
            .map(|c| (c.key.to_string(), c.value.is_some()))
            .collect();
        assert_eq!(changes.len(), 3, "{summary:?}");
        assert!(summary.contains(&(format!("host/{}", web.id.0), true)));
        assert!(summary.contains(&(format!("host/{}", db.0), false)));
    }

    #[test]
    fn diff_of_identical_vaults_is_empty() {
        let data = sample();
        assert!(diff(&data, &data.clone()).unwrap().is_empty());
    }

    #[test]
    fn diff_ignores_settings() {
        let old = sample();
        let new = old.with_settings(Settings {
            font_size: 20.0,
            ..old.settings.clone()
        });
        assert!(diff(&old, &new).unwrap().is_empty());
    }

    #[test]
    fn applying_the_diff_reproduces_the_new_vault() {
        let old = sample();
        let new = old
            .without_host(old.hosts[0].id)
            .with_host(Host::new("cache", "10.0.0.3"))
            .with_group(Group::new("Prod"));
        let rebuilt = apply(&old, &diff(&old, &new).unwrap()).unwrap();
        assert_eq!(rebuilt, new);
    }

    #[test]
    fn apply_keeps_local_settings_and_order() {
        let local = sample().with_settings(Settings {
            font_size: 18.0,
            ..Settings::default()
        });
        let edited = Host {
            label: "editado".into(),
            ..local.hosts[1].clone()
        };
        let change = Change {
            key: RecordKey::new(RecordKind::Host, edited.id.0.to_string()),
            value: Some(serde_json::to_value(&edited).unwrap()),
        };
        let merged = apply(&local, &[change]).unwrap();
        assert_eq!(merged.settings.font_size, 18.0);
        assert_eq!(merged.hosts[0], local.hosts[0]);
        assert_eq!(merged.hosts[1].label, "editado");
    }

    #[test]
    fn apply_rejects_records_that_do_not_match_the_model() {
        let change = |value| Change {
            key: RecordKey::new(RecordKind::Host, uuid::Uuid::from_u128(7).to_string()),
            value: Some(value),
        };
        let other = Host::new("otro", "1.1.1.1");
        for value in [
            serde_json::json!({"no": "es un host"}),
            serde_json::json!({"id": 5}),
            serde_json::to_value(&other).unwrap(),
        ] {
            assert!(apply(&VaultData::default(), &[change(value)]).is_err());
        }
    }
}
