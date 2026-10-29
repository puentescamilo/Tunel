//! Estado de la sincronización de un equipo: qué versión tiene de cada registro, qué
//! cambios faltan por subir y hasta dónde ha leído del servidor.
//!
//! Se guarda junto a la bóveda local, así que los cambios hechos sin conexión siguen en
//! la cola aunque se cierre la aplicación. Todas las operaciones devuelven un estado nuevo.

use super::hlc::Hlc;
use super::keys::RecordEnvelope;
use super::record::{self, Change, RecordKey};
use crate::vault::VaultData;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Cuánto puede adelantarse la marca de un registro remoto a la hora local. Uno con una
/// marca más lejana (un reloj roto o un equipo malicioso) ganaría para siempre a cualquier
/// cambio posterior, así que se aparta en lugar de aplicarse.
pub const MAX_CLOCK_DRIFT_MILLIS: u64 = 24 * 60 * 60 * 1000;

/// Registro remoto que no se aplicó y por qué.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub key: RecordKey,
    pub reason: String,
}

/// Resultado de fusionar lo que llega del servidor.
#[derive(Debug, Clone, PartialEq)]
pub struct Merged {
    pub data: VaultData,
    pub state: SyncState,
    /// Registros apartados; el resto se aplica igualmente para no bloquear la sincronización.
    pub rejected: Vec<Rejected>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    pub device: Uuid,
    /// Última marca emitida por este equipo.
    pub clock: Hlc,
    /// Versión que tiene este equipo de cada registro, incluidos los borrados.
    pub versions: BTreeMap<RecordKey, Hlc>,
    /// Registros cambiados aquí que el servidor aún no ha confirmado.
    pub pending: BTreeSet<RecordKey>,
    /// Posición en el historial del servidor hasta la que ya se trajeron cambios.
    pub cursor: u64,
    /// Versión más alta del manifiesto que ha visto este equipo; una menor es un retroceso.
    #[serde(default)]
    pub manifest_version: u64,
}

impl SyncState {
    pub fn new(device: Uuid) -> Self {
        Self {
            device,
            clock: Hlc::zero(device),
            versions: BTreeMap::new(),
            pending: BTreeSet::new(),
            cursor: 0,
            manifest_version: 0,
        }
    }

    /// Estado de un equipo que empieza a sincronizar una bóveda que ya tenía contenido:
    /// todos sus registros quedan pendientes de subir.
    pub fn adopt(
        device: Uuid,
        data: &VaultData,
        wall_millis: u64,
    ) -> Result<Self, serde_json::Error> {
        Self::new(device).record_local(&VaultData::default(), data, wall_millis)
    }

    /// Anota los cambios locales de `old` a `new`, con una marca nueva cada uno.
    pub fn record_local(
        &self,
        old: &VaultData,
        new: &VaultData,
        wall_millis: u64,
    ) -> Result<Self, serde_json::Error> {
        let changes = record::diff(old, new)?;
        let mut next = self.clone();
        for change in changes {
            next.clock = next.clock.tick(wall_millis);
            next.versions.insert(change.key.clone(), next.clock);
            next.pending.insert(change.key);
        }
        Ok(next)
    }

    /// Cambios pendientes con su contenido actual, listos para cifrar y subir.
    pub fn outgoing(&self, data: &VaultData) -> Result<Vec<RecordEnvelope>, serde_json::Error> {
        let current = record::records(data)?;
        Ok(self
            .pending
            .iter()
            .filter_map(|key| {
                self.versions.get(key).map(|hlc| RecordEnvelope {
                    key: key.clone(),
                    hlc: *hlc,
                    value: current.get(key).cloned(),
                })
            })
            .collect())
    }

    /// El servidor guardó estos registros. Solo salen de la cola si no se volvieron a
    /// cambiar mientras se subían.
    pub fn acknowledge(&self, sent: &[RecordEnvelope]) -> Self {
        let mut next = self.clone();
        for envelope in sent {
            if next.versions.get(&envelope.key) == Some(&envelope.hlc) {
                next.pending.remove(&envelope.key);
            }
        }
        next
    }

    /// Fusiona los registros que llegan del servidor: gana la marca más reciente, así que
    /// un cambio local posterior se conserva y sigue en la cola para subirlo.
    ///
    /// Los registros con una marca demasiado adelantada o con un contenido que no encaja
    /// en el modelo se apartan en `rejected` y no cambian nada.
    pub fn merge_remote(
        &self,
        data: &VaultData,
        incoming: &[RecordEnvelope],
        cursor: u64,
        wall_millis: u64,
    ) -> Result<Merged, serde_json::Error> {
        let mut next = self.clone();
        let mut changes = Vec::new();
        let mut rejected = Vec::new();
        let horizon = wall_millis.saturating_add(MAX_CLOCK_DRIFT_MILLIS);
        for envelope in incoming {
            if envelope.hlc.millis > horizon {
                rejected.push(Rejected {
                    key: envelope.key.clone(),
                    reason: "marca de tiempo demasiado adelantada".into(),
                });
                continue;
            }
            let newer = next
                .versions
                .get(&envelope.key)
                .is_none_or(|local| envelope.hlc > *local);
            if !newer {
                continue;
            }
            let change = Change {
                key: envelope.key.clone(),
                value: envelope.value.clone(),
            };
            if let Err(e) = record::validate(&change) {
                rejected.push(Rejected {
                    key: envelope.key.clone(),
                    reason: e.to_string(),
                });
                continue;
            }
            next.clock = next.clock.observe(envelope.hlc, wall_millis);
            next.versions.insert(envelope.key.clone(), envelope.hlc);
            next.pending.remove(&envelope.key);
            changes.push(change);
        }
        next.cursor = next.cursor.max(cursor);
        Ok(Merged {
            data: record::apply(data, &changes)?,
            state: next,
            rejected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Host;

    fn device(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    /// Simula un servidor: guarda la última versión que recibe de cada registro.
    #[derive(Default)]
    struct Server {
        log: Vec<RecordEnvelope>,
    }

    impl Server {
        fn push(&mut self, records: &[RecordEnvelope]) {
            self.log.extend_from_slice(records);
        }

        fn since(&self, cursor: u64) -> (Vec<RecordEnvelope>, u64) {
            let start = (cursor as usize).min(self.log.len());
            (self.log[start..].to_vec(), self.log.len() as u64)
        }
    }

    /// Un equipo con su bóveda local y su estado.
    struct Device {
        data: VaultData,
        state: SyncState,
    }

    impl Device {
        fn new(n: u128) -> Self {
            Self {
                data: VaultData::default(),
                state: SyncState::new(device(n)),
            }
        }

        fn edit(&mut self, new: VaultData, wall: u64) {
            self.state = self.state.record_local(&self.data, &new, wall).unwrap();
            self.data = new;
        }

        fn sync(&mut self, server: &mut Server, wall: u64) {
            let outgoing = self.state.outgoing(&self.data).unwrap();
            server.push(&outgoing);
            self.state = self.state.acknowledge(&outgoing);
            let (incoming, cursor) = server.since(self.state.cursor);
            let merged = self
                .state
                .merge_remote(&self.data, &incoming, cursor, wall)
                .unwrap();
            assert!(merged.rejected.is_empty(), "{:?}", merged.rejected);
            self.data = merged.data;
            self.state = merged.state;
        }
    }

    #[test]
    fn local_changes_queue_until_acknowledged() {
        let mut laptop = Device::new(1);
        laptop.edit(
            VaultData::default().with_host(Host::new("web", "1.1.1.1")),
            1000,
        );
        assert_eq!(laptop.state.pending.len(), 1);

        let outgoing = laptop.state.outgoing(&laptop.data).unwrap();
        assert_eq!(outgoing[0].value.as_ref().unwrap()["label"], "web");
        assert!(laptop.state.acknowledge(&outgoing).pending.is_empty());
    }

    #[test]
    fn edits_made_while_uploading_stay_pending() {
        let mut laptop = Device::new(1);
        laptop.edit(
            VaultData::default().with_host(Host::new("web", "1.1.1.1")),
            1000,
        );
        let sent = laptop.state.outgoing(&laptop.data).unwrap();
        let host = laptop.data.hosts[0].clone();
        laptop.edit(
            laptop.data.with_host(Host {
                label: "web-2".into(),
                ..host
            }),
            1001,
        );
        assert_eq!(laptop.state.acknowledge(&sent).pending.len(), 1);
    }

    #[test]
    fn two_devices_converge() {
        let mut server = Server::default();
        let mut laptop = Device::new(1);
        let mut desktop = Device::new(2);

        laptop.edit(
            VaultData::default().with_host(Host::new("web", "1.1.1.1")),
            1000,
        );
        laptop.sync(&mut server, 1000);
        desktop.sync(&mut server, 1100);
        assert_eq!(desktop.data.hosts, laptop.data.hosts);

        let host = desktop.data.hosts[0].clone();
        desktop.edit(desktop.data.without_host(host.id), 1200);
        desktop.sync(&mut server, 1200);
        laptop.sync(&mut server, 1300);
        assert!(laptop.data.hosts.is_empty());
        assert!(laptop.state.pending.is_empty() && desktop.state.pending.is_empty());
    }

    #[test]
    fn offline_edits_survive_and_the_latest_edit_wins() {
        let mut server = Server::default();
        let mut laptop = Device::new(1);
        let mut desktop = Device::new(2);
        laptop.edit(
            VaultData::default().with_host(Host::new("web", "1.1.1.1")),
            1000,
        );
        laptop.sync(&mut server, 1000);
        desktop.sync(&mut server, 1000);
        let host = laptop.data.hosts[0].clone();

        // Los dos editan el mismo host sin conexión; el portátil lo hace más tarde.
        desktop.edit(
            desktop.data.with_host(Host {
                label: "de-escritorio".into(),
                ..host.clone()
            }),
            2000,
        );
        laptop.edit(
            laptop.data.with_host(Host {
                label: "de-portatil".into(),
                ..host
            }),
            3000,
        );
        // Además, cada uno crea un host propio.
        laptop.edit(
            laptop.data.with_host(Host::new("solo-portatil", "2.2.2.2")),
            3001,
        );
        desktop.edit(
            desktop
                .data
                .with_host(Host::new("solo-escritorio", "3.3.3.3")),
            2001,
        );

        desktop.sync(&mut server, 4000);
        laptop.sync(&mut server, 4000);
        desktop.sync(&mut server, 4100);

        for d in [&laptop, &desktop] {
            let labels: BTreeSet<&str> = d.data.hosts.iter().map(|h| h.label.as_str()).collect();
            assert_eq!(
                labels,
                BTreeSet::from(["de-portatil", "solo-portatil", "solo-escritorio"])
            );
            assert!(d.state.pending.is_empty());
        }
    }

    #[test]
    fn older_remote_versions_do_not_overwrite_local_changes() {
        let mut laptop = Device::new(1);
        laptop.edit(
            VaultData::default().with_host(Host::new("web", "1.1.1.1")),
            5000,
        );
        let mut stale = laptop.state.outgoing(&laptop.data).unwrap();
        stale[0].hlc = Hlc::zero(device(9)).tick(10);
        stale[0].value = Some(serde_json::json!(null));
        let merged = laptop
            .state
            .merge_remote(&laptop.data, &stale, 1, 6000)
            .unwrap();
        assert_eq!(merged.data, laptop.data);
        assert_eq!(merged.state.pending.len(), 1);
        assert_eq!(merged.state.cursor, 1);
    }

    fn remote_host(device_n: u128, millis: u64, value: serde_json::Value) -> RecordEnvelope {
        let host = Host::new("remoto", "9.9.9.9");
        RecordEnvelope {
            key: RecordKey::new(record::RecordKind::Host, host.id.0.to_string()),
            hlc: Hlc {
                millis,
                counter: 0,
                device: device(device_n),
            },
            value: Some(value),
        }
    }

    #[test]
    fn records_from_the_far_future_are_set_aside() {
        let laptop = Device::new(1);
        let host = Host::new("futuro", "1.1.1.1");
        let mut envelope = remote_host(2, u64::MAX, serde_json::to_value(&host).unwrap());
        envelope.key = RecordKey::new(record::RecordKind::Host, host.id.0.to_string());
        let merged = laptop
            .state
            .merge_remote(&laptop.data, &[envelope], 1, 1000)
            .unwrap();
        assert!(merged.data.hosts.is_empty());
        assert_eq!(merged.rejected.len(), 1);
        assert_eq!(merged.state.clock, laptop.state.clock);
        assert_eq!(merged.state.cursor, 1);
    }

    #[test]
    fn one_bad_record_does_not_block_the_others() {
        let laptop = Device::new(1);
        let good = Host::new("bueno", "1.1.1.1");
        let mut good_envelope = remote_host(2, 900, serde_json::to_value(&good).unwrap());
        good_envelope.key = RecordKey::new(record::RecordKind::Host, good.id.0.to_string());
        let bad = remote_host(2, 900, serde_json::json!({"no": "es un host"}));
        let merged = laptop
            .state
            .merge_remote(&laptop.data, &[bad.clone(), good_envelope], 2, 1000)
            .unwrap();
        assert_eq!(merged.data.hosts, vec![good]);
        assert_eq!(merged.rejected.len(), 1);
        assert_eq!(merged.rejected[0].key, bad.key);
        assert!(!merged.state.versions.contains_key(&bad.key));
        assert_eq!(merged.state.cursor, 2);
    }

    #[test]
    fn adopting_an_existing_vault_queues_everything() {
        let data = VaultData::default()
            .with_host(Host::new("a", "1"))
            .with_host(Host::new("b", "2"));
        let state = SyncState::adopt(device(1), &data, 1000).unwrap();
        assert_eq!(state.pending.len(), 2);
    }

    #[test]
    fn state_round_trips_through_json() {
        let data = VaultData::default().with_host(Host::new("a", "1"));
        let state = SyncState::adopt(device(1), &data, 1000).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<SyncState>(&json).unwrap(), state);
    }
}
