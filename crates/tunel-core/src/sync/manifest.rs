//! Manifiesto autenticado: la lista de todos los registros de la bóveda con su versión.
//!
//! Lo escribe, cifrado con la clave de bóveda, el equipo que sube cambios, y su número de
//! versión solo puede crecer. Con él, un equipo detecta que el servidor le ocultó algún
//! registro o le dio una versión anterior a la última, y que no le devolvió un manifiesto
//! más antiguo que uno ya visto. El servidor no puede fabricar uno porque no tiene la clave.

use super::hlc::Hlc;
use super::keys::{SealedBlob, SyncCryptoError, VaultKey};
use super::state::SyncState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const AAD_MANIFEST: &[u8] = b"tunel-sync-manifiesto-v1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u64,
    /// Identificador opaco de cada registro y la versión más reciente subida.
    pub entries: BTreeMap<String, Hlc>,
}

/// Lo que falla al comprobar un manifiesto frente a lo que tiene el equipo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("el servidor devolvió una versión antigua de la bóveda ({got} < {seen})")]
    Rollback { got: u64, seen: u64 },
    #[error("faltan {} registros o están desactualizados", .0.len())]
    Incomplete(Vec<String>),
}

impl Manifest {
    pub fn empty() -> Self {
        Self {
            version: 0,
            entries: BTreeMap::new(),
        }
    }

    /// Manifiesto siguiente tras subir `pushed` (identificador opaco y versión).
    pub fn with_pushed(&self, pushed: impl IntoIterator<Item = (String, Hlc)>) -> Self {
        let mut entries = self.entries.clone();
        for (id, hlc) in pushed {
            let newest = entries.get(&id).map_or(hlc, |current| hlc.max(*current));
            entries.insert(id, newest);
        }
        Self {
            version: self.version + 1,
            entries,
        }
    }

    fn aad(version: u64) -> Vec<u8> {
        [AAD_MANIFEST, &version.to_be_bytes()].concat()
    }

    pub fn seal(&self, vault: &VaultKey) -> Result<SealedBlob, SyncCryptoError> {
        let plain = serde_json::to_vec(self).map_err(|_| SyncCryptoError::Corrupt)?;
        vault.seal_blob(&plain, &Self::aad(self.version))
    }

    /// Descifra el manifiesto que el servidor dice que tiene la versión `version`.
    pub fn open(
        blob: &SealedBlob,
        version: u64,
        vault: &VaultKey,
    ) -> Result<Self, SyncCryptoError> {
        let plain = vault.open_blob(blob, &Self::aad(version))?;
        let manifest: Self =
            serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)?;
        if manifest.version != version {
            return Err(SyncCryptoError::Mismatch);
        }
        Ok(manifest)
    }

    /// Comprueba que el equipo, con el estado `state`, tiene todo lo que el manifiesto
    /// dice que existe, en su última versión o una posterior, y que el manifiesto no es
    /// más antiguo que el último visto.
    ///
    /// `ignored` son registros auténticos que el equipo apartó, con la versión que vio. Solo
    /// justifican la ausencia si esa versión es la del manifiesto o una posterior; si no,
    /// el servidor podría reenviar una versión vieja apartada para ocultar la nueva.
    pub fn verify(
        &self,
        state: &SyncState,
        vault: &VaultKey,
        ignored: &[(String, Hlc)],
    ) -> Result<(), ManifestError> {
        if self.version < state.manifest_version {
            return Err(ManifestError::Rollback {
                got: self.version,
                seen: state.manifest_version,
            });
        }
        let local: BTreeMap<String, Hlc> = state
            .versions
            .iter()
            .map(|(key, hlc)| (vault.record_id(key), *hlc))
            .collect();
        let missing: Vec<String> = self
            .entries
            .iter()
            .filter(|(id, hlc)| {
                let set_aside = ignored
                    .iter()
                    .any(|(ignored_id, seen)| ignored_id == *id && seen >= *hlc);
                !set_aside && local.get(*id).is_none_or(|have| have < *hlc)
            })
            .map(|(id, _)| id.clone())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(ManifestError::Incomplete(missing))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Host;
    use crate::vault::VaultData;
    use uuid::Uuid;

    fn device(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    /// Estado de un equipo con un host y el manifiesto que correspondería a subirlo.
    fn synced() -> (SyncState, Manifest, VaultKey) {
        let vault = VaultKey::generate();
        let data = VaultData::default().with_host(Host::new("web", "1.1.1.1"));
        let state = SyncState::adopt(device(1), &data, 1000).unwrap();
        let pushed = state
            .versions
            .iter()
            .map(|(key, hlc)| (vault.record_id(key), *hlc));
        let manifest = Manifest::empty().with_pushed(pushed);
        (state, manifest, vault)
    }

    #[test]
    fn manifest_round_trips_and_is_bound_to_its_version() {
        let (_, manifest, vault) = synced();
        let sealed = manifest.seal(&vault).unwrap();
        assert_eq!(Manifest::open(&sealed, 1, &vault).unwrap(), manifest);
        assert!(Manifest::open(&sealed, 2, &vault).is_err());
        assert!(Manifest::open(&sealed, 1, &VaultKey::generate()).is_err());
    }

    #[test]
    fn with_pushed_keeps_the_newest_version_of_each_record() {
        let old = Hlc::zero(device(1)).tick(10);
        let new = old.tick(20);
        let manifest = Manifest::empty()
            .with_pushed([("a".to_string(), new)])
            .with_pushed([("a".to_string(), old), ("b".to_string(), old)]);
        assert_eq!(manifest.version, 2);
        assert_eq!(manifest.entries["a"], new);
        assert_eq!(manifest.entries["b"], old);
    }

    #[test]
    fn a_complete_device_passes() {
        let (state, manifest, vault) = synced();
        assert_eq!(manifest.verify(&state, &vault, &[]), Ok(()));
    }

    #[test]
    fn a_withheld_record_is_detected() {
        let (_, manifest, vault) = synced();
        let fresh = SyncState::new(device(2));
        assert!(matches!(
            manifest.verify(&fresh, &vault, &[]),
            Err(ManifestError::Incomplete(missing)) if missing.len() == 1
        ));
    }

    #[test]
    fn an_older_version_of_a_record_is_detected() {
        let (state, manifest, vault) = synced();
        let (key, hlc) = state.versions.iter().next().unwrap();
        let newer = manifest.with_pushed([(vault.record_id(key), hlc.tick(5000))]);
        assert!(newer.verify(&state, &vault, &[]).is_err());
    }

    #[test]
    fn ignored_records_do_not_count_as_missing() {
        let (_, manifest, vault) = synced();
        let ignored: Vec<(String, Hlc)> = manifest
            .entries
            .iter()
            .map(|(id, hlc)| (id.clone(), *hlc))
            .collect();
        let fresh = SyncState::new(device(2));
        assert_eq!(manifest.verify(&fresh, &vault, &ignored), Ok(()));
    }

    #[test]
    fn an_older_set_aside_version_does_not_excuse_a_newer_record() {
        let (_, manifest, vault) = synced();
        let older: Vec<(String, Hlc)> = manifest
            .entries
            .iter()
            .map(|(id, hlc)| {
                let earlier = Hlc {
                    millis: hlc.millis - 1,
                    ..*hlc
                };
                (id.clone(), earlier)
            })
            .collect();
        let fresh = SyncState::new(device(2));
        assert!(manifest.verify(&fresh, &vault, &older).is_err());
    }

    #[test]
    fn an_older_manifest_than_one_already_seen_is_a_rollback() {
        let (state, manifest, vault) = synced();
        let seen = SyncState {
            manifest_version: 5,
            ..state
        };
        assert_eq!(
            manifest.verify(&seen, &vault, &[]),
            Err(ManifestError::Rollback { got: 1, seen: 5 })
        );
    }
}
