//! Lo que Túnel guarda de Vaultwarden en este equipo y cómo completa con ello una conexión.
//!
//! La integración es opcional: sin cuenta configurada no hay archivo y
//! [`ResolvedHost::with_external`] no cambia nada. El protocolo vive en el crate
//! `tunel-vaultwarden`; aquí solo hay datos.

use crate::model::{SshKey, VaultwardenLink};
use crate::vault::ResolvedHost;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cuánto vale la copia local de un secreto sin volver a sincronizar.
pub const CACHE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// El secreto de un elemento de Vaultwarden, ya descifrado.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ExternalSecret {
    /// Nombre del elemento, para los avisos.
    pub name: String,
    /// Organización del elemento; `None` si es de la bóveda personal.
    #[serde(default)]
    pub organization_id: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Clave privada de un elemento *SSH Key*, en formato OpenSSH.
    pub private_key: Option<String>,
    /// Campo personalizado `enable` del elemento: la contraseña *enable* de un switch.
    #[serde(default)]
    pub enable: Option<String>,
}

impl std::fmt::Debug for ExternalSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalSecret")
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("private_key", &self.private_key.as_ref().map(|_| "***"))
            .field("enable", &self.enable.as_ref().map(|_| "***"))
            .finish_non_exhaustive()
    }
}

impl ResolvedHost {
    /// Completa la identidad vinculada a Vaultwarden con su secreto. Sin vínculo, o si
    /// `lookup` no lo tiene (sin cuenta, caducado o sin acceso), la deja como está: SSH
    /// pedirá la contraseña al conectar.
    ///
    /// El vínculo viene de la bóveda, que en un Team edita cualquier miembro: solo se usa el
    /// secreto si es de la organización que dice el vínculo y, en un Team, si es de una
    /// organización. Así un vínculo cambiado no saca un elemento personal de quien conecta.
    pub fn with_external(
        self,
        lookup: impl Fn(&VaultwardenLink) -> Option<ExternalSecret>,
    ) -> Self {
        let Some(identity) = self.identity.as_ref() else {
            return self;
        };
        let Some(secret) = identity
            .vaultwarden
            .as_ref()
            .and_then(|link| lookup(link).filter(|s| may_use(identity.team.as_deref(), link, s)))
        else {
            return self;
        };
        let Some(mut identity) = self.identity.clone() else {
            return self;
        };
        if identity.username.trim().is_empty()
            && let Some(username) = &secret.username
        {
            identity.username = username.clone();
        }
        if secret.password.is_some() {
            identity.password = secret.password.clone();
        }
        if secret.enable.is_some() {
            identity.enable_password = secret.enable.clone();
        }
        let key = match &secret.private_key {
            Some(private_key) => {
                let mut key = SshKey::new(secret.name.clone(), private_key.clone());
                key.team = identity.team.clone();
                identity.key = Some(key.id);
                Some(key)
            }
            None => self.key.clone(),
        };
        Self {
            identity: Some(identity),
            key,
            ..self
        }
    }
}

/// Si una identidad (personal o de un Team) puede usar el secreto al que apunta su vínculo.
fn may_use(team: Option<&str>, link: &VaultwardenLink, secret: &ExternalSecret) -> bool {
    secret.organization_id == link.organization_id
        && (team.is_none() || secret.organization_id.is_some())
}

/// Copia local de un secreto usado, con la fecha en que se descargó.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CachedSecret {
    pub item_id: String,
    pub secret: ExternalSecret,
    pub fetched_at_ms: u64,
}

/// La cuenta de Vaultwarden de este equipo. Va cifrada con la clave de la bóveda en
/// `<bóveda>.vaultwarden` y no se sincroniza.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultwardenLocal {
    pub server: String,
    pub email: String,
    /// Identificador fijo de este equipo para Vaultwarden.
    pub device_id: String,
    /// Para retomar la sesión sin la contraseña maestra de Vaultwarden.
    pub refresh_token: Option<String>,
    /// Clave de usuario de Vaultwarden (64 bytes en base64).
    pub user_key: Option<String>,
    #[serde(default)]
    pub cache: Vec<CachedSecret>,
}

impl std::fmt::Debug for VaultwardenLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultwardenLocal")
            .field("email", &self.email)
            .field("cached", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl Zeroize for CachedSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl VaultwardenLocal {
    /// El secreto de `item_id` si la copia no ha caducado.
    pub fn cached(&self, item_id: &str, now_ms: u64) -> Option<&ExternalSecret> {
        self.cache
            .iter()
            .find(|c| c.item_id == item_id)
            .filter(|c| now_ms.saturating_sub(c.fetched_at_ms) < CACHE_TTL_MS)
            .map(|c| &c.secret)
    }

    /// Sustituye la copia por los secretos recién descargados de los elementos en uso. Lo
    /// que ya no está (borrado o sin acceso) desaparece de la copia.
    pub fn with_cache(&self, fresh: Vec<(String, ExternalSecret)>, now_ms: u64) -> Self {
        let mut copy = self.clone();
        copy.cache = fresh
            .into_iter()
            .map(|(item_id, secret)| CachedSecret {
                item_id,
                secret,
                fetched_at_ms: now_ms,
            })
            .collect();
        copy
    }

    /// Lo mismo sin la sesión: al cerrarla hay que volver a escribir la contraseña.
    pub fn signed_out(&self) -> Self {
        let mut copy = self.clone();
        copy.refresh_token.zeroize();
        copy.user_key.zeroize();
        copy.refresh_token = None;
        copy.user_key = None;
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Host, Identity};

    fn resolved(identity: Option<Identity>, key: Option<SshKey>) -> ResolvedHost {
        ResolvedHost {
            host: Host::new("sw", "10.0.0.1"),
            port: 22,
            identity,
            key,
        }
    }

    fn linked(username: &str) -> Identity {
        let mut identity = Identity::new("Switches", username);
        identity.vaultwarden = Some(VaultwardenLink {
            item_id: "item-1".into(),
            organization_id: None,
        });
        identity
    }

    fn secret() -> ExternalSecret {
        ExternalSecret {
            name: "SW-Core".into(),
            organization_id: None,
            username: Some("admin".into()),
            password: Some("cisco".into()),
            private_key: None,
            enable: Some("en4ble".into()),
        }
    }

    #[test]
    fn without_a_link_nothing_changes_even_if_vaultwarden_has_secrets() {
        let local = Identity::new("Local", "ana").with_password("local");
        let before = resolved(Some(local), None);
        let after = before.clone().with_external(|_| Some(secret()));
        assert_eq!(after, before);
        let none = resolved(None, None);
        assert_eq!(none.clone().with_external(|_| Some(secret())), none);
    }

    #[test]
    fn a_linked_identity_takes_the_password_and_keeps_its_own_username() {
        let after = resolved(Some(linked("camilo")), None).with_external(|link| {
            assert_eq!(link.item_id, "item-1");
            Some(secret())
        });
        let identity = after.identity.unwrap();
        assert_eq!(identity.username, "camilo");
        assert_eq!(identity.password.as_deref(), Some("cisco"));
        assert_eq!(identity.enable_password.as_deref(), Some("en4ble"));

        let empty = resolved(Some(linked(" ")), None).with_external(|_| Some(secret()));
        assert_eq!(empty.identity.unwrap().username, "admin");
    }

    #[test]
    fn an_unavailable_secret_leaves_the_identity_without_password() {
        let before = resolved(Some(linked("camilo")), None);
        let after = before.clone().with_external(|_| None);
        assert_eq!(after, before);
        assert!(after.identity.unwrap().password.is_none());
    }

    #[test]
    fn an_ssh_key_item_becomes_the_key_of_the_connection() {
        let ssh = ExternalSecret {
            name: "Clave deploy".into(),
            organization_id: Some("org".into()),
            username: None,
            password: None,
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
            enable: None,
        };
        let mut identity = linked("deploy").with_team("acme");
        if let Some(link) = identity.vaultwarden.as_mut() {
            link.organization_id = Some("org".into());
        }
        let after = resolved(Some(identity), None).with_external(|_| Some(ssh.clone()));
        let key = after.key.unwrap();
        assert!(key.private_key.starts_with("-----BEGIN"));
        assert_eq!(key.team.as_deref(), Some("acme"));
        let identity = after.identity.unwrap();
        assert_eq!(identity.key, Some(key.id));
        assert!(identity.password.is_none());
    }

    #[test]
    fn a_changed_link_cannot_pull_a_secret_from_somewhere_else() {
        let in_org = |org: Option<&str>| {
            let mut secret = secret();
            secret.organization_id = org.map(str::to_string);
            secret
        };
        let password = |identity: Identity, found: ExternalSecret| {
            resolved(Some(identity), None)
                .with_external(move |_| Some(found.clone()))
                .identity
                .unwrap()
                .password
                .clone()
        };
        // El vínculo dice «personal» pero el elemento es de una organización, y al revés.
        assert_eq!(password(linked("a"), in_org(Some("org"))), None);
        let mut to_org = linked("a");
        to_org.vaultwarden.as_mut().unwrap().organization_id = Some("org".into());
        assert_eq!(password(to_org.clone(), in_org(None)), None);
        assert_eq!(password(to_org.clone(), in_org(Some("otra"))), None);
        assert_eq!(
            password(to_org.clone(), in_org(Some("org"))).as_deref(),
            Some("cisco")
        );
        // En un Team, nunca un elemento personal de quien conecta.
        assert_eq!(password(linked("a").with_team("acme"), in_org(None)), None);
        assert_eq!(
            password(to_org.with_team("acme"), in_org(Some("org"))).as_deref(),
            Some("cisco")
        );
    }

    #[test]
    fn the_cached_copy_expires_after_seven_days() {
        let local =
            VaultwardenLocal::default().with_cache(vec![("item-1".into(), secret())], 1_000);
        assert!(local.cached("item-1", 1_000 + CACHE_TTL_MS - 1).is_some());
        assert!(local.cached("item-1", 1_000 + CACHE_TTL_MS).is_none());
        assert!(local.cached("otro", 1_000).is_none());

        let refreshed = local.with_cache(Vec::new(), 2_000);
        assert!(refreshed.cache.is_empty(), "lo que ya no está se olvida");
    }

    #[test]
    fn identities_without_a_link_serialize_as_before() {
        let plain = serde_json::to_value(Identity::new("a", "ana")).unwrap();
        assert!(plain.get("vaultwarden").is_none());
        let old: Identity = serde_json::from_value(plain).unwrap();
        assert!(old.vaultwarden.is_none());

        let with = serde_json::to_string(&linked("ana")).unwrap();
        let back: Identity = serde_json::from_str(&with).unwrap();
        assert_eq!(back.vaultwarden.as_ref().unwrap().item_id, "item-1");
    }

    #[test]
    fn debug_does_not_show_secrets() {
        let mut local = VaultwardenLocal::default().with_cache(vec![("i".into(), secret())], 0);
        local.refresh_token = Some("token-secreto".into());
        let text = format!("{local:?} {:?}", secret());
        assert!(
            !text.contains("cisco") && !text.contains("token-secreto"),
            "{text}"
        );
    }
}
