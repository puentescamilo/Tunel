//! La bóveda de Vaultwarden ya descifrada: las organizaciones, las colecciones y los
//! elementos que le sirven a Túnel (usuario y contraseña, y claves SSH).

use crate::VwError;
use crate::crypto::{CryptoError, EncString, PrivateKey, SymmetricKey, open_text, seal_text};
use crate::wire::{self, CipherData, SyncResponse};
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    /// La colección oculta las contraseñas a esta persona: se pueden usar, no mostrar.
    pub hide_passwords: bool,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Content {
    Login {
        username: Option<String>,
        password: Option<String>,
        uris: Vec<String>,
    },
    SshKey {
        private_key: String,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

/// Solo el tipo, para los registros.
impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Login { .. } => "Login(..)",
            Self::SshKey { .. } => "SshKey(..)",
        })
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    pub id: String,
    pub organization_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Vec<Field>,
    pub content: Content,
    /// Falso si alguna colección del elemento oculta las contraseñas a esta persona.
    pub view_password: bool,
}

impl Item {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }
}

/// Sin secretos, para los registros.
impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .finish_non_exhaustive()
    }
}

/// Algo que no se pudo descifrar: se informa en vez de mostrarlo vacío.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// Id del elemento o de la organización.
    pub id: String,
    pub reason: CryptoError,
}

pub struct Vault {
    /// Id del usuario de la sesión.
    pub user_id: String,
    /// Una organización tiene activa «Quitar la bóveda individual»: el servidor rechaza
    /// crear elementos personales y solo se puede guardar en colecciones. (A los
    /// propietarios y administradores el servidor puede eximirlos.)
    pub personal_vault_disabled: bool,
    pub organizations: Vec<Organization>,
    pub collections: Vec<Collection>,
    pub items: Vec<Item>,
    pub unreadable: Vec<Unreadable>,
    org_keys: HashMap<String, SymmetricKey>,
}

impl Vault {
    /// Descifra lo que devuelve `/api/sync` con la clave de usuario.
    pub fn open(sync: &SyncResponse, user_key: &SymmetricKey) -> Result<Self, VwError> {
        let mut unreadable = Vec::new();
        let private_key = sync
            .profile
            .private_key
            .as_deref()
            .map(|k| -> Result<PrivateKey, CryptoError> {
                let der = k.parse::<EncString>()?.decrypt(user_key)?;
                PrivateKey::from_pkcs8_der(&der)
            })
            .transpose()?;

        let mut organizations = Vec::new();
        let mut org_keys = HashMap::new();
        for org in &sync.profile.organizations {
            match org_key(org.key.as_deref(), private_key.as_ref()) {
                Ok(key) => {
                    org_keys.insert(org.id.clone(), key);
                    organizations.push(Organization {
                        id: org.id.clone(),
                        name: org.name.clone(),
                    });
                }
                Err(reason) => unreadable.push(Unreadable {
                    id: org.id.clone(),
                    reason,
                }),
            }
        }

        let mut collections = Vec::new();
        for c in &sync.collections {
            // Sin la clave de su organización ya se informó de la organización.
            let Some(key) = org_keys.get(&c.organization_id) else {
                continue;
            };
            match open_text(Some(&c.name), key) {
                Ok(name) => collections.push(Collection {
                    id: c.id.clone(),
                    organization_id: c.organization_id.clone(),
                    name: name.unwrap_or_default(),
                    hide_passwords: c.hide_passwords,
                }),
                Err(reason) => unreadable.push(Unreadable {
                    id: c.id.clone(),
                    reason,
                }),
            }
        }

        let mut items = Vec::new();
        for cipher in &sync.ciphers {
            if cipher.deleted_date.is_some() || !matches!(cipher.kind, wire::LOGIN | wire::SSH_KEY)
            {
                continue;
            }
            let key = match &cipher.organization_id {
                Some(org) => org_keys.get(org),
                None => Some(user_key),
            };
            // Sin la clave de su organización ya se informó de la organización.
            let Some(key) = key else { continue };
            match open_item(cipher, key) {
                Ok(item) => items.push(item),
                Err(reason) => unreadable.push(Unreadable {
                    id: cipher.id.clone(),
                    reason,
                }),
            }
        }

        Ok(Self {
            user_id: sync.profile.id.clone(),
            personal_vault_disabled: sync
                .policies
                .iter()
                .any(|p| p.enabled && p.kind == wire::PERSONAL_OWNERSHIP_POLICY),
            organizations,
            collections,
            items,
            unreadable,
            org_keys,
        })
    }

    pub fn item(&self, id: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }

    /// La clave con que se cifra un elemento nuevo: la de su organización o la del usuario.
    pub(crate) fn key_for<'a>(
        &'a self,
        organization_id: Option<&str>,
        user_key: &'a SymmetricKey,
    ) -> Option<&'a SymmetricKey> {
        match organization_id {
            Some(org) => self.org_keys.get(org),
            None => Some(user_key),
        }
    }
}

fn org_key(
    sealed: Option<&str>,
    private_key: Option<&PrivateKey>,
) -> Result<SymmetricKey, CryptoError> {
    let sealed = sealed.ok_or(CryptoError::Key)?;
    let private_key = private_key.ok_or(CryptoError::Key)?;
    let bytes = sealed.parse::<EncString>()?.decrypt_rsa(private_key)?;
    SymmetricKey::from_bytes(&bytes)
}

fn open_item(cipher: &CipherData, key: &SymmetricKey) -> Result<Item, CryptoError> {
    // El elemento puede tener su propia clave, cifrada con la de fuera.
    let own_key = cipher
        .key
        .as_deref()
        .map(|k| SymmetricKey::from_bytes(&k.parse::<EncString>()?.decrypt(key)?))
        .transpose()?;
    let key = own_key.as_ref().unwrap_or(key);
    let text = |value: &Option<String>| open_text(value.as_deref(), key);

    let content = match (cipher.kind, &cipher.login, &cipher.ssh_key) {
        (wire::LOGIN, login, _) => {
            let login = login.clone().unwrap_or_default();
            let mut uris = Vec::new();
            for uri in login.uris.iter().flatten() {
                uris.extend(text(&uri.uri)?);
            }
            Content::Login {
                username: text(&login.username)?,
                password: text(&login.password)?,
                uris,
            }
        }
        (wire::SSH_KEY, _, Some(ssh)) => Content::SshKey {
            private_key: text(&ssh.private_key)?.ok_or(CryptoError::Format)?,
            public_key: text(&ssh.public_key)?,
            fingerprint: text(&ssh.key_fingerprint)?,
        },
        _ => return Err(CryptoError::Format),
    };

    let mut fields = Vec::new();
    for f in cipher.fields.iter().flatten() {
        fields.push(Field {
            name: text(&f.name)?.unwrap_or_default(),
            value: text(&f.value)?.unwrap_or_default(),
            hidden: f.kind == wire::HIDDEN_FIELD,
        });
    }

    Ok(Item {
        id: cipher.id.clone(),
        organization_id: cipher.organization_id.clone(),
        collection_ids: cipher.collection_ids.clone(),
        name: text(&Some(cipher.name.clone()))?.unwrap_or_default(),
        notes: text(&cipher.notes)?,
        fields,
        content,
        view_password: cipher.view_password,
    })
}

/// Un elemento de usuario y contraseña nuevo, aún sin cifrar.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct NewLogin {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub fields: Vec<Field>,
}

impl NewLogin {
    /// Lo cifra con `key` para mandarlo al servidor. `user_id` es quien lo cifra.
    pub(crate) fn seal(
        &self,
        key: &SymmetricKey,
        organization_id: Option<&str>,
        user_id: &str,
    ) -> CipherData {
        let seal = |v: &Option<String>| v.as_deref().map(|v| seal_text(v, key));
        CipherData {
            kind: wire::LOGIN,
            organization_id: organization_id.map(str::to_string),
            encrypted_for: Some(user_id.to_string()),
            name: seal_text(&self.name, key),
            notes: seal(&self.notes),
            login: Some(wire::LoginData {
                username: seal(&self.username),
                password: seal(&self.password),
                totp: None,
                uris: Some(
                    self.uris
                        .iter()
                        .map(|u| wire::UriData {
                            uri: Some(seal_text(u, key)),
                        })
                        .collect(),
                ),
            }),
            fields: Some(
                self.fields
                    .iter()
                    .map(|f| wire::FieldData {
                        kind: if f.hidden { wire::HIDDEN_FIELD } else { 0 },
                        name: Some(seal_text(&f.name, key)),
                        value: Some(seal_text(&f.value, key)),
                    })
                    .collect(),
            ),
            ..CipherData::default()
        }
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
