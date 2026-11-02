//! Registro de auditoría de un Team: quién se conectó a qué host, quién vio o cambió una
//! contraseña, quién entró o salió.
//!
//! Cada entrada la firma quien hizo la acción con la clave de su cuenta y va cifrada con
//! la clave del Team: el servidor la guarda pero no puede leerla ni inventarla, y un
//! miembro no puede escribir en nombre de otro. El servidor sí podría borrar entradas o
//! no entregarlas; tampoco puede impedir que alguien con la clave deje de registrar sus
//! propias acciones, porque el registro lo escribe cada app.
//!
//! Al renovar la clave del Team, la anterior se guarda cifrada con la nueva
//! ([`seal_previous_key`]): así quien tiene la clave actual lee también las entradas viejas.

use super::keys::{SealedBlob, SyncCryptoError, VaultKey};
use super::protocol::TeamRole;
use super::team::{AccountKeypair, PublicKey};
use crate::crypto::KEY_LEN;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const AAD_AUDIT: &[u8] = b"tunel-equipo-auditoria-v1:";
const SIGNATURE_DOMAIN: &[u8] = b"tunel-equipo-auditoria-firma-v1:";
const AAD_PREVIOUS_KEY: &[u8] = b"tunel-equipo-clave-anterior-v1:";
/// Tope de una entrada firmada, en bytes; los nombres de hosts y correos son cortos.
pub const MAX_AUDIT_ENTRY: usize = 4096;
/// Tope de lo que se recorta de un nombre al registrarlo.
const MAX_NAME: usize = 200;

/// Lo que pasó.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "accion", rename_all = "snake_case")]
pub enum AuditAction {
    /// Abrió una sesión con un host del Team.
    Connected { host: String },
    /// Mostró la contraseña guardada de un elemento del Team.
    SecretViewed { item: String },
    /// Cambió la contraseña o la clave privada de un elemento del Team.
    SecretChanged { item: String },
    /// Un admin invitó a alguien.
    MemberInvited { email: String, role: TeamRole },
    /// Alguien aceptó la invitación.
    Joined,
    /// Un admin sacó a alguien.
    MemberRemoved { email: String },
    /// Un admin cambió el rol de alguien.
    RoleChanged { email: String, role: TeamRole },
    /// Salió del Team por su cuenta.
    Left,
    /// Un admin encendió o apagó la grabación de las sesiones.
    RecordingChanged { on: bool },
}

impl AuditAction {
    /// La misma acción con los nombres limpios, para mostrar lo que escribió otra app.
    pub fn cleaned(self) -> Self {
        match self {
            Self::Connected { host } => Self::Connected {
                host: clean_name(&host),
            },
            Self::SecretViewed { item } => Self::SecretViewed {
                item: clean_name(&item),
            },
            Self::SecretChanged { item } => Self::SecretChanged {
                item: clean_name(&item),
            },
            Self::MemberInvited { email, role } => Self::MemberInvited {
                email: clean_name(&email),
                role,
            },
            Self::MemberRemoved { email } => Self::MemberRemoved {
                email: clean_name(&email),
            },
            Self::RoleChanged { email, role } => Self::RoleChanged {
                email: clean_name(&email),
                role,
            },
            Self::Joined | Self::Left | Self::RecordingChanged { .. } => self,
        }
    }

    /// Solo la puede hacer un admin.
    pub fn needs_admin(&self) -> bool {
        matches!(
            self,
            Self::MemberInvited { .. }
                | Self::MemberRemoved { .. }
                | Self::RoleChanged { .. }
                | Self::RecordingChanged { .. }
        )
    }

    /// Texto para la lista, sin quién lo hizo.
    pub fn describe(&self) -> String {
        let role = |role: &TeamRole| match role {
            TeamRole::Admin => "admin",
            TeamRole::Member => "miembro",
        };
        match self {
            Self::Connected { host } => format!("se conectó a «{host}»"),
            Self::SecretViewed { item } => format!("vio la contraseña de «{item}»"),
            Self::SecretChanged { item } => format!("cambió la contraseña de «{item}»"),
            Self::MemberInvited { email, role: r } => {
                format!("invitó a {email} como {}", role(r))
            }
            Self::Joined => "entró en el Team".into(),
            Self::MemberRemoved { email } => format!("sacó a {email} del Team"),
            Self::RoleChanged { email, role: r } => format!("hizo {} a {email}", role(r)),
            Self::Left => "salió del Team".into(),
            Self::RecordingChanged { on: true } => "activó la grabación de sesiones".into(),
            Self::RecordingChanged { on: false } => "desactivó la grabación de sesiones".into(),
        }
    }
}

/// Recorta un nombre para el registro, sin caracteres de control ni los que cambian el
/// sentido del texto, con los que se podría disfrazar una entrada.
pub fn clean_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .take(MAX_NAME)
        .collect()
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Una entrada del registro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Único: el mismo evento subido dos veces se muestra una.
    pub id: String,
    pub team: String,
    /// Correo de quien lo hizo, en minúsculas.
    pub actor: String,
    /// Milisegundos desde 1970, según el reloj de quien lo hizo.
    pub at: u64,
    #[serde(flatten)]
    pub action: AuditAction,
}

/// Una entrada firmada, lista para cifrar. Así espera en la cola hasta que se sube: se
/// cifra al subirla, con la clave que tenga entonces el Team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuditEvent {
    payload: String,
    signature: String,
}

impl SignedAuditEvent {
    pub fn sign(event: &AuditEvent, pair: &AccountKeypair) -> Result<Self, SyncCryptoError> {
        let payload = serde_json::to_string(event).map_err(|_| SyncCryptoError::Corrupt)?;
        if payload.len() > MAX_AUDIT_ENTRY {
            return Err(SyncCryptoError::Corrupt);
        }
        let signature = B64.encode(pair.sign(&message(&payload)));
        Ok(Self { payload, signature })
    }

    /// El identificador del evento, para quitarlo de la cola una vez subido.
    pub fn id(&self) -> Option<String> {
        serde_json::from_str::<AuditEvent>(&self.payload)
            .ok()
            .map(|e| e.id)
    }

    pub fn seal(
        &self,
        key: &VaultKey,
        team: &str,
        epoch: u64,
    ) -> Result<SealedBlob, SyncCryptoError> {
        let plain = Zeroizing::new(serde_json::to_vec(self).map_err(|_| SyncCryptoError::Corrupt)?);
        key.seal_blob(&plain, &aad(team, epoch))
    }

    /// Descifra una entrada y comprueba que es de este Team. La firma la comprueba quien
    /// llama, con [`UnverifiedAudit::signed_by`], porque solo él sabe la clave de cada uno.
    pub fn open(
        blob: &SealedBlob,
        key: &VaultKey,
        team: &str,
        epoch: u64,
    ) -> Result<UnverifiedAudit, SyncCryptoError> {
        let plain = key.open_blob(blob, &aad(team, epoch))?;
        let signed: Self = serde_json::from_slice(&plain).map_err(|_| SyncCryptoError::Corrupt)?;
        if signed.payload.len() > MAX_AUDIT_ENTRY {
            return Err(SyncCryptoError::Corrupt);
        }
        let event: AuditEvent =
            serde_json::from_str(&signed.payload).map_err(|_| SyncCryptoError::Corrupt)?;
        if event.team != team {
            return Err(SyncCryptoError::Mismatch);
        }
        Ok(UnverifiedAudit {
            message: message(&signed.payload),
            signature: B64
                .decode(&signed.signature)
                .map_err(|_| SyncCryptoError::Corrupt)?,
            event,
        })
    }
}

/// Una entrada descifrada cuya firma falta por comprobar.
#[derive(Debug)]
pub struct UnverifiedAudit {
    pub event: AuditEvent,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl UnverifiedAudit {
    pub fn signed_by(&self, key: &PublicKey) -> bool {
        key.verify(&self.message, &self.signature)
    }
}

fn message(payload: &str) -> Vec<u8> {
    [SIGNATURE_DOMAIN, payload.as_bytes()].concat()
}

fn aad(team: &str, epoch: u64) -> Vec<u8> {
    [AAD_AUDIT, team.as_bytes(), b":", &epoch.to_be_bytes()].concat()
}

fn previous_key_aad(team: &str, epoch: u64) -> Vec<u8> {
    [
        AAD_PREVIOUS_KEY,
        team.as_bytes(),
        b":",
        &epoch.to_be_bytes(),
    ]
    .concat()
}

/// Cifra `previous`, la clave de la época `epoch - 1`, con `current`, la de `epoch`.
pub fn seal_previous_key(
    current: &VaultKey,
    previous: &VaultKey,
    team: &str,
    epoch: u64,
) -> Result<SealedBlob, SyncCryptoError> {
    current.seal_blob(previous.as_bytes(), &previous_key_aad(team, epoch))
}

/// La clave de la época `epoch - 1`, guardada con la de `epoch`.
pub fn open_previous_key(
    current: &VaultKey,
    blob: &SealedBlob,
    team: &str,
    epoch: u64,
) -> Result<VaultKey, SyncCryptoError> {
    let plain = current.open_blob(blob, &previous_key_aad(team, epoch))?;
    let bytes: [u8; KEY_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| SyncCryptoError::Corrupt)?;
    Ok(VaultKey::from_bytes(Zeroizing::new(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{RecordKey, RecordKind};

    const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

    fn event(action: AuditAction) -> AuditEvent {
        AuditEvent {
            id: "e1".into(),
            team: TEAM.into(),
            actor: "ana@ejemplo.com".into(),
            at: 1_700_000_000_000,
            action,
        }
    }

    fn connected() -> AuditEvent {
        event(AuditAction::Connected { host: "web".into() })
    }

    #[test]
    fn an_entry_round_trips_and_its_signature_names_the_author() {
        let key = VaultKey::generate();
        let ana = AccountKeypair::generate();
        let signed = SignedAuditEvent::sign(&connected(), &ana).unwrap();
        assert_eq!(signed.id().as_deref(), Some("e1"));
        let sealed = signed.seal(&key, TEAM, 3).unwrap();
        let opened = SignedAuditEvent::open(&sealed, &key, TEAM, 3).unwrap();
        assert_eq!(opened.event, connected());
        assert!(opened.signed_by(&ana.public()));
        assert!(!opened.signed_by(&AccountKeypair::generate().public()));
    }

    #[test]
    fn an_entry_only_opens_in_its_team_and_epoch() {
        let key = VaultKey::generate();
        let sealed = SignedAuditEvent::sign(&connected(), &AccountKeypair::generate())
            .unwrap()
            .seal(&key, TEAM, 3)
            .unwrap();
        assert!(SignedAuditEvent::open(&sealed, &key, TEAM, 4).is_err());
        assert!(SignedAuditEvent::open(&sealed, &key, "otro", 3).is_err());
        assert!(SignedAuditEvent::open(&sealed, &VaultKey::generate(), TEAM, 3).is_err());
    }

    #[test]
    fn an_entry_of_another_team_is_rejected_even_with_the_right_key() {
        let key = VaultKey::generate();
        let foreign = AuditEvent {
            team: "otro".into(),
            ..connected()
        };
        let sealed = SignedAuditEvent::sign(&foreign, &AccountKeypair::generate())
            .unwrap()
            .seal(&key, TEAM, 0)
            .unwrap();
        assert!(matches!(
            SignedAuditEvent::open(&sealed, &key, TEAM, 0),
            Err(SyncCryptoError::Mismatch)
        ));
    }

    #[test]
    fn a_changed_payload_breaks_the_signature() {
        let key = VaultKey::generate();
        let ana = AccountKeypair::generate();
        let mut signed = SignedAuditEvent::sign(&connected(), &ana).unwrap();
        signed.payload = signed.payload.replace("\"web\"", "\"db\"");
        let sealed = signed.seal(&key, TEAM, 0).unwrap();
        let opened = SignedAuditEvent::open(&sealed, &key, TEAM, 0).unwrap();
        assert!(!opened.signed_by(&ana.public()));
    }

    #[test]
    fn the_previous_key_is_recovered_with_the_current_one() {
        let old = VaultKey::generate();
        let new = VaultKey::generate();
        let blob = seal_previous_key(&new, &old, TEAM, 5).unwrap();
        let back = open_previous_key(&new, &blob, TEAM, 5).unwrap();
        let record = RecordKey::new(RecordKind::Host, "x");
        assert_eq!(back.record_id(&record), old.record_id(&record));
        assert!(open_previous_key(&new, &blob, TEAM, 6).is_err());
        assert!(open_previous_key(&old, &blob, TEAM, 5).is_err());
    }

    #[test]
    fn actions_read_naturally_and_names_are_cleaned() {
        assert_eq!(
            AuditAction::MemberInvited {
                email: "eva@ejemplo.com".into(),
                role: TeamRole::Admin
            }
            .describe(),
            "invitó a eva@ejemplo.com como admin"
        );
        assert_eq!(clean_name("web\n\u{1b}[31m"), "web[31m");
        assert_eq!(clean_name("ana\u{202E}moc.olpmeje"), "anamoc.olpmeje");
        assert_eq!(
            AuditAction::RoleChanged {
                email: "e\u{2066}va".into(),
                role: TeamRole::Admin
            }
            .cleaned(),
            AuditAction::RoleChanged {
                email: "eva".into(),
                role: TeamRole::Admin
            }
        );
        assert!(AuditAction::MemberRemoved { email: "x".into() }.needs_admin());
        assert!(!AuditAction::Left.needs_admin());
        assert_eq!(clean_name(&"x".repeat(500)).len(), MAX_NAME);
    }

    #[test]
    fn huge_entries_are_not_signed() {
        let huge = event(AuditAction::Connected {
            host: "x".repeat(MAX_AUDIT_ENTRY),
        });
        assert!(SignedAuditEvent::sign(&huge, &AccountKeypair::generate()).is_err());
    }
}
