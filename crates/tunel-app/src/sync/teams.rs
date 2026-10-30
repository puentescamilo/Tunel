//! Teams desde la interfaz. Cada operación corre en segundo plano como una tarea del
//! controlador de sincronización, así nunca coincide con una ronda: las dos cambian la
//! configuración y la bóveda, y la segunda en terminar pisaría a la primera.

use super::{SyncStatus, rebase, save};
use crate::app::TunelApp;
use std::time::Duration;
use tunel_core::sync::protocol::TeamRole;
use tunel_core::sync::{PublicKey, SyncLocal};
use tunel_core::vault::VaultData;
use tunel_sync::SyncError;
use tunel_sync::teams::{self, MemberView};

/// Lo que se le pide al servidor.
pub enum TeamOp {
    Create {
        name: String,
    },
    Lookup {
        email: String,
    },
    Invite {
        team: String,
        email: String,
        role: TeamRole,
        key: PublicKey,
    },
    Accept {
        team: String,
    },
    Leave {
        team: String,
    },
    Delete {
        team: String,
    },
    SetRole {
        team: String,
        email: String,
        role: TeamRole,
    },
    Remove {
        team: String,
        email: String,
    },
    Members {
        team: String,
    },
}

impl TeamOp {
    /// Lo que se muestra mientras corre.
    fn label(&self) -> &'static str {
        match self {
            Self::Create { .. } => "Creando el Team…",
            Self::Lookup { .. } => "Buscando la cuenta…",
            Self::Invite { .. } => "Invitando…",
            Self::Accept { .. } => "Aceptando la invitación…",
            Self::Leave { .. } => "Saliendo del Team…",
            Self::Delete { .. } => "Borrando el Team…",
            Self::SetRole { .. } => "Cambiando el rol…",
            Self::Remove { .. } => "Expulsando y renovando la clave del Team…",
            Self::Members { .. } => "Cargando los miembros…",
        }
    }
}

/// Resultado de una operación.
pub enum Done {
    Created {
        team: String,
    },
    Found {
        email: String,
        key: PublicKey,
    },
    Invited {
        team: String,
        email: String,
    },
    Accepted,
    Left,
    Deleted,
    RoleChanged {
        team: String,
    },
    Removed {
        team: String,
        email: String,
    },
    Members {
        team: String,
        members: Vec<MemberView>,
    },
}

pub struct TeamDone {
    local: SyncLocal,
    /// La bóveda nueva, si la operación la cambió.
    data: Option<VaultData>,
    done: Done,
}

/// Corre la operación; se llama desde el motor, fuera del hilo de la interfaz.
pub async fn run(op: TeamOp, local: SyncLocal, data: VaultData) -> Result<TeamDone, SyncError> {
    let keep = |local: SyncLocal, done: Done| TeamDone {
        local,
        data: None,
        done,
    };
    Ok(match op {
        TeamOp::Create { name } => {
            let (local, team) = teams::create_team(&local, &name).await?;
            keep(local, Done::Created { team })
        }
        TeamOp::Lookup { email } => {
            let (local, key) = teams::lookup_key(&local, &email).await?;
            keep(local, Done::Found { email, key })
        }
        TeamOp::Invite {
            team,
            email,
            role,
            key,
        } => {
            let local = teams::invite(&local, &team, &email, role, key).await?;
            keep(local, Done::Invited { team, email })
        }
        TeamOp::Accept { team } => {
            let local = teams::accept_invitation(&local, &team).await?;
            keep(local, Done::Accepted)
        }
        TeamOp::Leave { team } => {
            let (local, data) = teams::leave_team(&local, &data, &team).await?;
            TeamDone {
                local,
                data: Some(data),
                done: Done::Left,
            }
        }
        TeamOp::Delete { team } => {
            let (local, data) = teams::delete_team(&local, &data, &team).await?;
            TeamDone {
                local,
                data: Some(data),
                done: Done::Deleted,
            }
        }
        TeamOp::SetRole { team, email, role } => {
            let local = teams::set_role(&local, &team, &email, role).await?;
            keep(local, Done::RoleChanged { team })
        }
        TeamOp::Remove { team, email } => {
            let (local, data) = teams::remove_member(&local, &data, &team, &email).await?;
            TeamDone {
                local,
                data: Some(data),
                done: Done::Removed { team, email },
            }
        }
        TeamOp::Members { team } => {
            let (local, members) = teams::members(&local, &team).await?;
            keep(local, Done::Members { team, members })
        }
    })
}

/// Acción destructiva a la espera de que la persona la confirme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    Remove { team: String, email: String },
    Leave { team: String },
    Delete { team: String },
}

/// Estado de la tarjeta de Teams en Ajustes.
#[derive(Default)]
pub struct TeamsUi {
    pub new_name: String,
    /// Team desplegado.
    pub open: Option<String>,
    /// Miembros del Team desplegado, tal como llegaron del servidor.
    pub members: Option<(String, Vec<MemberView>)>,
    pub invite_email: String,
    pub invite_admin: bool,
    /// Cuenta buscada para invitar: su correo y la clave cuya huella se muestra.
    pub found: Option<(String, PublicKey)>,
    pub confirm: Option<Confirm>,
    /// Operación en curso.
    pub working: Option<&'static str>,
}

/// Lanza una operación si no hay otra tarea en curso.
pub fn start(app: &mut TunelApp, op: TeamOp) {
    if app.sync.busy() {
        return app.notify("Espera a que termine la sincronización en curso");
    }
    let (Some(local), Some(data)) = (app.sync.local.clone(), app.data().cloned()) else {
        return;
    };
    app.sync.teams.working = Some(op.label());
    let round = app.sync.begin(data.clone());
    app.engine.team_op(round, op, local, data);
}

pub fn on_done(app: &mut TunelApp, round: u64, result: Result<Box<TeamDone>, SyncError>) {
    let Some(snapshot) = app.sync.finish(round) else {
        return;
    };
    app.sync.teams.working = None;
    let done = match result {
        Ok(done) => *done,
        Err(e) => return app.notify(describe(&e)),
    };
    let Some(current) = app.data().cloned() else {
        return;
    };
    let result = done.data.unwrap_or_else(|| snapshot.clone());
    let (data, local) = match rebase(&snapshot, &current, &result, done.local) {
        Ok(rebased) => rebased,
        Err(e) => return app.notify(format!("No se pudo aplicar el cambio del Team: {e}")),
    };
    if data != current
        && let Err(e) = app.commit_synced(data)
    {
        return app.notify(format!("No se pudo guardar la bóveda: {e}"));
    }
    app.sync.local = Some(local);
    save(app);
    after(app, done.done);
}

/// Actualiza la tarjeta y avisa de lo que pasó.
fn after(app: &mut TunelApp, done: Done) {
    let message = match done {
        Done::Created { team } => {
            app.sync.teams.new_name.clear();
            app.sync.teams.open = Some(team.clone());
            app.sync.teams.members = None;
            start_members(app, team);
            "Team creado. Invita a otras cuentas de este servidor desde su ficha.".to_string()
        }
        Done::Found { email, key } => {
            app.sync.teams.found = Some((email, key));
            return;
        }
        Done::Invited { team, email } => {
            app.sync.teams.found = None;
            app.sync.teams.invite_email.clear();
            start_members(app, team);
            format!("Invitación enviada a {email}; podrá aceptarla en Ajustes")
        }
        Done::Accepted => {
            schedule_sync(app);
            "Invitación aceptada; recibiendo el Team…".to_string()
        }
        Done::Left => {
            app.sync.teams.open = None;
            app.sync.teams.members = None;
            "Has salido del Team; sus hosts ya no están en este equipo".to_string()
        }
        Done::Deleted => {
            app.sync.teams.open = None;
            app.sync.teams.members = None;
            "Team borrado para todos sus miembros".to_string()
        }
        Done::RoleChanged { team } => {
            start_members(app, team);
            return;
        }
        Done::Removed { team, email } => {
            start_members(app, team);
            format!("{email} ya no es miembro; la clave del Team se renovó")
        }
        Done::Members { team, members } => {
            app.sync.teams.members = Some((team, members));
            return;
        }
    };
    app.notify(message);
}

fn start_members(app: &mut TunelApp, team: String) {
    start(app, TeamOp::Members { team });
}

fn schedule_sync(app: &mut TunelApp) {
    if matches!(
        app.sync.status,
        SyncStatus::Idle { .. } | SyncStatus::Failed { .. }
    ) {
        app.sync.schedule_in(Duration::ZERO);
    }
}

fn describe(error: &SyncError) -> String {
    match error {
        SyncError::NotFound(_) => {
            "No hay ninguna cuenta con claves para Teams con ese correo en este servidor".into()
        }
        other => format!("Teams: {other}"),
    }
}

/// La persona comparó la huella de `email` y confía en esta clave. No necesita al
/// servidor, pero sí que no corra ninguna tarea: su resultado traería la configuración
/// de antes y desharía el cambio.
pub fn trust_key(app: &mut TunelApp, email: &str, key: PublicKey, replace: bool) {
    if app.sync.busy() {
        return app.notify("Espera a que termine la sincronización en curso");
    }
    let Some(local) = app.sync.local.as_ref() else {
        return;
    };
    let next = if replace {
        local.replace_key(email, key)
    } else {
        match local.pin(email, key) {
            Ok(pinned) => pinned.mark_verified(email),
            Err(e) => return app.notify(e.to_string()),
        }
    };
    app.sync.local = Some(next);
    save(app);
    if let Some((_, members)) = app.sync.teams.members.as_mut()
        && let Some(member) = members.iter_mut().find(|m| m.email == email)
    {
        member.key = teams::KeyStatus::Verified;
    }
    schedule_sync(app);
}

/// Teams de esta cuenta, para los desplegables de las fichas: identificador y nombre.
pub fn names(app: &TunelApp) -> Vec<(String, String)> {
    app.sync
        .local
        .as_ref()
        .map(|l| {
            l.teams
                .iter()
                .map(|t| (t.id.clone(), t.name.clone()))
                .collect()
        })
        .unwrap_or_default()
}
