//! Comandos de administración: listar cuentas, cerrar sus sesiones y borrarlas.
//!
//! Se ejecutan con el servidor en marcha, sobre la misma base de datos:
//!
//! ```text
//! docker compose -f crates/tunel-server/compose.yaml exec tunel-server tunel-server cuentas
//! ```
//!
//! Borrar una cuenta que envolvió la clave de un Team para otros miembros no puede quitar
//! su fila todavía: esos miembros comprueban su clave con la clave pública de quien la
//! envolvió. La cuenta queda como lápida (sin correo, credenciales ni datos, solo su clave
//! pública) y el Team, pendiente de renovar la clave. Al renovarla, otra admin vuelve a
//! envolver la clave para todos y la lápida se borra.

use crate::db::{Db, DbError};
use rusqlite::{OptionalExtension, Transaction, params};

/// Una cuenta, tal como la muestra `cuentas`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    pub email: String,
    /// Proveedor de identidad (`google`, `microsoft`, `oidc`); `None` si entra con
    /// contraseña.
    pub provider: Option<String>,
    /// Segundos desde 1970.
    pub created_at: i64,
    /// Teams de los que es miembro, sin contar las invitaciones pendientes.
    pub teams: u64,
    pub records: u64,
    /// Sesiones sin caducar.
    pub sessions: u64,
}

/// Lo que pasó con los Teams de una cuenta borrada.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteReport {
    /// Teams que se borraron porque no quedaba nadie más.
    pub teams_deleted: Vec<String>,
    /// Teams de los que salió y que quedan pendientes de renovar la clave.
    pub teams_left: Vec<String>,
    /// Teams en los que `nuevo admin` pasó a ser admin.
    pub teams_promoted: Vec<String>,
    /// La cuenta quedó como lápida hasta que esos Teams renueven la clave.
    pub tombstone: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("no hay ninguna cuenta con el correo {0}")]
    NoAccount(String),
    #[error(
        "{email} es la única admin del Team {team}, que tiene más miembros: indica quién pasa \
         a serlo con --nuevo-admin <correo>"
    )]
    NeedsNewAdmin { email: String, team: String },
    #[error("{email} no es miembro del Team {team}, así que no puede pasar a ser su admin")]
    NotAMember { email: String, team: String },
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("base de datos: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Correo con el que queda una lápida: nadie puede registrar uno de `.invalid`, y la
/// parte aleatoria evita chocar con una cuenta que se registró así antes de impedirlo.
fn tombstone_email(id: i64) -> String {
    let tag: [u8; 8] = rand::random();
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    format!("borrada-{id}-{tag}@cuenta.invalid")
}

/// Borra las lápidas que ya no envolvieron la clave de ningún miembro.
pub(crate) fn purge_tombstones(tx: &Transaction<'_>) -> Result<usize, rusqlite::Error> {
    tx.execute(
        "DELETE FROM accounts WHERE deleted_at IS NOT NULL
           AND id NOT IN (SELECT wrapped_by FROM team_members)",
        [],
    )
}

fn account_id(tx: &Transaction<'_>, email: &str) -> Result<Option<i64>, rusqlite::Error> {
    tx.query_row(
        "SELECT id FROM accounts WHERE email = ?1 AND deleted_at IS NULL",
        params![email],
        |row| row.get(0),
    )
    .optional()
}

/// Un Team de la cuenta que se borra: identificador, si es admin y si aceptó.
struct Membership {
    team: String,
    admin: bool,
    accepted: bool,
}

fn memberships(tx: &Transaction<'_>, account: i64) -> Result<Vec<Membership>, rusqlite::Error> {
    let mut stmt = tx.prepare(
        "SELECT team_id, role = 'admin', accepted FROM team_members
         WHERE account_id = ?1 ORDER BY team_id",
    )?;
    stmt.query_map(params![account], |row| {
        Ok(Membership {
            team: row.get(0)?,
            admin: row.get(1)?,
            accepted: row.get(2)?,
        })
    })?
    .collect()
}

fn count(
    tx: &Transaction<'_>,
    sql: &str,
    team: &str,
    account: i64,
) -> Result<i64, rusqlite::Error> {
    tx.query_row(sql, params![team, account], |row| row.get(0))
}

/// Saca a la cuenta `account` de sus Teams.
fn leave_teams(
    tx: &Transaction<'_>,
    email: &str,
    account: i64,
    new_admin: Option<(&str, i64)>,
    report: &mut DeleteReport,
) -> Result<(), AdminError> {
    for m in memberships(tx, account)? {
        let others = count(
            tx,
            "SELECT COUNT(*) FROM team_members
             WHERE team_id = ?1 AND account_id <> ?2 AND accepted = 1",
            &m.team,
            account,
        )?;
        if others == 0 {
            tx.execute("DELETE FROM teams WHERE id = ?1", params![m.team])?;
            report.teams_deleted.push(m.team);
            continue;
        }
        let other_admins = count(
            tx,
            "SELECT COUNT(*) FROM team_members
             WHERE team_id = ?1 AND account_id <> ?2 AND accepted = 1 AND role = 'admin'",
            &m.team,
            account,
        )?;
        if m.admin && m.accepted && other_admins == 0 {
            let Some((new_email, new_id)) = new_admin else {
                return Err(AdminError::NeedsNewAdmin {
                    email: email.into(),
                    team: m.team,
                });
            };
            let promoted = tx.execute(
                "UPDATE team_members SET role = 'admin'
                 WHERE team_id = ?1 AND account_id = ?2 AND accepted = 1",
                params![m.team, new_id],
            )?;
            if promoted == 0 {
                return Err(AdminError::NotAMember {
                    email: new_email.into(),
                    team: m.team,
                });
            }
            report.teams_promoted.push(m.team.clone());
        }
        tx.execute(
            "DELETE FROM team_members WHERE team_id = ?1 AND account_id = ?2",
            params![m.team, account],
        )?;
        // Se lleva la clave del Team: hay que renovarla, como al sacar a alguien.
        if m.accepted {
            tx.execute(
                "UPDATE teams SET rekey_needed = 1 WHERE id = ?1",
                params![m.team],
            )?;
            report.teams_left.push(m.team);
        }
    }
    Ok(())
}

impl Db {
    /// Todas las cuentas, por correo.
    pub async fn list_accounts(&self, now: i64) -> Result<Vec<AccountSummary>, DbError> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT a.email, a.oauth_provider, a.created_at,
                    (SELECT COUNT(*) FROM team_members m
                     WHERE m.account_id = a.id AND m.accepted = 1),
                    (SELECT COUNT(*) FROM records r WHERE r.account_id = a.id),
                    (SELECT COUNT(*) FROM sessions s
                     WHERE s.account_id = a.id AND s.expires_at > ?1)
                 FROM accounts a WHERE a.deleted_at IS NULL ORDER BY a.email",
            )?;
            let accounts = stmt
                .query_map(params![now], |row| {
                    Ok(AccountSummary {
                        email: row.get(0)?,
                        provider: row.get(1)?,
                        created_at: row.get(2)?,
                        teams: row.get::<_, i64>(3)? as u64,
                        records: row.get::<_, i64>(4)? as u64,
                        sessions: row.get::<_, i64>(5)? as u64,
                    })
                })?
                .collect::<Result<_, _>>()?;
            Ok(accounts)
        })
        .await
    }

    /// Cierra todas las sesiones de la cuenta `email`; devuelve cuántas había.
    pub async fn close_sessions(
        &self,
        email: String,
    ) -> Result<Result<usize, AdminError>, DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            let Some(id) = account_id(&tx, &email)? else {
                return Ok(Err(AdminError::NoAccount(email)));
            };
            let closed = tx.execute("DELETE FROM sessions WHERE account_id = ?1", params![id])?;
            tx.commit()?;
            Ok(Ok(closed))
        })
        .await
    }

    /// Borra la cuenta `email` con sus registros y sesiones y la saca de sus Teams. En los
    /// Teams donde era la única admin, `new_admin` pasa a serlo. Nada cambia si falla, ni
    /// si `confirm` es `false`: entonces solo dice lo que pasaría.
    pub async fn delete_account(
        &self,
        email: String,
        new_admin: Option<String>,
        now: i64,
        confirm: bool,
    ) -> Result<Result<DeleteReport, AdminError>, DbError> {
        self.call(move |conn| {
            let tx = conn.transaction()?;
            Ok(
                delete_in(&tx, &email, new_admin.as_deref(), now).and_then(|report| {
                    if confirm {
                        tx.commit()?;
                    }
                    Ok(report)
                }),
            )
        })
        .await
    }
}

fn delete_in(
    tx: &Transaction<'_>,
    email: &str,
    new_admin: Option<&str>,
    now: i64,
) -> Result<DeleteReport, AdminError> {
    let id = account_id(tx, email)?.ok_or_else(|| AdminError::NoAccount(email.into()))?;
    let new_admin = match new_admin {
        Some(other) => Some((
            other,
            account_id(tx, other)?.ok_or_else(|| AdminError::NoAccount(other.into()))?,
        )),
        None => None,
    };
    let mut report = DeleteReport::default();
    leave_teams(tx, email, id, new_admin, &mut report)?;
    tx.execute("DELETE FROM sessions WHERE account_id = ?1", params![id])?;
    tx.execute("DELETE FROM records WHERE account_id = ?1", params![id])?;
    let wrapped_for_others: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM team_members WHERE wrapped_by = ?1)",
        params![id],
        |row| row.get(0),
    )?;
    if wrapped_for_others {
        tx.execute(
            "UPDATE teams SET rekey_needed = 1
             WHERE id IN (SELECT team_id FROM team_members WHERE wrapped_by = ?1)",
            params![id],
        )?;
        tx.execute(
            "UPDATE accounts SET email = ?1, auth_salt = x'', auth_hash = x'', vault_key = '',
                 manifest = NULL, private_key = NULL, oauth_provider = NULL,
                 oauth_subject = NULL, previous_vault_key = NULL, deleted_at = ?2
             WHERE id = ?3",
            params![tombstone_email(id), now, id],
        )?;
        report.tombstone = true;
    } else {
        tx.execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
    }
    purge_tombstones(tx)?;
    Ok(report)
}

/// Fecha en formato AAAA-MM-DD (UTC) de `seconds` desde 1970.
fn date(seconds: i64) -> String {
    // Algoritmo de días civiles de Howard Hinnant.
    let days = seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Tabla de cuentas para la terminal.
pub fn format_accounts(accounts: &[AccountSummary]) -> String {
    if accounts.is_empty() {
        return "No hay cuentas.\n".into();
    }
    let width = accounts
        .iter()
        .map(|a| a.email.chars().count())
        .max()
        .unwrap_or(0)
        .max("CORREO".len());
    let mut out = format!(
        "{:<width$}  {:<11}  {:<10}  {:>5}  {:>9}  {:>8}\n",
        "CORREO", "ACCESO", "ALTA", "TEAMS", "REGISTROS", "SESIONES"
    );
    for a in accounts {
        out += &format!(
            "{:<width$}  {:<11}  {:<10}  {:>5}  {:>9}  {:>8}\n",
            a.email,
            a.provider.as_deref().unwrap_or("contraseña"),
            date(a.created_at),
            a.teams,
            a.records,
            a.sessions
        );
    }
    out += &format!("\n{} cuentas\n", accounts.len());
    out
}

/// Resumen de un borrado para la terminal.
pub fn format_report(email: &str, report: &DeleteReport, done: bool) -> String {
    let mut out = if done {
        format!("Cuenta {email} borrada.\n")
    } else {
        format!("Esto es lo que pasaría al borrar {email} (todavía no se ha borrado nada):\n")
    };
    let list = |label: &str, teams: &[String]| {
        if teams.is_empty() {
            String::new()
        } else {
            format!("{label}: {}\n", teams.join(", "))
        }
    };
    out += &list(
        "Teams borrados (no quedaba nadie más)",
        &report.teams_deleted,
    );
    out += &list("Nueva admin en los Teams", &report.teams_promoted);
    out += &list(
        "Teams pendientes de renovar la clave (lo hará su admin al sincronizar)",
        &report.teams_left,
    );
    if report.tombstone {
        out += "Su clave pública se conserva hasta que esos Teams renueven la clave; después \
                se borra sola.\n";
    }
    if !done {
        out += "\nPara borrarla, repite el comando con --confirmar. Se borran sus registros \
                y sesiones, y no se puede deshacer.\n";
    }
    out
}

pub const USAGE: &str = "\
Comandos de administración (con el servidor en marcha, sobre la misma base de datos):

  tunel-server cuentas
      Lista las cuentas: correo, forma de entrar, alta, Teams, registros y sesiones.

  tunel-server cerrar-sesiones <correo>
      Cierra todas sus sesiones: sus equipos tendrán que volver a iniciar sesión.

  tunel-server borrar-cuenta <correo> [--nuevo-admin <correo>] [--confirmar]
      Sin --confirmar, solo muestra lo que pasaría. Borra la cuenta, sus registros y
      sesiones, y la saca de sus Teams. Si era la única admin de un Team con más
      miembros, --nuevo-admin dice quién pasa a serlo.

Con Docker:
  docker compose -f crates/tunel-server/compose.yaml exec tunel-server tunel-server cuentas
";

/// Comando de administración ya leído de la línea de órdenes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Accounts,
    CloseSessions(String),
    Delete {
        email: String,
        new_admin: Option<String>,
        confirm: bool,
    },
}

fn email_arg(value: Option<&String>) -> Result<String, String> {
    value
        .map(|e| e.trim().to_lowercase())
        .filter(|e| e.contains('@'))
        .ok_or_else(|| "falta el correo de la cuenta".to_string())
}

/// Lee un comando de administración; `Ok(None)` si `args` no es ninguno.
pub fn parse(args: &[String]) -> Result<Option<Command>, String> {
    let Some(name) = args.first() else {
        return Ok(None);
    };
    let rest = &args[1..];
    match name.as_str() {
        "cuentas" if rest.is_empty() => Ok(Some(Command::Accounts)),
        "cerrar-sesiones" if rest.len() == 1 => {
            Ok(Some(Command::CloseSessions(email_arg(rest.first())?)))
        }
        "borrar-cuenta" => {
            let email = email_arg(rest.first())?;
            let (mut new_admin, mut confirm) = (None, false);
            let mut options = rest[1..].iter();
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--confirmar" => confirm = true,
                    "--nuevo-admin" => new_admin = Some(email_arg(options.next())?),
                    other => return Err(format!("opción desconocida: {other}")),
                }
            }
            Ok(Some(Command::Delete {
                email,
                new_admin,
                confirm,
            }))
        }
        "cuentas" | "cerrar-sesiones" => Err(format!("argumentos de más o de menos para {name}")),
        "ayuda" | "--help" | "-h" => Err(String::new()),
        _ => Ok(None),
    }
}

/// Ejecuta `command` y devuelve el texto para la terminal.
pub async fn run(db: &Db, command: Command, now: i64) -> Result<String, AdminError> {
    match command {
        Command::Accounts => Ok(format_accounts(&db.list_accounts(now).await?)),
        Command::CloseSessions(email) => {
            let closed = db.close_sessions(email.clone()).await??;
            Ok(format!("Cerradas {closed} sesiones de {email}.\n"))
        }
        Command::Delete {
            email,
            new_admin,
            confirm,
        } => {
            let report = db
                .delete_account(email.clone(), new_admin, now, confirm)
                .await??;
            Ok(format_report(&email, &report, confirm))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn commands_are_parsed_and_unknown_ones_start_the_server() {
        assert_eq!(parse(&args("cuentas")), Ok(Some(Command::Accounts)));
        assert_eq!(
            parse(&args("cerrar-sesiones  Ana@Empresa.com ")),
            Ok(Some(Command::CloseSessions("ana@empresa.com".into())))
        );
        assert_eq!(
            parse(&args(
                "borrar-cuenta ana@e.com --nuevo-admin bob@e.com --confirmar"
            )),
            Ok(Some(Command::Delete {
                email: "ana@e.com".into(),
                new_admin: Some("bob@e.com".into()),
                confirm: true,
            }))
        );
        assert_eq!(parse(&args("")), Ok(None));
        assert!(parse(&args("borrar-cuenta")).is_err());
        assert!(parse(&args("borrar-cuenta ana@e.com --forzar")).is_err());
        assert!(parse(&args("borrar-cuenta ana@e.com --nuevo-admin")).is_err());
        assert!(parse(&args("cuentas de-mas")).is_err());
    }

    #[test]
    fn dates_are_civil_utc_days() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_793_404_800), "2026-10-31");
    }

    #[test]
    fn the_table_shows_how_each_account_signs_in() {
        let table = format_accounts(&[AccountSummary {
            email: "ana@empresa.com".into(),
            provider: Some("google".into()),
            created_at: 0,
            teams: 1,
            records: 12,
            sessions: 2,
        }]);
        assert!(table.contains("ana@empresa.com"), "{table}");
        assert!(table.contains("google"), "{table}");
        assert!(table.contains("1970-01-01"), "{table}");
        assert!(table.ends_with("1 cuentas\n"), "{table}");
        assert_eq!(format_accounts(&[]), "No hay cuentas.\n");
    }
}
