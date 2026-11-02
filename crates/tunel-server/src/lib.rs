//! Servidor de sincronización de Túnel.
//!
//! Guarda, por cuenta, la clave de bóveda envuelta, el manifiesto y los registros cifrados
//! tal como los manda el cliente. No puede leer nada de su contenido: solo comprueba la
//! clave de acceso de cada cuenta y ordena los cambios para que cada equipo pida los que
//! le faltan.

pub mod admin;
pub mod api;
pub mod audit;
pub mod auth;
pub mod db;
pub mod live;
pub mod oauth;
mod pulls;
pub mod recordings;

pub use api::{AppState, Config, parse_allowed_domains, router, spawn_session_sweeper};
pub use db::{Db, Quota};
pub use live::LiveLimits;
pub use oauth::OAuthConfig;
