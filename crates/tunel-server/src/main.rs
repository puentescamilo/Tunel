//! Arranca el servidor de sincronización.
//!
//! Variables de entorno:
//! - `TUNEL_DB`: archivo SQLite (por defecto `tunel.db`).
//! - `TUNEL_ESCUCHA`: dirección y puerto (por defecto `127.0.0.1:8080`).
//! - `TUNEL_REGISTRO_ABIERTO=1`: permite crear cuentas a cualquiera; si no, solo la primera.
//! - `TUNEL_DOMINIOS_PERMITIDOS=ejemplo.com,otro.com`: solo se crean cuentas con correos
//!   de esos dominios, y para ellos el registro queda abierto.
//! - Proveedores de identidad (iniciar sesión con Google, Microsoft 365 u OpenID Connect):
//!   `TUNEL_URL_PUBLICA` y `TUNEL_GOOGLE_*`, `TUNEL_MICROSOFT_*` o `TUNEL_OIDC_*`; ver
//!   `.env.example`.
//!
//! Sirve HTTP sin cifrar: ponlo detrás de un proxy con HTTPS (Caddy, nginx, Traefik).
//!
//! `tunel-server salud` comprueba que un servidor en marcha responde; lo usa el
//! `HEALTHCHECK` de la imagen Docker, que no trae curl.

use anyhow::Context as _;
use std::path::PathBuf;
use tunel_server::{
    AppState, Config, Db, OAuthConfig, parse_allowed_domains, router, spawn_session_sweeper,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

fn listen_address() -> String {
    std::env::var("TUNEL_ESCUCHA").unwrap_or_else(|_| DEFAULT_LISTEN.into())
}

/// Pide `/health` al servidor local y termina con éxito solo si responde 200.
fn health_check() -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let listen = listen_address();
    let port = listen.rsplit(':').next().unwrap_or("8080");
    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    anyhow::ensure!(response.starts_with("HTTP/1.1 200"), "respuesta inesperada");
    Ok(())
}

/// Avisa de configuraciones de proveedores que no harán lo que se espera.
fn warn_about_oauth(config: &Config) {
    let Some(oauth) = &config.oauth else {
        return;
    };
    let names: Vec<_> = oauth.providers.iter().map(|p| p.name.as_str()).collect();
    tracing::info!(proveedores = %names.join(", "), url = %oauth.public_url, "inicio de sesión con proveedores de identidad");
    for provider in &oauth.providers {
        tracing::info!(
            "dirección de retorno que hay que registrar en {}: {}/v1/auth/{}/callback",
            provider.name,
            oauth.public_url,
            provider.id
        );
        let restricted = provider.trusted_tenant
            || config.open_registration
            || !config.allowed_domains.is_empty();
        if !restricted {
            tracing::warn!(
                "con {} nadie podrá crear cuentas nuevas: define TUNEL_DOMINIOS_PERMITIDOS \
                 (o, si de verdad quieres admitir cualquier correo, TUNEL_REGISTRO_ABIERTO=1)",
                provider.name
            );
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("salud") {
        return health_check();
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let db_path =
        std::env::var_os("TUNEL_DB").map_or_else(|| PathBuf::from("tunel.db"), PathBuf::from);
    let listen = listen_address();
    let allowed_domains =
        parse_allowed_domains(&std::env::var("TUNEL_DOMINIOS_PERMITIDOS").unwrap_or_default())
            .map_err(|e| anyhow::anyhow!("TUNEL_DOMINIOS_PERMITIDOS: {e}"))?;
    let oauth = OAuthConfig::from_env(|name| std::env::var(name).ok())
        .map_err(|e| anyhow::anyhow!("proveedores de identidad: {e}"))?;
    let config = Config {
        open_registration: std::env::var("TUNEL_REGISTRO_ABIERTO").is_ok_and(|v| v == "1"),
        allowed_domains,
        oauth,
        ..Config::default()
    };
    warn_about_oauth(&config);

    let db = Db::open(&db_path)
        .with_context(|| format!("no se pudo abrir la base de datos {}", db_path.display()))?;
    let state = AppState::new(db, config).await?;
    spawn_session_sweeper(state.clone());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("no se pudo escuchar en {listen}"))?;
    let registration = match (
        &state.config.allowed_domains[..],
        state.config.open_registration,
    ) {
        ([], true) => "abierto".to_string(),
        ([], false) => "solo la primera cuenta".to_string(),
        (domains, _) => format!("solo {}", domains.join(", ")),
    };
    tracing::info!(%listen, db = %db_path.display(), %registration, "servidor de Túnel en marcha");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Ctrl+C o, en Unix, SIGTERM (lo que envía `docker stop`).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("apagando el servidor");
}
