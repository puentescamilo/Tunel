//! Arranque de Mosh: se lanza `mosh-server` por SSH y se obtiene el puerto UDP y la clave.
//!
//! La sesión UDP la atiende el `mosh-client` del sistema (ver `tunel-term`).

use crate::client::{SshConnection, SshError};

pub const DEFAULT_SERVER_COMMAND: &str = "mosh-server";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoshServer {
    pub ip: String,
    pub port: u16,
    pub key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MoshError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error("mosh-server no respondió con MOSH CONNECT (¿está instalado en el servidor?): {0}")]
    NoConnectLine(String),
    #[error("no se pudo resolver la dirección del servidor: {0}")]
    Resolve(String),
}

/// Busca la línea `MOSH CONNECT <puerto> <clave>` en la salida de mosh-server.
pub fn parse_connect_line(output: &str) -> Option<(u16, String)> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("MOSH CONNECT ")?;
        let mut parts = rest.split_whitespace();
        let port = parts.next()?.parse().ok()?;
        let key = parts.next()?;
        (key.len() == 22).then(|| (port, key.to_string()))
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

pub fn server_command(custom: Option<&str>, port_range: &str) -> String {
    let base = custom
        .filter(|c| !c.trim().is_empty())
        .unwrap_or(DEFAULT_SERVER_COMMAND);
    format!(
        "{base} new -s -c 256 -l LANG=en_US.UTF-8 -p {}",
        shell_quote(port_range)
    )
}

pub async fn start_server(
    conn: &SshConnection,
    address: &str,
    custom_command: Option<&str>,
    port_range: &str,
) -> Result<MoshServer, MoshError> {
    let (output, _status) = conn
        .exec(&server_command(custom_command, port_range))
        .await?;
    let text = String::from_utf8_lossy(&output);
    let (port, key) = parse_connect_line(&text)
        .ok_or_else(|| MoshError::NoConnectLine(text.trim().to_string()))?;
    let ip = tokio::net::lookup_host((address, port))
        .await
        .map_err(|e| MoshError::Resolve(e.to_string()))?
        .next()
        .ok_or_else(|| MoshError::Resolve(address.to_string()))?
        .ip()
        .to_string();
    Ok(MoshServer { ip, port, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_line_among_noise() {
        let out = "\r\nMOSH CONNECT 60001 AbCdEfGhIjKlMnOpQrStUv\r\n\nmosh-server (mosh 1.4.0)\n";
        assert_eq!(
            parse_connect_line(out),
            Some((60001, "AbCdEfGhIjKlMnOpQrStUv".into()))
        );
    }

    #[test]
    fn rejects_malformed_connect_lines() {
        assert_eq!(parse_connect_line("MOSH CONNECT abc key"), None);
        assert_eq!(parse_connect_line("MOSH CONNECT 60001 corta"), None);
        assert_eq!(parse_connect_line("command not found: mosh-server"), None);
    }

    #[test]
    fn server_command_quotes_port_range() {
        assert_eq!(
            server_command(None, "60000:61000"),
            "mosh-server new -s -c 256 -l LANG=en_US.UTF-8 -p '60000:61000'"
        );
        assert!(
            server_command(Some("/opt/bin/mosh-server"), "1:2")
                .starts_with("/opt/bin/mosh-server new")
        );
        assert!(server_command(Some("  "), "1:2").starts_with("mosh-server new"));
    }
}
