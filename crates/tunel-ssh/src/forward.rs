//! Reenvío de puertos: local (-L), remoto (-R) y dinámico (-D, SOCKS5).

use crate::client::{SshConnection, SshError};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tunel_core::{ForwardKind, PortForward};

/// Conexiones simultáneas por túnel; las demás esperan turno.
const MAX_CONNECTIONS: usize = 256;
/// Tiempo máximo para completar el saludo SOCKS5.
const SOCKS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Pausa tras un error de `accept` (p. ej. sin descriptores libres) para no girar en vacío.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);

/// `true` si la dirección solo acepta conexiones de este equipo.
pub fn is_loopback(bind_address: &str) -> bool {
    matches!(bind_address, "localhost" | "127.0.0.1" | "::1")
        || bind_address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Túnel activo; se detiene al llamar a `stop` o al soltarse.
pub struct ActiveForward {
    pub rule: PortForward,
    pub bound: Option<SocketAddr>,
    task: Option<JoinHandle<()>>,
    connection: Arc<SshConnection>,
}

impl ActiveForward {
    pub async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if self.rule.kind == ForwardKind::Remote {
            let _ = self
                .connection
                .handle()
                .cancel_tcpip_forward(
                    self.rule.bind_address.clone(),
                    u32::from(self.rule.bind_port),
                )
                .await;
            if let Ok(mut targets) = self.connection.remote_targets().lock() {
                targets.remove(&(
                    self.rule.bind_address.clone(),
                    u32::from(self.rule.bind_port),
                ));
            }
        }
    }
}

impl Drop for ActiveForward {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub async fn start(
    connection: Arc<SshConnection>,
    rule: PortForward,
) -> Result<ActiveForward, SshError> {
    match rule.kind {
        ForwardKind::Local | ForwardKind::Dynamic => {
            let listener = TcpListener::bind((rule.bind_address.as_str(), rule.bind_port)).await?;
            let bound = listener.local_addr().ok();
            let task = tokio::spawn(accept_loop(listener, connection.clone(), rule.clone()));
            Ok(ActiveForward {
                rule,
                bound,
                task: Some(task),
                connection,
            })
        }
        ForwardKind::Remote => {
            let key = (rule.bind_address.clone(), u32::from(rule.bind_port));
            if let Ok(mut targets) = connection.remote_targets().lock() {
                targets.insert(key, (rule.destination_host.clone(), rule.destination_port));
            }
            connection
                .handle()
                .tcpip_forward(rule.bind_address.clone(), u32::from(rule.bind_port))
                .await?;
            Ok(ActiveForward {
                rule,
                bound: None,
                task: None,
                connection,
            })
        }
    }
}

async fn accept_loop(listener: TcpListener, connection: Arc<SshConnection>, rule: PortForward) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok(permit) = slots.clone().acquire_owned().await else {
            return;
        };
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "error aceptando conexión del túnel");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let connection = connection.clone();
        let rule = rule.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = match rule.kind {
                ForwardKind::Local => {
                    pipe(
                        &connection,
                        socket,
                        peer,
                        &rule.destination_host,
                        rule.destination_port,
                    )
                    .await
                }
                ForwardKind::Dynamic => socks5_serve(&connection, socket, peer).await,
                ForwardKind::Remote => Ok(()),
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, "conexión del túnel terminada con error");
            }
        });
    }
}

async fn pipe(
    connection: &SshConnection,
    mut socket: TcpStream,
    peer: SocketAddr,
    host: &str,
    port: u16,
) -> Result<(), SshError> {
    let channel = connection
        .handle()
        .channel_open_direct_tcpip(
            host.to_string(),
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await?;
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut socket, &mut stream).await?;
    Ok(())
}

/// Petición CONNECT de SOCKS5 ya leída.
#[derive(Debug, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

const SOCKS_VERSION: u8 = 0x05;
const REPLY_OK: u8 = 0x00;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;

/// Servidor SOCKS5 mínimo: sin autenticación y solo CONNECT (suficiente para navegadores y curl).
pub async fn socks5_accept<S>(stream: &mut S) -> std::io::Result<Option<SocksTarget>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "petición SOCKS5 no válida");
    if stream.read_u8().await? != SOCKS_VERSION {
        return Err(invalid());
    }
    let n_methods = usize::from(stream.read_u8().await?);
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[SOCKS_VERSION, 0xff]).await?;
        return Ok(None);
    }
    stream.write_all(&[SOCKS_VERSION, 0x00]).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(invalid());
    }
    let host = match head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        0x03 => {
            let len = usize::from(stream.read_u8().await?);
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    let port = stream.read_u16().await?;
    if head[1] != 0x01 {
        socks5_reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Ok(None);
    }
    Ok(Some(SocksTarget { host, port }))
}

async fn socks5_reply<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    code: u8,
) -> std::io::Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

async fn socks5_serve(
    connection: &SshConnection,
    mut socket: TcpStream,
    peer: SocketAddr,
) -> Result<(), SshError> {
    let handshake = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, socks5_accept(&mut socket)).await;
    let Ok(accepted) = handshake else {
        return Ok(());
    };
    let Some(target) = accepted? else {
        return Ok(());
    };
    let channel = connection
        .handle()
        .channel_open_direct_tcpip(
            target.host,
            u32::from(target.port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await;
    let channel = match channel {
        Ok(channel) => channel,
        Err(e) => {
            socks5_reply(&mut socket, REPLY_HOST_UNREACHABLE).await?;
            return Err(e.into());
        }
    };
    socks5_reply(&mut socket, REPLY_OK).await?;
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut socket, &mut stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn loopback_detection_covers_names_and_addresses() {
        for addr in ["127.0.0.1", "localhost", "::1", "127.0.0.2"] {
            assert!(is_loopback(addr), "{addr}");
        }
        for addr in ["0.0.0.0", "192.168.1.10", "::", "ejemplo.com"] {
            assert!(!is_loopback(addr), "{addr}");
        }
    }

    #[tokio::test]
    async fn socks5_accept_parses_domain_connect() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move { socks5_accept(&mut server).await.unwrap() });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        client.write_all(&[5, 1, 0, 3, 7]).await.unwrap();
        client.write_all(b"ejemplo").await.unwrap();
        client.write_all(&443u16.to_be_bytes()).await.unwrap();
        assert_eq!(
            task.await.unwrap(),
            Some(SocksTarget {
                host: "ejemplo".into(),
                port: 443
            })
        );
    }

    #[tokio::test]
    async fn socks5_accept_parses_ipv4_connect() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move { socks5_accept(&mut server).await.unwrap() });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        client
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(
            task.await.unwrap(),
            Some(SocksTarget {
                host: "10.0.0.1".into(),
                port: 80
            })
        );
    }

    #[tokio::test]
    async fn socks5_accept_rejects_clients_requiring_auth() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move { socks5_accept(&mut server).await.unwrap() });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
        assert_eq!(task.await.unwrap(), None);
    }

    #[tokio::test]
    async fn socks5_accept_refuses_bind_command() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move { socks5_accept(&mut server).await.unwrap() });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        client
            .write_all(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut refusal = [0u8; 10];
        client.read_exact(&mut refusal).await.unwrap();
        assert_eq!(refusal[1], REPLY_COMMAND_NOT_SUPPORTED);
        assert_eq!(task.await.unwrap(), None);
    }
}
