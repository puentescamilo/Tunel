//! Conexión TCP inicial, directa o a través de un proxy SOCKS5 / HTTP CONNECT.

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tunel_core::ProxyConfig;

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_USER_PASS: u8 = 0x02;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_IPV6: u8 = 0x04;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("error de red: {0}")]
    Io(#[from] std::io::Error),
    #[error("el proxy respondió algo inesperado")]
    Protocol,
    #[error("el proxy rechazó las credenciales")]
    AuthRejected,
    #[error("el proxy no pudo conectar con el destino (código {0})")]
    ConnectRejected(u8),
    #[error("el proxy HTTP respondió: {0}")]
    HttpStatus(String),
    #[error("nombre de host demasiado largo para SOCKS5")]
    HostTooLong,
}

pub async fn connect(
    proxy: Option<&ProxyConfig>,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyError> {
    match proxy {
        None => Ok(TcpStream::connect((host, port)).await?),
        Some(ProxyConfig::Socks5 {
            host: ph,
            port: pp,
            username,
            password,
        }) => {
            let stream = TcpStream::connect((ph.as_str(), *pp)).await?;
            let creds = username
                .as_deref()
                .map(|u| (u, password.as_deref().unwrap_or("")));
            socks5_handshake(stream, host, port, creds).await
        }
        Some(ProxyConfig::Http {
            host: ph,
            port: pp,
            username,
            password,
        }) => {
            let stream = TcpStream::connect((ph.as_str(), *pp)).await?;
            let creds = username
                .as_deref()
                .map(|u| (u, password.as_deref().unwrap_or("")));
            http_connect(stream, host, port, creds).await
        }
    }
}

pub async fn socks5_handshake<S>(
    mut stream: S,
    host: &str,
    port: u16,
    creds: Option<(&str, &str)>,
) -> Result<S, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let method = if creds.is_some() {
        SOCKS_USER_PASS
    } else {
        SOCKS_NO_AUTH
    };
    stream.write_all(&[SOCKS_VERSION, 1, method]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != SOCKS_VERSION || reply[1] != method {
        return Err(ProxyError::Protocol);
    }
    if let Some((user, pass)) = creds {
        let (user, pass) = (user.as_bytes(), pass.as_bytes());
        let (user_len, pass_len) = (u8::try_from(user.len()), u8::try_from(pass.len()));
        let (Ok(user_len), Ok(pass_len)) = (user_len, pass_len) else {
            return Err(ProxyError::AuthRejected);
        };
        let mut msg = vec![0x01, user_len];
        msg.extend_from_slice(user);
        msg.push(pass_len);
        msg.extend_from_slice(pass);
        stream.write_all(&msg).await?;
        stream.read_exact(&mut reply).await?;
        if reply[1] != 0 {
            return Err(ProxyError::AuthRejected);
        }
    }
    let host_len = u8::try_from(host.len()).map_err(|_| ProxyError::HostTooLong)?;
    let mut request = vec![
        SOCKS_VERSION,
        SOCKS_CMD_CONNECT,
        0x00,
        SOCKS_ATYP_DOMAIN,
        host_len,
    ];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(ProxyError::Protocol);
    }
    if head[1] != 0 {
        return Err(ProxyError::ConnectRejected(head[1]));
    }
    let addr_len = match head[3] {
        SOCKS_ATYP_IPV4 => 4,
        SOCKS_ATYP_IPV6 => 16,
        SOCKS_ATYP_DOMAIN => usize::from(stream.read_u8().await?),
        _ => return Err(ProxyError::Protocol),
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

pub async fn http_connect<S>(
    mut stream: S,
    host: &str,
    port: u16,
    creds: Option<(&str, &str)>,
) -> Result<S, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let auth = creds
        .map(|(u, p)| {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            format!("Proxy-Authorization: Basic {token}\r\n")
        })
        .unwrap_or_default();
    let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Leer byte a byte para no consumir datos del túnel que lleguen tras las cabeceras.
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() > MAX_HTTP_HEADER_BYTES {
            return Err(ProxyError::Protocol);
        }
        header.push(stream.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&header);
    let status = text.lines().next().unwrap_or_default();
    let code = status
        .split_whitespace()
        .nth(1)
        .ok_or(ProxyError::Protocol)?;
    if !code.starts_with('2') {
        return Err(ProxyError::HttpStatus(status.trim().to_string()));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader, duplex};

    #[tokio::test]
    async fn socks5_without_auth_sends_domain_connect() {
        let (client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [5, 1, 0, 3, 11]);
            let mut rest = [0u8; 13];
            server.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[..11], b"example.com");
            assert_eq!(&rest[11..], &22u16.to_be_bytes());
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 22])
                .await
                .unwrap();
            server.write_all(b"SSH-2.0-test").await.unwrap();
        });
        let mut stream = socks5_handshake(client, "example.com", 22, None)
            .await
            .unwrap();
        let mut banner = [0u8; 12];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-test");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_sends_username_password() {
        let (client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 9];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x03ana\x03pwd");
            server.write_all(&[1, 1]).await.unwrap();
        });
        let err = socks5_handshake(client, "h", 22, Some(("ana", "pwd")))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::AuthRejected));
    }

    #[tokio::test]
    async fn socks5_reports_connect_failure_code() {
        let (client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 8];
            server.read_exact(&mut req).await.unwrap();
            server.write_all(&[5, 5, 0, 1]).await.unwrap();
        });
        let err = socks5_handshake(client, "h", 22, None).await.unwrap_err();
        assert!(matches!(err, ProxyError::ConnectRejected(5)));
    }

    #[tokio::test]
    async fn http_connect_succeeds_on_200_and_sends_basic_auth() {
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut reader = BufReader::new(server);
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            assert!(request.starts_with("CONNECT db:5432 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dTpw\r\n"));
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nSSH-2.0")
                .await
                .unwrap();
        });
        let mut stream = http_connect(client, "db", 5432, Some(("u", "p")))
            .await
            .unwrap();
        let mut banner = [0u8; 7];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0");
    }

    #[tokio::test]
    async fn http_connect_reports_non_2xx_status() {
        let (client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let _ = server.read(&mut buf).await;
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let err = http_connect(client, "db", 22, None).await.unwrap_err();
        assert!(matches!(err, ProxyError::HttpStatus(s) if s.contains("407")));
    }
}
