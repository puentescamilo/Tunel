//! Reenvío X11: las aplicaciones gráficas del servidor se muestran en el servidor X local.
//!
//! Como OpenSSH, al servidor se le envía una cookie falsa y aleatoria. Cuando llega una
//! conexión X11 se comprueba esa cookie y se sustituye por la real del servidor X local, que
//! nunca sale de este equipo.

use crate::client::SshError;
use russh::Channel;
use russh::client::Msg;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const AUTH_PROTOCOL: &str = "MIT-MAGIC-COOKIE-1";
const COOKIE_LEN: usize = 16;
const X11_BASE_PORT: u32 = 6000;
/// Cabecera fija del mensaje de inicio de conexión X11.
const SETUP_HEADER_LEN: usize = 12;
/// Un inicio de conexión legítimo ocupa unas decenas de bytes.
const MAX_SETUP_LEN: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum X11Error {
    #[error("DISPLAY no válido: «{0}»")]
    InvalidDisplay(String),
    #[error("la conexión X11 no se identificó con la cookie de esta sesión")]
    BadCookie,
    #[error("inicio de conexión X11 no válido")]
    BadSetup,
}

/// Dónde escucha el servidor X local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDisplay {
    Unix {
        path: PathBuf,
        screen: u32,
    },
    Tcp {
        host: String,
        port: u16,
        screen: u32,
    },
}

impl LocalDisplay {
    pub fn screen(&self) -> u32 {
        match self {
            Self::Unix { screen, .. } | Self::Tcp { screen, .. } => *screen,
        }
    }
}

/// `DISPLAY` por defecto: el del entorno o, si no hay, el habitual de cada sistema
/// (VcXsrv o Xming escuchan en `localhost:0` en Windows).
pub fn default_display() -> String {
    std::env::var("DISPLAY")
        .ok()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "localhost:0".into()
            } else {
                ":0".into()
            }
        })
}

/// Interpreta un `DISPLAY`: `:0`, `:0.1`, `unix:0`, `host:0` o la ruta de un socket
/// (XQuartz usa `/private/tmp/com.apple.launchd.…/org.xquartz:0`).
pub fn parse_display(display: &str) -> Result<LocalDisplay, X11Error> {
    let invalid = || X11Error::InvalidDisplay(display.to_string());
    let display = display.trim();
    let (host, number) = display.rsplit_once(':').ok_or_else(invalid)?;
    let (number_text, screen) = number.split_once('.').unwrap_or((number, "0"));
    let number: u32 = number_text.parse().map_err(|_| invalid())?;
    let screen: u32 = screen.parse().map_err(|_| invalid())?;
    if host.starts_with('/') {
        // En XQuartz el nombre del socket incluye el `:0` (pero no la pantalla).
        let path = PathBuf::from(format!("{host}:{number_text}"));
        return Ok(LocalDisplay::Unix { path, screen });
    }
    if (host.is_empty() || host == "unix") && cfg!(unix) {
        let path = PathBuf::from(format!("/tmp/.X11-unix/X{number}"));
        return Ok(LocalDisplay::Unix { path, screen });
    }
    let host = match host {
        "" | "unix" => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    let port = u16::try_from(X11_BASE_PORT + number).map_err(|_| invalid())?;
    Ok(LocalDisplay::Tcp { host, port, screen })
}

/// Primera cookie MIT-MAGIC-COOKIE-1 de la salida de `xauth list`.
pub fn parse_xauth_list(output: &str) -> Option<Vec<u8>> {
    output.lines().find_map(|line| {
        let mut fields = line.split_whitespace().skip(1);
        (fields.next()? == AUTH_PROTOCOL)
            .then(|| fields.next())
            .flatten()
            .and_then(decode_hex)
    })
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compara sin cortar en el primer byte distinto.
fn same_cookie(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn padded(len: usize) -> usize {
    len.div_ceil(4) * 4
}

/// Resultado de examinar el inicio de una conexión X11 que llega del servidor.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupRewrite {
    /// Faltan bytes para tener el mensaje completo.
    Incomplete,
    /// Mensaje listo para el servidor X local, seguido de lo que llegó detrás.
    Ready(Vec<u8>),
}

/// Comprueba la cookie falsa del mensaje de inicio y la sustituye por la real (o por
/// ninguna, si el servidor X local no usa autenticación).
pub fn rewrite_setup(
    buffer: &[u8],
    fake_cookie: &[u8],
    real_cookie: Option<&[u8]>,
) -> Result<SetupRewrite, X11Error> {
    if buffer.len() < SETUP_HEADER_LEN {
        return Ok(SetupRewrite::Incomplete);
    }
    let read_u16 = |at: usize| -> Result<usize, X11Error> {
        let bytes = [buffer[at], buffer[at + 1]];
        match buffer[0] {
            b'B' => Ok(usize::from(u16::from_be_bytes(bytes))),
            b'l' => Ok(usize::from(u16::from_le_bytes(bytes))),
            _ => Err(X11Error::BadSetup),
        }
    };
    let name_len = read_u16(6)?;
    let data_len = read_u16(8)?;
    let name_start = SETUP_HEADER_LEN;
    let data_start = name_start + padded(name_len);
    let total = data_start + padded(data_len);
    if buffer.len() < total {
        return Ok(SetupRewrite::Incomplete);
    }
    let name = &buffer[name_start..name_start + name_len];
    let data = &buffer[data_start..data_start + data_len];
    if name != AUTH_PROTOCOL.as_bytes() || !same_cookie(data, fake_cookie) {
        return Err(X11Error::BadCookie);
    }
    let (new_name, new_data): (&[u8], &[u8]) = match real_cookie {
        Some(cookie) => (AUTH_PROTOCOL.as_bytes(), cookie),
        None => (b"", b""),
    };
    let encode_u16 = |value: usize| -> [u8; 2] {
        let value = value as u16;
        if buffer[0] == b'B' {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    };
    let mut setup = buffer[..6].to_vec();
    setup.extend_from_slice(&encode_u16(new_name.len()));
    setup.extend_from_slice(&encode_u16(new_data.len()));
    setup.extend_from_slice(&buffer[10..12]);
    for part in [new_name, new_data] {
        setup.extend_from_slice(part);
        setup.resize(setup.len() + padded(part.len()) - part.len(), 0);
    }
    setup.extend_from_slice(&buffer[total..]);
    Ok(SetupRewrite::Ready(setup))
}

/// Reenvío X11 de una conexión SSH: la pantalla local y las dos cookies.
pub struct X11Forwarding {
    display: LocalDisplay,
    fake_cookie: [u8; COOKIE_LEN],
    real_cookie: Option<Vec<u8>>,
}

impl X11Forwarding {
    pub fn new(display: LocalDisplay, real_cookie: Option<Vec<u8>>) -> Self {
        Self {
            display,
            fake_cookie: rand::random(),
            real_cookie,
        }
    }

    /// Prepara el reenvío hacia `display`, leyendo su cookie con `xauth` si está instalado.
    pub async fn for_display(display: &str) -> Result<Self, X11Error> {
        let parsed = parse_display(display)?;
        Ok(Self::new(parsed, read_xauth_cookie(display).await))
    }

    /// Cookie falsa en hexadecimal, tal como se envía en `x11-req`.
    pub fn fake_cookie_hex(&self) -> String {
        encode_hex(&self.fake_cookie)
    }

    pub fn screen(&self) -> u32 {
        self.display.screen()
    }

    /// Atiende un canal X11 abierto por el servidor hasta que se cierre.
    pub async fn serve(self: Arc<Self>, channel: Channel<Msg>) {
        let mut remote = channel.into_stream();
        if let Err(e) = self.proxy(&mut remote).await {
            tracing::warn!(error = %e, "conexión X11 rechazada o terminada con error");
        }
    }

    async fn proxy<S>(&self, remote: &mut S) -> Result<(), SshError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let setup = self.read_setup(remote).await?;
        match &self.display {
            LocalDisplay::Tcp { host, port, .. } => {
                let mut local = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
                local.write_all(&setup).await?;
                tokio::io::copy_bidirectional(remote, &mut local).await?;
            }
            #[cfg(unix)]
            LocalDisplay::Unix { path, .. } => {
                let mut local = tokio::net::UnixStream::connect(path).await?;
                local.write_all(&setup).await?;
                tokio::io::copy_bidirectional(remote, &mut local).await?;
            }
            #[cfg(not(unix))]
            LocalDisplay::Unix { path, .. } => {
                return Err(std::io::Error::other(format!(
                    "este sistema no admite el socket X11 {}",
                    path.display()
                ))
                .into());
            }
        }
        Ok(())
    }

    async fn read_setup<S>(&self, remote: &mut S) -> Result<Vec<u8>, SshError>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match rewrite_setup(&buffer, &self.fake_cookie, self.real_cookie.as_deref())? {
                SetupRewrite::Ready(setup) => return Ok(setup),
                SetupRewrite::Incomplete if buffer.len() > MAX_SETUP_LEN => {
                    return Err(X11Error::BadSetup.into());
                }
                SetupRewrite::Incomplete => {}
            }
            let read = remote.read(&mut chunk).await?;
            if read == 0 {
                return Err(X11Error::BadSetup.into());
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Rutas donde suele estar `xauth`; las apps abiertas desde el Finder no heredan el PATH.
const XAUTH_PATHS: [&str; 3] = ["xauth", "/opt/X11/bin/xauth", "/usr/bin/xauth"];

async fn read_xauth_cookie(display_name: &str) -> Option<Vec<u8>> {
    for program in XAUTH_PATHS {
        let output = tokio::process::Command::new(program)
            .args(["list", display_name])
            .output()
            .await;
        if let Ok(output) = output {
            let cookie = parse_xauth_list(&String::from_utf8_lossy(&output.stdout));
            if cookie.is_some() {
                return cookie;
            }
        }
    }
    tracing::info!(
        display = display_name,
        "sin cookie de xauth; se conecta al servidor X sin autenticar"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_number_and_screen_are_parsed() {
        let tcp = parse_display("servidor:2.1").unwrap();
        assert_eq!(
            tcp,
            LocalDisplay::Tcp {
                host: "servidor".into(),
                port: 6002,
                screen: 1
            }
        );
        assert_eq!(
            parse_display("localhost:0").unwrap(),
            LocalDisplay::Tcp {
                host: "localhost".into(),
                port: 6000,
                screen: 0
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_display_uses_unix_socket() {
        let expected = LocalDisplay::Unix {
            path: "/tmp/.X11-unix/X0".into(),
            screen: 0,
        };
        assert_eq!(parse_display(":0").unwrap(), expected);
        assert_eq!(parse_display("unix:0").unwrap(), expected);
    }

    #[test]
    fn xquartz_socket_path_keeps_display_number() {
        let display = "/private/tmp/com.apple.launchd.abc/org.xquartz:0";
        assert_eq!(
            parse_display(display).unwrap(),
            LocalDisplay::Unix {
                path: display.into(),
                screen: 0
            }
        );
    }

    #[test]
    fn xquartz_socket_path_drops_only_the_screen() {
        let parsed = parse_display("/tmp/launchd.a/org.xquartz:0.1").unwrap();
        assert_eq!(
            parsed,
            LocalDisplay::Unix {
                path: "/tmp/launchd.a/org.xquartz:0".into(),
                screen: 1
            }
        );
    }

    #[test]
    fn invalid_displays_are_rejected() {
        for display in ["", "sin-numero", ":x", "host:99999"] {
            assert!(parse_display(display).is_err(), "{display}");
        }
    }

    #[test]
    fn xauth_cookie_is_read_from_list_output() {
        let output = "mac/unix:0  MIT-MAGIC-COOKIE-1  00ff10a0\n";
        assert_eq!(parse_xauth_list(output), Some(vec![0x00, 0xff, 0x10, 0xa0]));
        assert_eq!(
            parse_xauth_list("mac/unix:0  XDM-AUTHORIZATION-1  00ff\n"),
            None
        );
        assert_eq!(parse_xauth_list(""), None);
    }

    fn setup_message(order: u8, name: &[u8], data: &[u8], trailing: &[u8]) -> Vec<u8> {
        let encode = |v: u16| {
            if order == b'B' {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut msg = vec![order, 0];
        msg.extend_from_slice(&encode(11));
        msg.extend_from_slice(&encode(0));
        msg.extend_from_slice(&encode(name.len() as u16));
        msg.extend_from_slice(&encode(data.len() as u16));
        msg.extend_from_slice(&[0, 0]);
        for part in [name, data] {
            msg.extend_from_slice(part);
            msg.resize(msg.len() + padded(part.len()) - part.len(), 0);
        }
        msg.extend_from_slice(trailing);
        msg
    }

    #[test]
    fn fake_cookie_is_replaced_by_real_one_in_both_byte_orders() {
        let fake = [7u8; COOKIE_LEN];
        let real = [9u8; COOKIE_LEN];
        for order in *b"Bl" {
            let incoming = setup_message(order, AUTH_PROTOCOL.as_bytes(), &fake, b"resto");
            let expected = setup_message(order, AUTH_PROTOCOL.as_bytes(), &real, b"resto");
            assert_eq!(
                rewrite_setup(&incoming, &fake, Some(&real)),
                Ok(SetupRewrite::Ready(expected))
            );
        }
    }

    #[test]
    fn without_real_cookie_the_authentication_is_removed() {
        let fake = [7u8; COOKIE_LEN];
        let incoming = setup_message(b'l', AUTH_PROTOCOL.as_bytes(), &fake, b"");
        let expected = setup_message(b'l', b"", b"", b"");
        assert_eq!(
            rewrite_setup(&incoming, &fake, None),
            Ok(SetupRewrite::Ready(expected))
        );
    }

    #[test]
    fn wrong_cookie_or_protocol_is_rejected() {
        let fake = [7u8; COOKIE_LEN];
        let wrong = setup_message(b'l', AUTH_PROTOCOL.as_bytes(), &[8u8; COOKIE_LEN], b"");
        assert_eq!(rewrite_setup(&wrong, &fake, None), Err(X11Error::BadCookie));
        let other = setup_message(b'l', b"XDM-AUTHORIZATION-1", &fake, b"");
        assert_eq!(rewrite_setup(&other, &fake, None), Err(X11Error::BadCookie));
        let bad_order = setup_message(b'x', AUTH_PROTOCOL.as_bytes(), &fake, b"");
        assert_eq!(
            rewrite_setup(&bad_order, &fake, None),
            Err(X11Error::BadSetup)
        );
    }

    #[test]
    fn partial_setup_waits_for_more_bytes() {
        let fake = [7u8; COOKIE_LEN];
        let full = setup_message(b'B', AUTH_PROTOCOL.as_bytes(), &fake, b"");
        for cut in [0, 5, SETUP_HEADER_LEN, full.len() - 1] {
            assert_eq!(
                rewrite_setup(&full[..cut], &fake, None),
                Ok(SetupRewrite::Incomplete),
                "{cut}"
            );
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    #[tokio::test]
    async fn proxy_forwards_rewritten_setup_to_local_display() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let display = LocalDisplay::Tcp {
            host: "127.0.0.1".into(),
            port,
            screen: 0,
        };
        let real = vec![9u8; COOKIE_LEN];
        let forwarding = X11Forwarding::new(display, Some(real.clone()));
        let incoming = setup_message(b'l', AUTH_PROTOCOL.as_bytes(), &forwarding.fake_cookie, b"");
        let (mut remote_side, mut proxy_side) = tokio::io::duplex(4096);
        remote_side.write_all(&incoming).await.unwrap();
        let proxy = tokio::spawn(async move { forwarding.proxy(&mut proxy_side).await });
        let (mut local, _) = listener.accept().await.unwrap();
        let expected = setup_message(b'l', AUTH_PROTOCOL.as_bytes(), &real, b"");
        let mut received = vec![0u8; expected.len()];
        local.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        local.write_all(b"respuesta-x").await.unwrap();
        let mut reply = [0u8; 11];
        remote_side.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"respuesta-x");
        drop(remote_side);
        drop(local);
        proxy.await.unwrap().ok();
    }
}
