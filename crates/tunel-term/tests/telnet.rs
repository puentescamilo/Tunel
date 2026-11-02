//! Telnet de punta a punta contra un servidor TCP que negocia como uno real.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tunel_core::io::{SessionInput, SessionIo, SessionOutput, session_pair};

const TIMEOUT: Duration = Duration::from_secs(10);
const IAC: u8 = 255;
const DO: u8 = 253;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const ECHO: u8 = 1;
const TTYPE: u8 = 24;
const NAWS: u8 = 31;

/// Arranca el cliente contra un servidor nuevo y devuelve los dos extremos.
async fn connect(cols: u16, rows: u16) -> (TcpStream, SessionIo) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (io, backend) = session_pair();
    tokio::spawn(tunel_term::telnet::run("127.0.0.1", port, cols, rows, backend));
    let (server, _) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("el cliente no se conectó")
        .unwrap();
    (server, io)
}

/// Lee del cliente hasta que llegue `expected`; devuelve todo lo leído.
async fn read_until(server: &mut TcpStream, expected: &[u8]) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    tokio::time::timeout(TIMEOUT, async {
        while !seen.windows(expected.len()).any(|w| w == expected) {
            let n = server.read(&mut buf).await.unwrap();
            assert!(n > 0, "el cliente cerró; llegó {seen:?}");
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no llegó {expected:?}; llegó {seen:?}"));
    seen
}

/// Lo que el cliente pasa a la terminal hasta que llegue `expected`.
async fn output_until(io: &mut SessionIo, expected: &[u8]) -> Vec<u8> {
    let mut seen = Vec::new();
    tokio::time::timeout(TIMEOUT, async {
        while !seen.windows(expected.len()).any(|w| w == expected) {
            match io.output.recv().await {
                Some(SessionOutput::Data(data)) => seen.extend(data),
                other => panic!("se esperaban datos, llegó {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no llegó {expected:?} a la terminal; llegó {seen:?}"));
    seen
}

fn naws(cols: u16, rows: u16) -> Vec<u8> {
    [&[IAC, SB, NAWS][..], &cols.to_be_bytes(), &rows.to_be_bytes(), &[IAC, SE]].concat()
}

#[tokio::test]
async fn negotiates_echo_terminal_type_and_window_size() {
    let (mut server, mut io) = connect(80, 24).await;
    server
        .write_all(&[IAC, WILL, ECHO, IAC, DO, TTYPE, IAC, DO, NAWS])
        .await
        .unwrap();
    let replies = read_until(&mut server, &naws(80, 24)).await;
    assert!(replies.windows(3).any(|w| w == [IAC, DO, ECHO]));
    assert!(replies.windows(3).any(|w| w == [IAC, WILL, TTYPE]));

    // El servidor pide el tipo de terminal.
    server.write_all(&[IAC, SB, TTYPE, 1, IAC, SE]).await.unwrap();
    let ttype = [&[IAC, SB, TTYPE, 0][..], b"XTERM-256COLOR", &[IAC, SE]].concat();
    read_until(&mut server, &ttype).await;

    // Al cambiar el tamaño de la ventana se avisa.
    io.input.send(SessionInput::Resize { cols: 120, rows: 40 }).unwrap();
    read_until(&mut server, &naws(120, 40)).await;

    // Las órdenes no llegan a la pantalla; el texto sí.
    server.write_all(b"login: ").await.unwrap();
    assert_eq!(output_until(&mut io, b"login: ").await, b"login: ");
}

#[tokio::test]
async fn escapes_iac_and_bare_carriage_returns_in_both_directions() {
    let (mut server, mut io) = connect(80, 24).await;
    // Un 0xFF en los datos llega duplicado y la terminal lo recibe una vez.
    server.write_all(&[b'a', IAC, IAC, b'b']).await.unwrap();
    assert_eq!(output_until(&mut io, b"b").await, [b'a', IAC, b'b']);

    // Al revés: Enter es CR NUL y el 0xFF se duplica.
    io.input
        .send(SessionInput::Data(vec![b'a', b'n', b'a', b'\r', IAC]))
        .unwrap();
    let sent = read_until(&mut server, &[b'\r', 0, IAC, IAC]).await;
    assert_eq!(sent, [b'a', b'n', b'a', b'\r', 0, IAC, IAC]);
}

#[tokio::test]
async fn the_session_ends_when_the_server_closes() {
    let (server, mut io) = connect(80, 24).await;
    drop(server);
    let end = tokio::time::timeout(TIMEOUT, io.output.recv()).await.unwrap();
    assert!(
        matches!(end, Some(SessionOutput::Closed { exit_status: None })),
        "{end:?}"
    );
}

#[tokio::test]
async fn closing_the_tab_closes_the_connection() {
    let (mut server, io) = connect(80, 24).await;
    io.input.send(SessionInput::Close).unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(TIMEOUT, server.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(n, 0, "el cliente debía cerrar la conexión");
}

#[tokio::test]
async fn an_unreachable_host_is_an_error() {
    // Un puerto recién liberado: nadie escucha.
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (_io, backend) = session_pair();
    let result = tunel_term::telnet::run("127.0.0.1", port, 80, 24, backend).await;
    assert!(result.is_err());
}
