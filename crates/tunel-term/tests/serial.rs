//! Consola serie de punta a punta contra un puerto virtual: una pareja de pseudoterminales
//! hace de cable, con Túnel en un extremo y el «equipo» en el otro. Solo en macOS y Linux.

#![cfg(unix)]

use serialport::{SerialPort, TTYPort};
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tunel_core::io::{SessionInput, SessionOutput, session_pair};

const TIMEOUT: Duration = Duration::from_secs(10);

/// El extremo del «equipo», y el nombre del que abre Túnel.
fn cable() -> (TTYPort, TTYPort, String) {
    let (mut device, tunel_end) = TTYPort::pair().expect("se crea la pareja de terminales");
    device.set_timeout(Duration::from_millis(50)).unwrap();
    let name = tunel_end.name().expect("el extremo tiene nombre");
    (device, tunel_end, name)
}

fn read_until(port: &mut TTYPort, expected: &[u8]) -> Vec<u8> {
    let start = Instant::now();
    let mut seen = Vec::new();
    let mut buf = [0u8; 256];
    while !seen.windows(expected.len()).any(|w| w == expected) {
        assert!(start.elapsed() < TIMEOUT, "no llegó {expected:?}; llegó {seen:?}");
        match port.read(&mut buf) {
            Ok(n) => seen.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("{e}"),
        }
    }
    seen
}

#[tokio::test]
async fn bytes_flow_both_ways_through_the_port() {
    let (mut device, _tunel_end, name) = cable();
    let (mut io, backend) = session_pair();
    tunel_term::serial::spawn(&name, 115_200, backend).expect("se abre el puerto");

    device.write_all(b"U-Boot 2026.01\r\n=> ").unwrap();
    let mut shown = Vec::new();
    tokio::time::timeout(TIMEOUT, async {
        while !shown.ends_with(b"=> ") {
            match io.output.recv().await {
                Some(SessionOutput::Data(data)) => shown.extend(data),
                other => panic!("se esperaban datos, llegó {other:?}"),
            }
        }
    })
    .await
    .expect("la salida del equipo no llegó a la terminal");
    assert_eq!(shown, b"U-Boot 2026.01\r\n=> ");

    // Sin traducir nada: lo tecleado llega tal cual, también bytes de control.
    io.input
        .send(SessionInput::Data(b"printenv\r\x03".to_vec()))
        .unwrap();
    let received = tokio::task::spawn_blocking(move || read_until(&mut device, b"\x03"))
        .await
        .unwrap();
    assert!(received.ends_with(b"printenv\r\x03"), "{received:?}");
}

#[test]
fn a_port_that_does_not_exist_is_a_clear_error() {
    let (_io, backend) = session_pair();
    let error = tunel_term::serial::spawn("/dev/no-existe-tunel", 9600, backend).unwrap_err();
    assert!(error.to_string().contains("/dev/no-existe-tunel"), "{error}");
}
