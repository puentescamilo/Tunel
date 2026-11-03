//! Mosh de verdad: `mosh-server` en este equipo y `mosh-client` lanzado como lo lanza Túnel.
//! Sin los dos programas instalados, la prueba avisa y no hace nada.

#![cfg(unix)]

use std::process::Command;
use std::time::Duration;
use tunel_core::io::{SessionInput, SessionOutput, session_pair};
use tunel_term::local::{self, CommandSpec};

const TIMEOUT: Duration = Duration::from_secs(20);

fn installed(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Arranca `mosh-server` con `program` en lugar de la shell; devuelve puerto y clave.
fn start_server(program: &[&str]) -> (u16, String) {
    let output = Command::new("mosh-server")
        .args([
            "new",
            "-s",
            "-i",
            "127.0.0.1",
            "-p",
            "60000:61000",
            "-l",
            "LANG=en_US.UTF-8",
            "--",
        ])
        .args(program)
        .output()
        .expect("se ejecuta mosh-server");
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("MOSH CONNECT "))
        .unwrap_or_else(|| panic!("mosh-server no dio MOSH CONNECT: {text}"));
    let (port, key) = line.split_once(' ').unwrap();
    (port.parse().unwrap(), key.trim().to_string())
}

#[tokio::test]
async fn a_mosh_session_shows_the_remote_program_and_takes_input() {
    if !installed("mosh-server") || !installed("mosh-client") {
        eprintln!("aviso: mosh-server o mosh-client no están instalados; no se prueba Mosh");
        return;
    }
    // El «programa remoto» repite lo que recibe, con una marca para reconocerlo.
    let (port, key) = start_server(&[
        "sh",
        "-c",
        "echo listo-mosh; while read l; do echo \"eco:$l\"; done",
    ]);
    let (mut io, backend) = session_pair();
    local::spawn(
        &CommandSpec::mosh_client("127.0.0.1", port, &key),
        80,
        24,
        backend,
    )
    .expect("se lanza mosh-client");

    let mut screen = Vec::new();
    let mut wait_for = async |needle: &str, screen: &mut Vec<u8>| {
        tokio::time::timeout(TIMEOUT, async {
            while !String::from_utf8_lossy(screen).contains(needle) {
                match io.output.recv().await {
                    Some(SessionOutput::Data(data)) => screen.extend(data),
                    Some(SessionOutput::Error(e)) => panic!("mosh-client falló: {e}"),
                    other => panic!("la sesión terminó antes de tiempo: {other:?}"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no apareció «{needle}»: {}",
                String::from_utf8_lossy(screen)
            )
        });
    };
    wait_for("listo-mosh", &mut screen).await;
    io.input
        .send(SessionInput::Data(b"hola\r".to_vec()))
        .unwrap();
    wait_for("eco:hola", &mut screen).await;
    io.input.send(SessionInput::Close).unwrap();
}
