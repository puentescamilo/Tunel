//! Arranque de Mosh por SSH: se ejecuta `mosh-server` en el host y se lee su `MOSH CONNECT`.

mod support;

use tunel_ssh::mosh::{self, MoshError};

const PORTS: &str = "60000:61000";
const KEY: &str = "AbCdEfGhIjKlMnOpQrStUv";

fn answering(command: String, output: &str) -> support::Commands {
    [(command, (output.to_string(), 0))].into()
}

#[tokio::test]
async fn the_server_is_started_over_ssh_and_its_port_and_key_are_read() {
    let command = mosh::server_command(None, PORTS);
    let output = format!("\r\nMOSH CONNECT 60001 {KEY}\r\n\nmosh-server (mosh 1.4.0)\n");
    let server = support::start(answering(command.clone(), &output)).await;
    let conn = support::connect(server.port).await;

    let mosh = mosh::start_server(&conn, "localhost", None, PORTS).await.unwrap();
    assert_eq!((mosh.port, mosh.key.as_str()), (60001, KEY));
    // `localhost` se resuelve a una IP: mosh-client no resuelve nombres.
    assert!(mosh.ip == "127.0.0.1" || mosh.ip == "::1", "{}", mosh.ip);
    assert_eq!(server.executed(), [command]);
}

#[tokio::test]
async fn a_custom_server_command_is_used_as_is() {
    let command = mosh::server_command(Some("/opt/mosh/bin/mosh-server"), PORTS);
    let server =
        support::start(answering(command.clone(), &format!("MOSH CONNECT 60002 {KEY}\n"))).await;
    let conn = support::connect(server.port).await;

    let mosh = mosh::start_server(&conn, "127.0.0.1", Some("/opt/mosh/bin/mosh-server"), PORTS)
        .await
        .unwrap();
    assert_eq!(mosh.port, 60002);
    assert!(server.executed()[0].starts_with("/opt/mosh/bin/mosh-server new"));
}

#[tokio::test]
async fn without_mosh_server_on_the_host_the_error_says_what_the_host_answered() {
    let server = support::start(Default::default()).await;
    let conn = support::connect(server.port).await;

    match mosh::start_server(&conn, "127.0.0.1", None, PORTS).await {
        Err(MoshError::NoConnectLine(text)) => assert!(text.contains("not found"), "{text}"),
        other => panic!("se esperaba NoConnectLine, llegó {other:?}"),
    }
}
