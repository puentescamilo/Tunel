//! Un servidor SSH de juguete para las pruebas de la terminal de las apps móviles:
//! `ssh-de-pruebas <usuario> <contraseña>`.
//!
//! La shell saluda con «bienvenida», devuelve en mayúsculas lo que recibe y con `exit`
//! termina. Escribe en la salida el puerto y sigue hasta que se cierra su entrada, es decir,
//! hasta que termina la prueba que lo lanzó.

use russh::keys::decode_secret_key;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use std::io::{BufRead, Write};
use std::sync::Arc;
use std::time::Duration;

/// La misma clave de servidor que las pruebas de `tunel-ssh`: es de juguete.
const HOST_KEY: &str = include_str!("../../../tunel-ssh/tests/fixtures/host_ed25519");

#[derive(Clone)]
struct Shell {
    user: Arc<str>,
    password: Arc<str>,
}

impl server::Server for Shell {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for Shell {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ok = user == &*self.user && password == &*self.password;
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"bienvenida\r\n".to_vec())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let text = String::from_utf8_lossy(data);
        if text.contains("exit") {
            session.eof(channel)?;
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
        } else {
            session.data(channel, text.to_uppercase().into_bytes())?;
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(user), Some(password)) = (args.next(), args.next()) else {
        eprintln!("uso: ssh-de-pruebas <usuario> <contraseña>");
        std::process::exit(2);
    };
    let config = Arc::new(server::Config {
        keys: vec![decode_secret_key(HOST_KEY, None).expect("clave del servidor")],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("puerto");
    let port = listener.local_addr().expect("dirección").port();
    let mut shell = Shell {
        user: user.into(),
        password: password.into(),
    };
    tokio::spawn(async move { shell.run_on_socket(config, &listener).await });

    println!("{port}");
    std::io::stdout().flush().expect("salida");
    // Hasta que la prueba cierre la entrada (o muera).
    tokio::task::spawn_blocking(|| std::io::stdin().lock().lines().count())
        .await
        .expect("entrada");
}
