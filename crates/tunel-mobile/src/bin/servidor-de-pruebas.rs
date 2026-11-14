//! Un `tunel-server` en memoria con una cuenta que ya tiene hosts, para las pruebas de las
//! apps móviles: `servidor-de-pruebas <correo> <contraseña> [host…]`.
//!
//! Escribe en la salida la dirección del servidor (`http://127.0.0.1:…`) y sigue hasta que
//! se cierra su entrada, es decir, hasta que termina la prueba que lo lanzó.

use std::io::{BufRead, Write};
use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::vault::VaultData;
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::{check_server_url, create_account, sync_once};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(email), Some(password)) = (args.next(), args.next()) else {
        eprintln!("uso: servidor-de-pruebas <correo> <contraseña> [host…]");
        std::process::exit(2);
    };
    let hosts: Vec<String> = args.collect();

    let config = Config {
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        open_registration: true,
        unauthenticated_burst: 1000,
        ..Config::default()
    };
    let state = AppState::new(Db::open_in_memory().expect("base de datos"), config)
        .await
        .expect("servidor");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("puerto");
    let address = listener.local_addr().expect("dirección");
    tokio::spawn(async move { axum::serve(listener, router(state)).await });

    let server = check_server_url(&format!("http://{address}")).expect("dirección válida");
    let data = hosts.iter().fold(VaultData::default(), |d, label| {
        d.with_host(Host::new(label, "10.0.0.1"))
    });
    let local = create_account(&server, &email, Zeroizing::new(password), &data)
        .await
        .expect("cuenta");
    sync_once(&local, &data).await.expect("subida");

    println!("http://{address}");
    std::io::stdout().flush().expect("salida");
    // Hasta que la prueba cierre la entrada (o muera).
    tokio::task::spawn_blocking(|| std::io::stdin().lock().lines().count())
        .await
        .expect("entrada");
}
