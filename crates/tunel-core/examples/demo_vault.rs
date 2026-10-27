//! Crea una bóveda de demostración para probar la interfaz.
//!
//! Uso: `cargo run -p tunel-core --example demo_vault -- <ruta> <contraseña>`

use tunel_core::crypto::KdfParams;
use tunel_core::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("falta la ruta de la bóveda")?;
    let password = args.next().ok_or("falta la contraseña")?;
    let _ = std::fs::remove_file(&path);
    let mut vault = UnlockedVault::create(path, &password, KdfParams::RECOMMENDED)?;

    let deploy = Identity {
        password: Some("demo".into()),
        ..Identity::new("deploy", "deploy")
    };
    let root = Identity::new("root", "root");
    let prod = Group {
        identity: Some(deploy.id),
        ..Group::new("Producción")
    };
    let staging = Group {
        identity: Some(deploy.id),
        ..Group::new("Staging")
    };
    let network = Group {
        identity: Some(root.id),
        ..Group::new("Red")
    };
    let bastion = Host {
        group: Some(prod.id),
        tags: vec!["bastión".into()],
        ..Host::new("bastion", "bastion.ejemplo.com")
    };
    let hosts = vec![
        Host {
            group: Some(prod.id),
            tags: vec!["web".into()],
            jump_hosts: vec![bastion.id],
            ..Host::new("web-01", "10.0.1.11")
        },
        Host {
            group: Some(prod.id),
            tags: vec!["web".into()],
            jump_hosts: vec![bastion.id],
            ..Host::new("web-02", "10.0.1.12")
        },
        Host {
            group: Some(prod.id),
            tags: vec!["db".into()],
            port: Some(2222),
            ..Host::new("postgres", "10.0.2.5")
        },
        bastion,
        Host {
            group: Some(staging.id),
            protocol: Some(Protocol::Mosh {
                server_command: None,
            }),
            ..Host::new("staging-app", "staging.ejemplo.com")
        },
        Host {
            group: Some(network.id),
            protocol: Some(Protocol::Telnet),
            ..Host::new("switch-core", "192.168.0.2")
        },
        Host {
            group: Some(network.id),
            protocol: Some(Protocol::Serial {
                device: "/dev/tty.usbserial".into(),
                baud_rate: 9600,
            }),
            ..Host::new("consola-router", "")
        },
        Host::new("raspberry", "raspberrypi.local"),
    ];
    let web = hosts[0].id;
    let mut data = vault
        .data
        .with_identity(deploy)
        .with_identity(root)
        .with_group(prod)
        .with_group(staging)
        .with_group(network);
    for host in hosts {
        data = data.with_host(host);
    }
    data = data
        .with_snippet(Snippet::new("Espacio en disco", "df -h"))
        .with_snippet(Snippet::new(
            "Actualizar paquetes",
            "sudo apt update && sudo apt upgrade -y",
        ))
        .with_forward(PortForward {
            label: "Grafana".into(),
            ..PortForward::local(web, 3000, "localhost", 3000)
        })
        .trust_host_key(KnownHost {
            host: "bastion.ejemplo.com".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:Zl7mJ0dQ2b8kq5f3m0YtLq4nX1bJr6vV9cWuA2sEo0k".into(),
        });
    vault.commit(data)?;
    println!(
        "bóveda de demostración creada en {}",
        vault.path().display()
    );
    Ok(())
}
