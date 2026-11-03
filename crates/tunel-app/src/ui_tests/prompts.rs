//! Lo que pregunta una conexión mientras se abre: la clave del servidor y las preguntas que
//! hace el propio servidor (keyboard-interactive). La respuesta vuelve a la conexión.

use super::*;
use tokio::sync::oneshot;
use tunel_core::{HostKeyStatus, KnownHost};
use tunel_ssh::Interaction;

const FINGERPRINT: &str = "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM";

fn ask_host_key(app: &mut TestApp, status: HostKeyStatus) -> oneshot::Receiver<bool> {
    let (reply, answer) = oneshot::channel();
    app.harness.state_mut().prompts.push(Interaction::HostKey {
        host: "bastion.ejemplo.com".into(),
        port: 22,
        algorithm: "ssh-ed25519".into(),
        fingerprint: FINGERPRINT.into(),
        status,
        reply,
    });
    app.settle();
    answer
}

#[test]
fn trusting_an_unknown_server_remembers_its_key() {
    let mut app = TestApp::unlocked(VaultData::default());
    let mut answer = ask_host_key(&mut app, HostKeyStatus::Unknown);
    assert!(app.exists(&text("Servidor desconocido")));
    assert!(app.exists(&text(FINGERPRINT)));
    app.harness.check_accessibility();

    app.click(&button("Confiar y conectar"));
    assert_eq!(answer.try_recv(), Ok(true));
    assert!(!app.exists(&text("Servidor desconocido")));
    let known = app.lock_and_read().known_hosts;
    assert_eq!(
        known,
        [KnownHost {
            host: "bastion.ejemplo.com".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: FINGERPRINT.into(),
        }]
    );
}

#[test]
fn a_changed_key_is_refused_by_default() {
    let old = KnownHost {
        host: "bastion.ejemplo.com".into(),
        port: 22,
        algorithm: "ssh-ed25519".into(),
        fingerprint: "SHA256:Zl7mJ0dQ2b8kq5f3m0YtLq4nX1bJr6vV9cWuA2sEo0k".into(),
    };
    let mut app = TestApp::unlocked(VaultData::default().trust_host_key(old.clone()));
    let mut answer = ask_host_key(
        &mut app,
        HostKeyStatus::Mismatch {
            expected: format!("{} {}", old.algorithm, old.fingerprint),
        },
    );
    assert!(app.exists(&text("La clave del servidor ha cambiado")));
    // Lo destacado es no conectar: aceptar la clave nueva es el botón de peligro.
    assert!(app.exists(&button("Aceptar la clave nueva")));
    app.click(&button("Cancelar"));
    assert_eq!(answer.try_recv(), Ok(false));
    // Se queda la clave de antes.
    assert_eq!(app.lock_and_read().known_hosts, [old]);
}

#[test]
fn the_questions_of_the_server_are_answered_in_order() {
    let mut app = TestApp::unlocked(VaultData::default());
    let (reply, mut answer) = oneshot::channel();
    app.harness
        .state_mut()
        .prompts
        .push(Interaction::KeyboardInteractive {
            host: "bastion.ejemplo.com".into(),
            instructions: "Segundo factor".into(),
            prompts: vec![("Contraseña:".into(), false), ("Código:".into(), true)],
            reply,
        });
    app.settle();
    assert!(app.exists(&text("Autenticación en bastion.ejemplo.com")));
    app.harness.check_accessibility();
    app.fill(&field("Contraseña:"), "secreto");
    app.fill(&field("Código:"), "123456");
    app.click(&button("Enviar"));
    assert_eq!(
        answer.try_recv(),
        Ok(Some(vec!["secreto".to_string(), "123456".to_string()]))
    );
}

#[test]
fn locking_the_vault_cancels_pending_questions() {
    let mut app = TestApp::unlocked(VaultData::default());
    let mut answer = ask_host_key(&mut app, HostKeyStatus::Unknown);
    app.harness.state_mut().lock_vault();
    app.settle();
    // La conexión que esperaba recibe un «no» al cerrarse el canal.
    assert_eq!(answer.try_recv(), Err(oneshot::error::TryRecvError::Closed));
    assert!(!app.exists(&text("Servidor desconocido")));
}
