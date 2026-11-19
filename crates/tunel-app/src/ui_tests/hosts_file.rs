//! El archivo hosts se edita como texto y se guarda con una copia del anterior. Aquí es un
//! archivo de prueba: el del sistema necesitaría permisos de administrador.

use super::*;
use crate::hosts_file::{HostsFileEditor, backup_dir, list_backups};

const EDITOR: &str = "Contenido del archivo hosts";

fn with_hosts_file(content: &str) -> (TestApp, PathBuf) {
    let mut app = TestApp::unlocked(VaultData::default());
    let path = app.path.with_file_name("hosts");
    std::fs::write(&path, content).unwrap();
    app.harness.state_mut().hosts_file = HostsFileEditor::new(path.clone());
    app.click(&button("Archivo hosts"));
    (app, path)
}

#[test]
fn an_edited_hosts_file_is_saved_with_a_backup_of_the_previous_one() {
    let (mut app, path) = with_hosts_file("127.0.0.1 localhost\n");
    assert!(app.exists(&field(EDITOR)));

    app.fill(&field(EDITOR), "127.0.0.1 localhost\n10.0.0.15 web-01.lab\n");
    assert!(app.exists(&text("Cambios sin guardar")));
    app.click(&button("Guardar…"));
    for _ in 0..50 {
        if app.harness.state().hosts_file.saving.is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        app.settle();
    }

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "127.0.0.1 localhost\n10.0.0.15 web-01.lab\n"
    );
    let copies = list_backups(&backup_dir(&app.path));
    assert_eq!(copies.len(), 1);
    assert_eq!(
        std::fs::read_to_string(&copies[0].path).unwrap(),
        "127.0.0.1 localhost\n"
    );
    assert!(!app.exists(&text("Cambios sin guardar")));
}

#[test]
fn lines_the_system_does_not_understand_are_pointed_out() {
    let (mut app, _path) = with_hosts_file("127.0.0.1 localhost\n");

    app.fill(&field(EDITOR), "127.0.0.1 localhost\n10.0.0.300 web\n");

    assert!(app.exists(&text("Línea 2: «10.0.0.300» no es una dirección IP")));
}

#[test]
fn discarding_goes_back_to_what_is_on_disk() {
    let (mut app, path) = with_hosts_file("127.0.0.1 localhost\n");

    app.fill(&field(EDITOR), "basura\n");
    app.click(&button("Descartar"));

    assert_eq!(app.harness.state().hosts_file.text, "127.0.0.1 localhost\n");
    assert_eq!(std::fs::read_to_string(path).unwrap(), "127.0.0.1 localhost\n");
}
