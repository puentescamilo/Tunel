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

    app.fill(
        &field(EDITOR),
        "127.0.0.1 localhost\n10.0.0.15 web-01.lab\n",
    );
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

fn wait_for_save(app: &mut TestApp) {
    for _ in 0..50 {
        if app.harness.state().hosts_file.saving.is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        app.settle();
    }
}

const BAD_LINE: &str = "Línea 2: «10.0.0.300» no es una dirección IP";

#[test]
fn bad_lines_are_pointed_out_on_save_not_while_typing() {
    let (mut app, path) = with_hosts_file("127.0.0.1 localhost\n");

    app.fill(&field(EDITOR), "127.0.0.1 localhost\n10.0.0.300 web\n");
    assert!(!app.exists(&text(BAD_LINE)), "avisa mientras se escribe");

    app.click(&button("Guardar…"));
    assert!(app.exists(&text(BAD_LINE)));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "127.0.0.1 localhost\n"
    );

    app.click(&button("Seguir editando"));
    assert!(!app.exists(&text(BAD_LINE)));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "127.0.0.1 localhost\n"
    );
}

#[test]
fn bad_lines_can_be_saved_anyway() {
    let (mut app, path) = with_hosts_file("127.0.0.1 localhost\n");

    app.fill(&field(EDITOR), "127.0.0.1 localhost\n10.0.0.300 web\n");
    app.click(&button("Guardar…"));
    app.click(&button("Guardar de todos modos"));
    wait_for_save(&mut app);

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "127.0.0.1 localhost\n10.0.0.300 web\n"
    );
    assert!(!app.exists(&text(BAD_LINE)));
}

#[test]
fn fixing_the_line_hides_the_warning() {
    let (mut app, _path) = with_hosts_file("127.0.0.1 localhost\n");

    app.fill(&field(EDITOR), "127.0.0.1 localhost\n10.0.0.300 web\n");
    app.click(&button("Guardar…"));
    app.fill(&field(EDITOR), "127.0.0.1 localhost\n10.0.0.30 web\n");

    assert!(!app.exists(&text(BAD_LINE)));
}

#[test]
fn discarding_goes_back_to_what_is_on_disk() {
    let (mut app, path) = with_hosts_file("127.0.0.1 localhost\n");

    app.fill(&field(EDITOR), "basura\n");
    app.click(&button("Descartar"));

    assert_eq!(app.harness.state().hosts_file.text, "127.0.0.1 localhost\n");
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "127.0.0.1 localhost\n"
    );
}

#[test]
fn a_half_written_name_does_not_interrupt_typing() {
    let (mut app, _path) = with_hosts_file("127.0.0.1 localhost\n");
    let editor = app.get(&field(EDITOR));
    editor.focus();
    app.settle();
    // Al final del texto, una línea nueva que se escribe en dos tandas.
    app.harness.key_press(egui::Key::End);
    app.harness
        .key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::End);
    app.settle();
    app.get(&field(EDITOR)).type_text("10.0.0.15 ui.");
    app.settle();
    app.get(&field(EDITOR)).type_text("ejemplo.com");
    app.settle();

    assert_eq!(
        app.harness.state().hosts_file.text,
        "127.0.0.1 localhost\n10.0.0.15 ui.ejemplo.com"
    );
}
