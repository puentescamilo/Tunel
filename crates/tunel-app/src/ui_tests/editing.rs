//! Crear, editar, buscar y borrar lo que guarda la bóveda, y los ajustes.

use super::*;
use egui_kittest::kittest::NodeT;
use tunel_core::{Host, Snippet};

fn two_hosts() -> VaultData {
    VaultData::default()
        .with_host(Host::new("web-01", "web-01.ejemplo.com"))
        .with_host(Host::new("db-01", "db-01.ejemplo.com"))
}

fn host_card(name: &'static str) -> By<'static> {
    by().role(egui::accesskit::Role::Button)
        .predicate(move |n| {
            n.label()
                .is_some_and(|l| l.starts_with(&format!("{name}, ")))
        })
}

#[test]
fn a_new_host_is_listed_and_saved() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Host"));
    assert!(app.exists(&text("Nuevo host")));
    app.harness.check_accessibility();

    app.fill(&field("Nombre"), "bastión");
    app.fill(&field("Dirección"), "bastion.ejemplo.com");
    app.fill(&field("Puerto"), "2222");
    app.fill(&field("Usuario nuevo"), "ana");
    app.fill(&field("Etiquetas"), "producción, web");
    app.click(&button("Guardar"));

    assert!(!app.exists(&text("Nuevo host")), "el editor sigue abierto");
    assert!(app.exists(&button("bastión, ssh · ana@bastion.ejemplo.com")));
    let saved = app.lock_and_read();
    let host = saved.hosts.iter().find(|h| h.label == "bastión").unwrap();
    assert_eq!(host.address, "bastion.ejemplo.com");
    assert_eq!(host.port, Some(2222));
    assert_eq!(host.tags, ["producción", "web"]);
    // El usuario nuevo se guarda como una identidad del llavero.
    let identity = saved.identity(host.identity.unwrap()).unwrap();
    assert_eq!(identity.username, "ana");
}

#[test]
fn a_host_without_address_is_not_saved() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Host"));
    app.fill(&field("Nombre"), "sin dirección");
    app.click(&button("Guardar"));
    assert!(app.exists(&text("La dirección es obligatoria")));
    assert!(app.exists(&text("Nuevo host")), "el editor se cerró");
    assert!(app.harness.state().data().unwrap().hosts.is_empty());
}

#[test]
fn closing_the_editor_discards_the_changes() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Host"));
    app.fill(&field("Nombre"), "borrador");
    app.fill(&field("Dirección"), "borrador.ejemplo.com");
    app.click(&button("Cancelar"));
    assert!(!app.exists(&text("Nuevo host")));
    assert!(app.harness.state().data().unwrap().hosts.is_empty());
}

#[test]
fn a_host_is_edited_from_its_menu() {
    let mut app = TestApp::unlocked(two_hosts());
    app.get(&host_card("web-01")).click_secondary();
    app.settle();
    app.click(&button("Editar"));
    assert!(app.exists(&text("Editar host")));
    assert_eq!(app.get(&field("Nombre")).value().as_deref(), Some("web-01"));
    app.fill(&field("Nombre"), "web-02");
    app.click(&button("Guardar"));
    assert!(app.exists(&host_card("web-02")));
    assert!(!app.exists(&host_card("web-01")));
    let saved = app.lock_and_read();
    assert!(saved.hosts.iter().any(|h| h.label == "web-02"));
    assert_eq!(saved.hosts.len(), 2);
}

#[test]
fn a_host_is_deleted_from_its_menu() {
    let mut app = TestApp::unlocked(two_hosts());
    app.get(&host_card("db-01")).click_secondary();
    app.settle();
    app.click(&button("Eliminar"));
    assert!(!app.exists(&host_card("db-01")));
    assert!(app.exists(&host_card("web-01")));
    let saved = app.lock_and_read();
    assert_eq!(saved.hosts.len(), 1);
    assert_eq!(saved.hosts[0].label, "web-01");
}

#[test]
fn the_search_box_filters_the_hosts() {
    let mut app = TestApp::unlocked(two_hosts());
    app.type_into(
        &placeholder("Buscar por nombre, dirección o etiqueta"),
        "db",
    );
    assert!(app.exists(&host_card("db-01")));
    assert!(!app.exists(&host_card("web-01")));
}

#[test]
fn a_new_snippet_is_saved() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Snippets"));
    app.click(&button("Snippet"));
    assert!(app.exists(&text("Nuevo snippet")));
    app.harness.check_accessibility();
    app.fill(&field("Nombre"), "Reiniciar nginx");
    app.fill(&field("Script"), "sudo systemctl restart {{servicio}}");
    app.click(&button("Guardar"));
    assert!(app.exists(&text("Reiniciar nginx")));
    let saved = app.lock_and_read();
    assert_eq!(saved.snippets.len(), 1);
    assert_eq!(
        saved.snippets[0].script,
        "sudo systemctl restart {{servicio}}"
    );
}

#[test]
fn a_new_identity_keeps_its_password() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Llavero"));
    app.click(&button("Identidad"));
    assert!(app.exists(&text("Nueva identidad")));
    app.harness.check_accessibility();
    app.fill(&field("Nombre"), "Producción");
    app.fill(&field("Usuario"), "despliegue");
    app.fill(&field("Contraseña"), "secreto-de-prueba");
    app.click(&button("Guardar"));
    let saved = app.lock_and_read();
    let identity = &saved.identities[0];
    assert_eq!(identity.label, "Producción");
    assert_eq!(identity.username, "despliegue");
    assert_eq!(identity.password.as_deref(), Some("secreto-de-prueba"));
}

#[test]
fn the_key_editors_name_their_fields() {
    let mut app = TestApp::unlocked(VaultData::default());
    app.click(&button("Llavero"));
    app.click(&button("Clave"));
    assert!(app.exists(&text("Nueva clave SSH")));
    app.harness.check_accessibility();
    app.click(&button("Cancelar"));
    app.click(&button("Generar clave"));
    assert!(app.exists(&text("Generar clave SSH")));
    app.harness.check_accessibility();
}

#[test]
fn turning_off_autocomplete_is_saved() {
    let data = VaultData::default().with_snippet(Snippet::new("lista", "ls -la"));
    let mut app = TestApp::unlocked(data);
    app.click(&button("Ajustes"));
    let switch = by()
        .role(egui::accesskit::Role::Switch)
        .label("Autocompletar comandos");
    assert_eq!(
        app.get(&switch).accesskit_node().toggled(),
        Some(egui::accesskit::Toggled::True)
    );
    app.click(&switch);
    assert_eq!(
        app.get(&switch).accesskit_node().toggled(),
        Some(egui::accesskit::Toggled::False)
    );
    assert!(!app.lock_and_read().settings.autocomplete);
}

#[test]
fn the_group_and_tunnel_editors_name_their_fields() {
    let mut app = TestApp::unlocked(two_hosts());
    app.click(&button("Grupo"));
    assert!(app.exists(&text("Nuevo grupo")));
    app.harness.check_accessibility();
    app.click(&button("Cancelar"));
    app.click(&button("Túneles"));
    app.click(&button("Regla"));
    assert!(app.exists(&text("Nueva regla de túnel")));
    app.harness.check_accessibility();
}

#[test]
fn a_new_group_holds_its_hosts() {
    let mut app = TestApp::unlocked(two_hosts());
    app.click(&button("Grupo"));
    app.fill(&field("Nombre"), "Producción");
    app.click(&button("Guardar"));
    let group = by()
        .role(egui::accesskit::Role::Button)
        .label("Producción, 0 hosts");
    app.click(&group);
    assert!(app.exists(&text("Producción")));
    // Un host creado dentro del grupo queda en él.
    app.click(&button("Host"));
    app.fill(&field("Nombre"), "api-01");
    app.fill(&field("Dirección"), "api-01.ejemplo.com");
    app.click(&button("Guardar"));
    let saved = app.lock_and_read();
    let group = saved
        .groups
        .iter()
        .find(|g| g.name == "Producción")
        .unwrap();
    let host = saved.hosts.iter().find(|h| h.label == "api-01").unwrap();
    assert_eq!(host.group, Some(group.id));
}
