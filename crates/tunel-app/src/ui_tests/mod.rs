//! Pruebas de la interfaz: la app entera en un arnés sin ventana, manejada por su árbol de
//! accesibilidad como lo haría una persona (buscar un texto, pulsar, escribir). Cada prueba
//! usa una bóveda nueva en una carpeta temporal y no sale a internet.

mod editing;
mod enable;
mod lock;
mod navigation;
mod panes;
mod prompts;
mod tabs;
mod vaultwarden;

use crate::app::TunelApp;
use egui_kittest::kittest::{By, Queryable, by};
use egui_kittest::{Harness, Node};
use std::path::PathBuf;
use tunel_core::crypto::KdfParams;
use tunel_core::{UnlockedVault, VaultData};

pub const PASSWORD: &str = "Prueba-de-interfaz-2026";
const WINDOW: egui::Vec2 = egui::vec2(1200.0, 800.0);

pub struct TestApp {
    pub harness: Harness<'static, TunelApp>,
    pub path: PathBuf,
    _dir: tempfile::TempDir,
}

impl TestApp {
    /// La app recién abierta, sin bóveda: la pantalla de bienvenida.
    pub fn first_run() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        Self::open(dir, path)
    }

    /// La app en la pantalla de bloqueo de una bóveda con `data`.
    pub fn locked(data: VaultData) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut vault =
            UnlockedVault::create(path.clone(), PASSWORD, KdfParams::FAST_FOR_TESTS).unwrap();
        vault.commit(data).unwrap();
        Self::open(dir, path)
    }

    /// La app desbloqueada con la contraseña, como al entrar cada día.
    pub fn unlocked(data: VaultData) -> Self {
        let mut app = Self::locked(data);
        app.type_into(&placeholder("Contraseña maestra"), PASSWORD);
        app.click(&button("Desbloquear"));
        if app.harness.state().vault.is_none() {
            panic!("no se desbloqueó; en pantalla: {:?}", app.visible_text());
        }
        app
    }

    /// Los textos que se ven, para explicar por qué falló una prueba.
    pub fn visible_text(&self) -> Vec<String> {
        use egui_kittest::kittest::NodeT;
        self.harness
            .query_all(by().role(egui::accesskit::Role::Label))
            .filter_map(|n| n.accesskit_node().value())
            .collect()
    }

    fn open(dir: tempfile::TempDir, path: PathBuf) -> Self {
        let vault_path = path.clone();
        let harness = Harness::builder()
            .with_size(WINDOW)
            .build_eframe(move |cc| {
                // Lo mismo que hace `main` antes de crear la app.
                crate::ui::theme::install_fonts(&cc.egui_ctx, None, None);
                crate::ui::theme::apply(&cc.egui_ctx, crate::ui::theme::DARK);
                let mut app = TunelApp::build(cc, vault_path).unwrap();
                app.updates = crate::updates::UpdateChecker::never();
                app
            });
        Self {
            harness,
            path,
            _dir: dir,
        }
    }

    pub fn get(&self, by: &By<'static>) -> Node<'_> {
        self.harness.get(by.clone())
    }

    pub fn exists(&self, by: &By<'static>) -> bool {
        self.harness.query_all(by.clone()).next().is_some()
    }

    /// Pulsa y deja que la interfaz reaccione. Antes lo trae a la vista, como haría una
    /// persona: un clic fuera de la ventana no llega a nada.
    pub fn click(&mut self, by: &By<'static>) {
        self.get(by).scroll_to_me();
        self.settle();
        self.get(by).click();
        self.settle();
    }

    pub fn type_into(&mut self, by: &By<'static>, text: &str) {
        let field = self.get(by);
        field.focus();
        field.type_text(text);
        self.settle();
    }

    /// Cambia todo el texto de un campo, como al seleccionarlo y escribir encima.
    pub fn fill(&mut self, by: &By<'static>, text: &str) {
        let field = self.get(by);
        field.focus();
        field.set_text_value_accesskit(text);
        self.settle();
    }

    pub fn key(&mut self, modifiers: egui::Modifiers, key: egui::Key) {
        self.harness.key_press_modifiers(modifiers, key);
        self.settle();
    }

    /// Unos cuantos fotogramas: lo justo para que se abran ventanas y menús. No se espera a que
    /// la app deje de pedir repintados: una terminal abierta los pide siempre.
    pub fn settle(&mut self) {
        self.harness.run_steps(4);
    }

    /// Bloquea la app y lee la bóveda tal como quedó en el disco (abierta, la app no deja
    /// que nadie más la abra).
    pub fn lock_and_read(&mut self) -> VaultData {
        self.harness.state_mut().lock_vault();
        self.settle();
        UnlockedVault::unlock(self.path.clone(), PASSWORD)
            .unwrap()
            .data
            .clone()
    }
}

/// Un texto visible (etiqueta, título) o el nombre de un control.
pub fn text(label: &'static str) -> By<'static> {
    by().label(label)
}

/// Un botón por su texto, lleve o no icono delante (`ui::with_icon` los separa con dos espacios).
pub fn button(label: &'static str) -> By<'static> {
    by().role(egui::accesskit::Role::Button)
        .predicate(move |node| {
            node.label().is_some_and(|l| {
                let l = l.trim();
                l == label || l.ends_with(&format!("  {label}"))
            })
        })
}

/// Un campo de texto que solo se reconoce por el texto de ayuda que muestra vacío.
pub fn placeholder(hint: &'static str) -> By<'static> {
    // Los datos crudos: el consumidor oculta el texto de ayuda en cuanto el campo tiene texto.
    by().predicate(move |node| node.data().placeholder() == Some(hint))
}

/// Un desplegable por el nombre de su etiqueta.
pub fn combo(label: &'static str) -> By<'static> {
    by().label(label).role(egui::accesskit::Role::ComboBox)
}

/// Un campo de texto con su etiqueta al lado (`labelled_by`).
pub fn field(label: &'static str) -> By<'static> {
    by().label(label).predicate(|node| {
        matches!(
            node.role(),
            egui::accesskit::Role::TextInput
                | egui::accesskit::Role::MultilineTextInput
                | egui::accesskit::Role::PasswordInput
        )
    })
}
