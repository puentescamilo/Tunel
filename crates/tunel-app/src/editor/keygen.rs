//! Generar una clave SSH nueva en el llavero.

use std::sync::mpsc::{Receiver, TryRecvError};
use tunel_core::SshKey;
use tunel_ssh::keygen::{self, GeneratedKey, KeyType, KeygenError};

/// Lo que se va a generar, y la generación en curso: una RSA tarda unos segundos.
pub struct KeyGenForm {
    pub label: String,
    pub kind: KeyType,
    pub comment: String,
    pub passphrase: String,
    pub confirm: String,
    pub error: Option<String>,
    pending: Option<Receiver<Result<GeneratedKey, KeygenError>>>,
}

/// `usuario@equipo`, como pone `ssh-keygen` en el comentario.
fn default_comment() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    match (user.is_empty(), host.is_empty()) {
        (false, false) => format!("{user}@{host}"),
        (false, true) => user,
        (true, _) => host,
    }
}

impl KeyGenForm {
    pub fn new() -> Self {
        Self {
            label: "Nueva clave".into(),
            kind: KeyType::default(),
            comment: default_comment(),
            passphrase: String::new(),
            confirm: String::new(),
            error: None,
            pending: None,
        }
    }

    pub fn generating(&self) -> bool {
        self.pending.is_some()
    }

    /// Empieza a generar la clave en otro hilo; avisa a `ctx` al terminar.
    pub fn start(&mut self, ctx: &egui::Context) -> Result<(), String> {
        if self.generating() {
            return Ok(());
        }
        if self.label.trim().is_empty() {
            return Err("Ponle un nombre a la clave".into());
        }
        if self.passphrase != self.confirm {
            return Err("Las frases de paso no coinciden".into());
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let (kind, comment, passphrase) = (
            self.kind,
            self.comment.trim().to_string(),
            self.passphrase.clone(),
        );
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let passphrase = Some(passphrase.as_str()).filter(|p| !p.is_empty());
            let _ = tx.send(keygen::generate(kind, &comment, passphrase));
            ctx.request_repaint();
        });
        self.pending = Some(rx);
        self.error = None;
        Ok(())
    }

    /// La clave, si ya está generada. Si falló, queda el error en el formulario.
    pub fn poll(&mut self) -> Option<SshKey> {
        let result = match self.pending.as_ref()?.try_recv() {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err("Se interrumpió la generación".into()),
        };
        self.pending = None;
        match result {
            Ok(generated) => {
                let mut key = SshKey::new(self.label.trim(), generated.private_key);
                key.public_key = Some(generated.public_key);
                key.passphrase = Some(self.passphrase.clone()).filter(|p| !p.is_empty());
                Some(key)
            }
            Err(e) => {
                self.error = Some(e);
                None
            }
        }
    }
}

pub fn keygen_form(ui: &mut egui::Ui, form: &mut KeyGenForm) {
    ui.add_enabled_ui(!form.generating(), |ui| {
        egui::Grid::new("form-generar-clave")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("Nombre");
                ui.text_edit_singleline(&mut form.label);
                ui.end_row();
                ui.label("Tipo");
                egui::ComboBox::from_id_salt("tipo-clave")
                    .selected_text(form.kind.label())
                    .show_ui(ui, |ui| {
                        for kind in KeyType::ALL {
                            ui.selectable_value(&mut form.kind, kind, kind.label());
                        }
                    });
                ui.end_row();
                ui.label("Comentario");
                ui.text_edit_singleline(&mut form.comment);
                ui.end_row();
                ui.label("Frase de paso");
                ui.add(egui::TextEdit::singleline(&mut form.passphrase).password(true));
                ui.end_row();
                ui.label("Repítela");
                ui.add(egui::TextEdit::singleline(&mut form.confirm).password(true));
                ui.end_row();
            });
    });
    ui.label(
        egui::RichText::new(
            "La frase de paso es opcional: protege la clave si la sacas de Túnel. Se guarda \
             en la bóveda para conectarte sin escribirla.",
        )
        .size(12.0)
        .color(crate::ui::pal(ui).muted),
    );
    if form.generating() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Generando la clave…");
        });
    }
    if let Some(error) = &form.error {
        ui.colored_label(ui.visuals().error_fg_color, error.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(form: &mut KeyGenForm) -> Option<SshKey> {
        for _ in 0..500 {
            if let Some(key) = form.poll() {
                return Some(key);
            }
            if !form.generating() {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        None
    }

    #[test]
    fn the_generated_key_keeps_its_passphrase_and_public_key() {
        let mut form = KeyGenForm {
            label: " servidor ".into(),
            passphrase: "frase".into(),
            confirm: "frase".into(),
            ..KeyGenForm::new()
        };
        form.start(&egui::Context::default()).unwrap();
        let key = wait(&mut form).expect("clave generada");
        assert_eq!(key.label, "servidor");
        assert_eq!(key.passphrase.as_deref(), Some("frase"));
        assert!(
            key.public_key
                .as_deref()
                .unwrap()
                .starts_with("ssh-ed25519 ")
        );
        assert!(key.private_key.contains("OPENSSH PRIVATE KEY"));
        assert!(key.team.is_none());
    }

    #[test]
    fn mismatched_passphrases_or_no_name_are_refused() {
        let ctx = egui::Context::default();
        let mut form = KeyGenForm {
            passphrase: "a".into(),
            confirm: "b".into(),
            ..KeyGenForm::new()
        };
        assert!(form.start(&ctx).is_err());
        assert!(!form.generating());
        let mut unnamed = KeyGenForm {
            label: "  ".into(),
            ..KeyGenForm::new()
        };
        assert!(unnamed.start(&ctx).is_err());
    }
}
