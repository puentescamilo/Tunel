//! Instalar la clave pública de una clave del llavero en un host, como `ssh-copy-id`.

use super::combo;
use tunel_core::{HostId, Protocol, SshKey, VaultData};
use tunel_ssh::authorized_keys::Installed;

pub struct InstallKeyForm {
    pub key: SshKey,
    pub host: Option<HostId>,
    pub error: Option<String>,
}

impl InstallKeyForm {
    pub fn new(key: SshKey) -> Self {
        Self {
            key,
            host: None,
            error: None,
        }
    }

    /// El host elegido y la clave pública que instalar en él.
    pub fn request(&self, data: &VaultData) -> Result<(HostId, String), String> {
        let host = self
            .host
            .filter(|h| data.host(*h).is_some())
            .ok_or("Elige el host")?;
        let public = self
            .key
            .public_key
            .clone()
            .or_else(|| {
                tunel_ssh::keygen::public_key(&self.key.private_key, self.key.passphrase.as_deref())
            })
            .ok_or("No se pudo leer la clave pública de esta clave")?;
        Ok((host, public))
    }
}

/// Los hosts SSH donde se puede instalar la clave, por nombre.
fn ssh_hosts(data: &VaultData) -> Vec<(HostId, String)> {
    let mut hosts: Vec<(HostId, String)> = data
        .hosts
        .iter()
        .filter(|h| h.protocol() == Protocol::Ssh)
        .map(|h| (h.id, h.display_name().to_string()))
        .collect();
    hosts.sort_by_key(|(_, name)| name.to_lowercase());
    hosts
}

pub fn install_key_form(ui: &mut egui::Ui, form: &mut InstallKeyForm, data: &VaultData) {
    ui.label(format!("Clave «{}»", form.key.label));
    let label = ui.label("Host");
    combo(
        ui,
        "instalar-host",
        &mut form.host,
        &ssh_hosts(data),
        "(elige un host)",
    )
    .labelled_by(label.id);
    ui.label(
        egui::RichText::new(
            "Túnel se conecta al host como siempre, con su contraseña por ejemplo, y añade la \
             clave pública a ~/.ssh/authorized_keys de ese usuario si no está. Después puedes \
             usar esta clave en su identidad.",
        )
        .size(12.0)
        .color(crate::ui::pal(ui).muted),
    );
    if let Some(error) = &form.error {
        ui.colored_label(ui.visuals().error_fg_color, error.as_str());
    }
}

/// El aviso al terminar de instalar la clave en `host`.
pub fn installed_message(host: &str, result: &Result<Installed, String>) -> String {
    match result {
        Ok(Installed::Added) => format!("Clave instalada en {host}"),
        Ok(Installed::AlreadyThere) => format!("La clave ya estaba instalada en {host}"),
        Err(e) => format!("No se pudo instalar la clave en {host}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunel_core::Host;

    #[test]
    fn only_ssh_hosts_are_offered() {
        let ssh = Host::new("web", "web.example");
        let telnet = Host {
            protocol: Some(Protocol::Telnet),
            ..Host::new("switch", "10.0.0.2")
        };
        let data = VaultData::default()
            .with_host(ssh.clone())
            .with_host(telnet);
        assert_eq!(ssh_hosts(&data), vec![(ssh.id, "web".to_string())]);
    }

    #[test]
    fn the_request_needs_a_host_and_a_readable_key() {
        let host = Host::new("web", "web.example");
        let data = VaultData::default().with_host(host.clone());
        let key = tunel_ssh::keygen::generate(Default::default(), "ana", None).unwrap();
        let mut form = InstallKeyForm::new(SshKey::new("k", key.private_key));
        assert!(form.request(&data).is_err(), "sin host");
        form.host = Some(host.id);
        let (chosen, public) = form.request(&data).unwrap();
        assert_eq!(chosen, host.id);
        assert!(public.starts_with("ssh-ed25519 "));
        form.key = SshKey::new("rota", "no es una clave");
        assert!(form.request(&data).is_err());
    }

    #[test]
    fn the_message_says_what_happened() {
        assert_eq!(
            installed_message("web", &Ok(Installed::AlreadyThere)),
            "La clave ya estaba instalada en web"
        );
        assert!(installed_message("web", &Err("sin red".into())).ends_with("web: sin red"));
    }
}
