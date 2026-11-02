//! Ventana para importar máquinas de la nube como hosts: se elige el proveedor y la cuenta,
//! se buscan sus máquinas y se marcan las que se quieren.

use crate::app::TunelApp;
use crate::cloud::{self, Account};
use crate::engine::AppEvent;
use crate::ui;
use egui::RichText;
use tunel_core::cloud::{CloudHost, Provider, import_into};

const WIDTH: f32 = 560.0;

/// Algo que se pide a la herramienta de la nube.
pub enum Loading<T> {
    Idle,
    Busy,
    Ready(T),
    Failed(String),
}

/// Qué cuenta y región se consultaron, para descartar respuestas viejas.
#[derive(Clone, PartialEq, Eq)]
pub struct Query {
    provider: Provider,
    account: String,
    region: String,
}

pub enum CloudEvent {
    Accounts {
        provider: Provider,
        result: Result<(Vec<Account>, Option<String>), String>,
    },
    Machines {
        query: Query,
        result: Result<Vec<CloudHost>, String>,
    },
}

pub struct CloudImport {
    provider: Provider,
    accounts: Loading<Vec<Account>>,
    account: usize,
    /// Solo para AWS, que consulta una región cada vez.
    region: String,
    machines: Loading<(Query, Vec<CloudHost>)>,
    selected: Vec<bool>,
    private: bool,
    group: String,
}

pub fn open(app: &mut TunelApp) {
    app.cloud_import = Some(CloudImport {
        provider: Provider::Aws,
        accounts: Loading::Idle,
        account: 0,
        region: String::new(),
        machines: Loading::Idle,
        selected: Vec::new(),
        private: false,
        group: String::new(),
    });
    load_accounts(app, Provider::Aws);
}

fn load_accounts(app: &mut TunelApp, provider: Provider) {
    let Some(state) = app.cloud_import.as_mut() else {
        return;
    };
    state.provider = provider;
    state.accounts = Loading::Busy;
    state.machines = Loading::Idle;
    state.account = 0;
    app.engine.background(async move {
        let result = match cloud::accounts(provider).await {
            Ok(accounts) => {
                let region = match (provider, accounts.first()) {
                    (Provider::Aws, Some(first)) => cloud::aws_region(&first.value).await,
                    _ => None,
                };
                Ok((accounts, region))
            }
            Err(e) => Err(e),
        };
        AppEvent::Cloud(CloudEvent::Accounts { provider, result })
    });
}

fn search(app: &mut TunelApp) {
    let Some(state) = app.cloud_import.as_mut() else {
        return;
    };
    let Loading::Ready(accounts) = &state.accounts else {
        return;
    };
    let Some(account) = accounts.get(state.account) else {
        return;
    };
    let query = Query {
        provider: state.provider,
        account: account.value.clone(),
        region: state.region.trim().to_string(),
    };
    state.group = match state.provider {
        Provider::Aws => format!("AWS {} {}", account.label, query.region),
        other => format!("{} {}", other.label(), account.label),
    };
    state.machines = Loading::Busy;
    app.engine.background(async move {
        let result = cloud::machines(query.provider, &query.account, &query.region).await;
        AppEvent::Cloud(CloudEvent::Machines { query, result })
    });
}

pub fn on_event(app: &mut TunelApp, event: CloudEvent) {
    let Some(state) = app.cloud_import.as_mut() else {
        return;
    };
    match event {
        CloudEvent::Accounts { provider, result } if provider == state.provider => {
            state.accounts = match result {
                Ok((accounts, region)) => {
                    if let Some(region) = region {
                        state.region = region;
                    }
                    Loading::Ready(accounts)
                }
                Err(e) => Loading::Failed(e),
            };
        }
        CloudEvent::Machines { query, result } if query.provider == state.provider => {
            state.machines = match result {
                Ok(machines) => {
                    state.selected = default_selection(&machines, state.private);
                    Loading::Ready((query, machines))
                }
                Err(e) => Loading::Failed(e),
            };
        }
        _ => {}
    }
}

/// Se marcan las encendidas que tienen dirección.
fn default_selection(machines: &[CloudHost], private: bool) -> Vec<bool> {
    machines
        .iter()
        .map(|m| m.running && m.address(private).is_some())
        .collect()
}

pub fn show(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(state) = app.cloud_import.as_mut() else {
        return;
    };
    let p = ui::theme::palette(ctx);
    let mut close = false;
    let mut change_provider = None;
    let mut do_search = false;
    let mut do_import = false;
    let modal = egui::Modal::new(egui::Id::unique("importar-nube")).show(ctx, |ui| {
        ui.set_width(WIDTH);
        ui.label(RichText::new("Importar de la nube").size(18.0).strong());
        ui.label(
            RichText::new(
                "Túnel usa la herramienta de cada proveedor con la sesión que ya tengas iniciada; \
                 no guarda credenciales de la nube.",
            )
            .size(12.0)
            .color(p.muted),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            for provider in Provider::ALL {
                if ui
                    .selectable_label(state.provider == provider, provider.label())
                    .clicked()
                    && state.provider != provider
                {
                    change_provider = Some(provider);
                }
            }
        });
        ui.add_space(6.0);
        match &state.accounts {
            Loading::Idle | Loading::Busy => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!("Buscando «{}»…", cloud::program(state.provider)));
                });
            }
            Loading::Failed(error) => {
                ui.colored_label(p.danger, error);
            }
            Loading::Ready(accounts) if accounts.is_empty() => {
                ui.colored_label(
                    p.warning,
                    format!(
                        "No hay cuentas configuradas. {}",
                        cloud::setup_hint(state.provider)
                    ),
                );
            }
            Loading::Ready(accounts) => {
                let noun = match state.provider {
                    Provider::Aws => "Perfil",
                    Provider::Azure => "Suscripción",
                    Provider::DigitalOcean => "Contexto",
                };
                egui::Grid::new("nube-cuenta")
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label(noun);
                        egui::ComboBox::from_id_salt("nube-cuentas")
                            .width(360.0)
                            .selected_text(
                                accounts.get(state.account).map_or("", |a| a.label.as_str()),
                            )
                            .show_ui(ui, |ui| {
                                for (i, account) in accounts.iter().enumerate() {
                                    ui.selectable_value(&mut state.account, i, &account.label);
                                }
                            });
                        ui.end_row();
                        if state.provider == Provider::Aws {
                            ui.label("Región");
                            ui.add(
                                egui::TextEdit::singleline(&mut state.region)
                                    .hint_text("eu-west-1")
                                    .desired_width(160.0),
                            );
                            ui.end_row();
                        }
                    });
                let ready = state.provider != Provider::Aws || !state.region.trim().is_empty();
                let busy = matches!(state.machines, Loading::Busy);
                if ui
                    .add_enabled(ready && !busy, egui::Button::new("Buscar máquinas"))
                    .clicked()
                {
                    do_search = true;
                }
            }
        }
        ui.add_space(6.0);
        match &state.machines {
            Loading::Idle => {}
            Loading::Busy => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Consultando…");
                });
            }
            Loading::Failed(error) => {
                ui.colored_label(p.danger, error);
            }
            Loading::Ready((_, machines)) if machines.is_empty() => {
                ui.label(RichText::new("No hay máquinas.").color(p.muted));
            }
            Loading::Ready((_, machines)) => {
                if ui
                    .checkbox(
                        &mut state.private,
                        "Conectar por la IP privada (VPN o bastión)",
                    )
                    .changed()
                {
                    state.selected = default_selection(machines, state.private);
                }
                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for (machine, selected) in machines.iter().zip(state.selected.iter_mut()) {
                            let address = machine.address(state.private);
                            ui.horizontal(|ui| {
                                ui.add_enabled(
                                    address.is_some(),
                                    egui::Checkbox::new(selected, ""),
                                );
                                ui.label(RichText::new(&machine.name).strong());
                                let detail = format!(
                                    "{} · {} · {}",
                                    address.unwrap_or("sin dirección"),
                                    machine.state,
                                    machine.region
                                );
                                ui.label(RichText::new(detail).size(12.0).color(p.muted));
                            });
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("Grupo");
                    ui.add(egui::TextEdit::singleline(&mut state.group).desired_width(300.0));
                });
            }
        }
        ui.add_space(12.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let count = state.selected.iter().filter(|s| **s).count();
            let can_import = count > 0
                && !state.group.trim().is_empty()
                && matches!(state.machines, Loading::Ready(_));
            if ui
                .add_enabled_ui(can_import, |ui| {
                    ui::primary_button(ui, &format!("  Importar {count}  "))
                })
                .inner
                .clicked()
            {
                do_import = true;
            }
            close |= ui::secondary_button(ui, "Cancelar").clicked();
        });
    });
    close |= modal.should_close();
    if let Some(provider) = change_provider {
        load_accounts(app, provider);
    } else if do_search {
        search(app);
    } else if do_import {
        import(app);
    } else if close {
        app.cloud_import = None;
    }
}

fn import(app: &mut TunelApp) {
    let (Some(state), Some(data)) = (app.cloud_import.take(), app.data().cloned()) else {
        return;
    };
    let Loading::Ready((_, machines)) = &state.machines else {
        return;
    };
    let chosen: Vec<CloudHost> = machines
        .iter()
        .zip(&state.selected)
        .filter(|(_, selected)| **selected)
        .map(|(m, _)| m.clone())
        .collect();
    let (updated, summary) = import_into(&data, &chosen, state.group.trim(), state.private);
    app.commit(updated);
    let mut message = format!("{} hosts importados", summary.added);
    if summary.updated > 0 {
        message.push_str(&format!(
            ", {} ya estaban (se actualizó su dirección)",
            summary.updated
        ));
    }
    app.notify(message);
}
