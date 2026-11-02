//! Contenedores de Docker y pods de Kubernetes de este equipo, con un botón para abrir una
//! shell en cada uno.

use super::cloud_import::Loading;
use crate::app::TunelApp;
use crate::engine::AppEvent;
use crate::ui::{self, icons};
use egui::RichText;
use tunel_core::containers::{
    Container, Pod, docker_remote_shell, docker_shell_args, kubectl_shell_args,
};
use tunel_core::{HostId, Protocol};

pub enum ContainersEvent {
    Docker(Result<Vec<Container>, String>),
    Contexts(Result<(Vec<String>, Option<String>), String>),
    Pods {
        context: String,
        result: Result<Vec<Pod>, String>,
    },
    /// Los contenedores de un servidor, por SSH.
    Remote {
        host: HostId,
        result: Result<Vec<Container>, String>,
    },
}

pub struct ContainersView {
    docker: Loading<Vec<Container>>,
    contexts: Loading<Vec<String>>,
    context: Option<String>,
    pods: Loading<Vec<Pod>>,
    /// Filtra los pods por espacio de nombres o nombre.
    filter: String,
    /// Servidor cuyos contenedores se miran.
    remote_host: Option<HostId>,
    remote: Loading<Vec<Container>>,
}

impl Default for ContainersView {
    fn default() -> Self {
        Self {
            docker: Loading::Idle,
            contexts: Loading::Idle,
            context: None,
            pods: Loading::Idle,
            filter: String::new(),
            remote_host: None,
            remote: Loading::Idle,
        }
    }
}

fn load_docker(app: &mut TunelApp) {
    app.containers.docker = Loading::Busy;
    app.engine.background(async {
        AppEvent::Containers(ContainersEvent::Docker(crate::containers::docker().await))
    });
}

fn load_contexts(app: &mut TunelApp) {
    app.containers.contexts = Loading::Busy;
    app.engine.background(async {
        AppEvent::Containers(ContainersEvent::Contexts(
            crate::containers::contexts().await,
        ))
    });
}

fn load_pods(app: &mut TunelApp, context: String) {
    app.containers.context = Some(context.clone());
    app.containers.pods = Loading::Busy;
    app.engine.background(async move {
        let result = crate::containers::pods(&context).await;
        AppEvent::Containers(ContainersEvent::Pods { context, result })
    });
}

fn ready<T>(result: Result<T, String>) -> Loading<T> {
    result.map_or_else(Loading::Failed, Loading::Ready)
}

pub fn on_event(app: &mut TunelApp, event: ContainersEvent) {
    let view = &mut app.containers;
    match event {
        ContainersEvent::Docker(result) => view.docker = ready(result),
        ContainersEvent::Contexts(result) => {
            let current = result
                .as_ref()
                .ok()
                .and_then(|(names, current)| current.clone().or_else(|| names.first().cloned()));
            view.contexts = ready(result.map(|(names, _)| names));
            if let Some(context) = current {
                load_pods(app, context);
            }
        }
        ContainersEvent::Pods { context, result } if view.context.as_deref() == Some(&context) => {
            view.pods = ready(result);
        }
        ContainersEvent::Pods { .. } => {}
        ContainersEvent::Remote { host, result } if view.remote_host == Some(host) => {
            view.remote = ready(result);
        }
        ContainersEvent::Remote { .. } => {}
    }
}

/// Mira los contenedores de `host`; desde la lista de hosts o desde esta vista.
pub fn load_remote(app: &mut TunelApp, host: HostId) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    app.containers.remote_host = Some(host);
    app.containers.remote = Loading::Busy;
    if let Err(e) = app.engine.remote_containers(&data, host) {
        app.containers.remote = Loading::Failed(format!("{e:#}"));
    }
}

/// Abre en una pestaña la shell del contenedor `container` del servidor `host`.
fn open_remote_shell(app: &mut TunelApp, host: HostId, container: &Container) {
    let Some(data) = app.data().cloned() else {
        return;
    };
    let Some(command) = docker_remote_shell(&container.id) else {
        return app.notify("Ese identificador de contenedor no es válido");
    };
    let server = data
        .host(host)
        .map(|h| h.display_name().to_string())
        .unwrap_or_default();
    match app.host_session(&data, host, Some(command)) {
        Ok(mut session) => {
            session.title = format!("🐳 {} @ {server}", container.name);
            app.push_tab(crate::app::Tab::Terminal(Box::new(session)));
        }
        Err(e) => app.notify(format!("No se pudo abrir la shell: {e:#}")),
    }
}

fn remote_section(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let Some(data) = app.data().cloned() else {
        return;
    };
    let mut hosts: Vec<(HostId, String)> = data
        .hosts
        .iter()
        .filter(|h| h.protocol() == Protocol::Ssh)
        .map(|h| (h.id, h.display_name().to_string()))
        .collect();
    hosts.sort_by_key(|(_, name)| name.to_lowercase());
    let mut chosen = None;
    let mut reload = false;
    ui.horizontal(|ui| {
        ui::section_label(ui, "Docker en un servidor");
        let current = app
            .containers
            .remote_host
            .and_then(|id| hosts.iter().find(|(h, _)| *h == id))
            .map_or("(elige un host)", |(_, name)| name.as_str());
        egui::ComboBox::from_id_salt("docker-servidor")
            .selected_text(current)
            .show_ui(ui, |ui| {
                for (id, name) in &hosts {
                    if ui
                        .selectable_label(app.containers.remote_host == Some(*id), name)
                        .clicked()
                    {
                        chosen = Some(*id);
                    }
                }
            });
        if app.containers.remote_host.is_some() {
            reload = ui::icon_button(ui, icons::REFRESH, "Volver a consultar").clicked();
        }
    });
    if let Some(host) = chosen.or(app.containers.remote_host.filter(|_| reload)) {
        load_remote(app, host);
    }
    let Some(host) = app.containers.remote_host else {
        ui.label(
            RichText::new("Elige un host SSH para ver sus contenedores, por la misma conexión.")
                .color(p.muted),
        );
        return;
    };
    if !state_line(ui, &app.containers.remote) {
        return;
    }
    let Loading::Ready(containers) = &app.containers.remote else {
        return;
    };
    if containers.is_empty() {
        ui.label(RichText::new("No hay contenedores en marcha.").color(p.muted));
    }
    let mut open = None;
    for container in containers {
        let detail = format!("{} · {}", container.image, container.status);
        row(
            ui,
            ("remoto", &container.id),
            &container.name,
            &detail,
            |ui| {
                if ui::secondary_button(ui, &ui::with_icon(icons::TERMINAL, "Shell")).clicked() {
                    open = Some(container.clone());
                }
            },
        );
    }
    if let Some(container) = open {
        open_remote_shell(app, host, &container);
    }
}

fn open_shell(app: &mut TunelApp, program: &str, title: String, args: Vec<String>) {
    match crate::containers::shell(program, args) {
        Ok(spec) => app.open_container_shell(title, spec),
        Err(e) => app.notify(e),
    }
}

/// Lo que se muestra mientras se carga o si falló; `true` si hay datos que mostrar.
fn state_line<T>(ui: &mut egui::Ui, loading: &Loading<T>) -> bool {
    let p = ui::pal(ui);
    match loading {
        Loading::Idle | Loading::Busy => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Consultando…").color(p.muted));
            });
            false
        }
        Loading::Failed(error) => {
            ui.label(RichText::new(error).color(p.danger));
            false
        }
        Loading::Ready(_) => true,
    }
}

fn row(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    title: &str,
    detail: &str,
    actions: impl FnOnce(&mut egui::Ui),
) {
    let p = ui::pal(ui);
    ui::list_row(ui, id, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new(title).strong());
                ui.label(RichText::new(detail).size(12.0).color(p.muted));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
        });
    });
    ui.add_space(2.0);
}

fn docker_section(app: &mut TunelApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui::section_label(ui, "Docker");
        if ui::icon_button(ui, icons::REFRESH, "Volver a consultar").clicked() {
            load_docker(app);
        }
    });
    if !state_line(ui, &app.containers.docker) {
        return;
    }
    let Loading::Ready(containers) = &app.containers.docker else {
        return;
    };
    if containers.is_empty() {
        ui.label(RichText::new("No hay contenedores en marcha.").color(ui::pal(ui).muted));
    }
    let mut open = None;
    for container in containers {
        let detail = format!("{} · {}", container.image, container.status);
        row(ui, &container.id, &container.name, &detail, |ui| {
            if ui::secondary_button(ui, &ui::with_icon(icons::TERMINAL, "Shell")).clicked() {
                open = Some(container.clone());
            }
        });
    }
    if let Some(c) = open {
        open_shell(
            app,
            "docker",
            format!("🐳 {}", c.name),
            docker_shell_args(&c.id),
        );
    }
}

fn kubernetes_section(app: &mut TunelApp, ui: &mut egui::Ui) {
    let p = ui::pal(ui);
    let mut reload = false;
    let mut switch = None;
    ui.horizontal(|ui| {
        ui::section_label(ui, "Kubernetes");
        if let Loading::Ready(contexts) = &app.containers.contexts {
            let current = app.containers.context.clone().unwrap_or_default();
            egui::ComboBox::from_id_salt("kube-contexto")
                .selected_text(&current)
                .show_ui(ui, |ui| {
                    for context in contexts {
                        if ui.selectable_label(*context == current, context).clicked() {
                            switch = Some(context.clone());
                        }
                    }
                });
        }
        reload = ui::icon_button(ui, icons::REFRESH, "Volver a consultar").clicked();
        ui.add(
            egui::TextEdit::singleline(&mut app.containers.filter)
                .hint_text("Filtrar pods")
                .desired_width(180.0),
        );
    });
    if let Some(context) = switch {
        load_pods(app, context);
    } else if reload {
        match app.containers.context.clone() {
            Some(context) => load_pods(app, context),
            None => load_contexts(app),
        }
    }
    if !state_line(ui, &app.containers.contexts) {
        return;
    }
    if matches!(&app.containers.contexts, Loading::Ready(c) if c.is_empty()) {
        ui.label(RichText::new("No hay clústeres en ~/.kube/config.").color(p.muted));
        return;
    }
    if !state_line(ui, &app.containers.pods) {
        return;
    }
    let (Loading::Ready(pods), Some(context)) = (&app.containers.pods, &app.containers.context)
    else {
        return;
    };
    let filter = app.containers.filter.trim().to_lowercase();
    let shown: Vec<&Pod> = pods
        .iter()
        .filter(|pod| {
            filter.is_empty()
                || pod.name.to_lowercase().contains(&filter)
                || pod.namespace.to_lowercase().contains(&filter)
        })
        .collect();
    if shown.is_empty() {
        ui.label(RichText::new("No hay pods.").color(p.muted));
    }
    let mut open = None;
    for pod in shown {
        let title = format!("{}/{}", pod.namespace, pod.name);
        let running = pod.phase == "Running";
        row(ui, ("pod", &title), &title, &pod.phase, |ui| {
            // De derecha a izquierda: el último contenedor queda a la izquierda.
            for container in pod.containers.iter().rev() {
                let label = if pod.containers.len() == 1 {
                    "Shell".to_string()
                } else {
                    container.clone()
                };
                let button = ui.add_enabled_ui(running, |ui| {
                    ui::secondary_button(ui, &ui::with_icon(icons::TERMINAL, &label))
                });
                if button.inner.clicked() {
                    open = Some((pod.clone(), container.clone()));
                }
            }
        });
    }
    if let Some((pod, container)) = open {
        let title = format!("☸ {}", pod.name);
        let args = kubectl_shell_args(context, &pod, &container);
        open_shell(app, "kubectl", title, args);
    }
}

pub fn show(app: &mut TunelApp, ui: &mut egui::Ui) {
    if matches!(app.containers.docker, Loading::Idle) {
        load_docker(app);
    }
    if matches!(app.containers.contexts, Loading::Idle) {
        load_contexts(app);
    }
    ui::page_header(
        ui,
        "Contenedores",
        "Contenedores de Docker y pods de Kubernetes de este equipo, y los de Docker en tus \
         servidores SSH.",
        |_| {},
    );
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            docker_section(app, ui);
            ui.add_space(16.0);
            kubernetes_section(app, ui);
            ui.add_space(16.0);
            remote_section(app, ui);
        });
}
