//! Paleta de conexión rápida: buscar un host guardado o conectar a `usuario@servidor:puerto`.

use crate::app::TunelApp;
use crate::ui::{self, icons};
use egui::{Align2, CornerRadius, Key, RichText, Sense, Vec2};
use tunel_core::{Host, HostId, Identity};

const MAX_RESULTS: usize = 8;
const WIDTH: f32 = 560.0;

/// Destino escrito a mano, sin guardar en la bóveda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdHocTarget {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// Acepta `servidor`, `usuario@servidor`, `servidor:2222`, `ssh usuario@servidor -p 2222`
/// y direcciones IPv6 entre corchetes (`[::1]:22`).
pub fn parse_target(input: &str) -> Option<AdHocTarget> {
    let mut words: Vec<&str> = input.split_whitespace().collect();
    if words.first() == Some(&"ssh") {
        words.remove(0);
    }
    let mut port_flag = None;
    if let Some(i) = words.iter().position(|w| *w == "-p") {
        port_flag = Some(words.get(i + 1)?.parse::<u16>().ok().filter(|p| *p > 0)?);
        words.drain(i..=i + 1);
    }
    let [target] = words.as_slice() else {
        return None;
    };
    let (user, rest) = match target.rsplit_once('@') {
        Some((user, rest)) if !user.is_empty() => (Some(user.to_string()), rest),
        Some(_) => return None,
        None => (None, *target),
    };
    let (host, port) = if let Some(stripped) = rest.strip_prefix('[') {
        let (host, after) = stripped.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
            None if after.is_empty() => None,
            None => return None,
        };
        (host.to_string(), port)
    } else {
        match rest.split_once(':') {
            Some((host, port)) => (
                host.to_string(),
                Some(port.parse::<u16>().ok().filter(|p| *p > 0)?),
            ),
            None => (rest.to_string(), None),
        }
    };
    let valid_host = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:".contains(c));
    valid_host.then(|| AdHocTarget {
        user,
        host,
        port: port_flag.or(port),
    })
}

#[derive(Default)]
pub struct QuickConnect {
    query: String,
    selected: usize,
    focused: bool,
}

impl QuickConnect {
    #[cfg(debug_assertions)]
    pub fn with_query(query: String) -> Self {
        Self {
            query,
            ..Self::default()
        }
    }
}

enum Choice {
    Host(HostId),
    AdHoc(AdHocTarget),
}

impl TunelApp {
    /// Conecta a un destino escrito a mano sin guardarlo en la bóveda.
    pub fn open_adhoc(&mut self, target: AdHocTarget) {
        let Some(data) = self.data().cloned() else {
            return;
        };
        let identity = target
            .user
            .as_ref()
            .map(|user| Identity::new(user.clone(), user.clone()));
        let host = Host {
            port: target.port,
            identity: identity.as_ref().map(|i| i.id),
            ..Host::new(target.host.clone(), target.host.clone())
        };
        let id = host.id;
        let ephemeral = match identity {
            Some(identity) => data.with_identity(identity),
            None => data,
        }
        .with_host(host);
        self.open_host_in(&ephemeral, id);
    }
}

pub fn show(app: &mut TunelApp, ctx: &egui::Context) {
    let Some(state) = app.quick_connect.as_mut() else {
        return;
    };
    let Some(data) = app.vault.as_ref().map(|v| &v.data) else {
        return;
    };
    let p = ui::theme::palette(ctx);

    let mut choices: Vec<(Choice, String, String)> = Vec::new();
    if let Some(target) = parse_target(&state.query)
        .filter(|t| t.user.is_some() || t.port.is_some() || t.host.contains('.'))
    {
        let label = format!(
            "Conectar a {}",
            state.query.trim().trim_start_matches("ssh ").trim()
        );
        choices.push((
            Choice::AdHoc(target),
            label,
            "Sin guardar en la bóveda".into(),
        ));
    }
    for host in data
        .search_hosts(&state.query)
        .into_iter()
        .take(MAX_RESULTS)
    {
        let user = data
            .resolve(host.id)
            .ok()
            .and_then(|r| r.identity)
            .map(|i| format!("{}@", i.username))
            .unwrap_or_default();
        choices.push((
            Choice::Host(host.id),
            host.display_name().to_string(),
            format!("{} · {user}{}", host.protocol().label(), host.address),
        ));
    }

    let (up, down, enter, escape) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::NONE, Key::ArrowUp),
            i.consume_key(egui::Modifiers::NONE, Key::ArrowDown),
            i.consume_key(egui::Modifiers::NONE, Key::Enter),
            i.consume_key(egui::Modifiers::NONE, Key::Escape),
        )
    });
    if down {
        state.selected = (state.selected + 1).min(choices.len().saturating_sub(1));
    }
    if up {
        state.selected = state.selected.saturating_sub(1);
    }
    state.selected = state.selected.min(choices.len().saturating_sub(1));

    let mut picked = enter
        .then_some(state.selected)
        .filter(|_| !choices.is_empty());
    let mut close = escape;
    let backdrop = egui::Modal::new(egui::Id::unique("conexion-rapida"))
        .area(
            egui::Modal::default_area(egui::Id::unique("conexion-rapida-area"))
                .anchor(Align2::CENTER_TOP, [0.0, 90.0]),
        )
        .show(ctx, |ui| {
            ui.set_width(WIDTH);
            let response = ui::search_box(
                ui,
                &mut state.query,
                "Buscar host o escribir usuario@servidor:puerto",
                WIDTH,
            );
            if !state.focused {
                response.request_focus();
                state.focused = true;
            }
            if response.changed() {
                state.selected = 0;
            }
            ui.add_space(6.0);
            if choices.is_empty() {
                ui.label(
                    RichText::new("Sin resultados. Prueba con usuario@servidor").color(p.muted),
                );
            }
            for (i, (choice, title, subtitle)) in choices.iter().enumerate() {
                let (rect, row) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 46.0), Sense::click());
                let active = i == state.selected || row.hovered();
                if active {
                    ui.painter()
                        .rect_filled(rect, CornerRadius::same(8), p.surface_hover);
                }
                let icon = match choice {
                    Choice::AdHoc(_) => icons::LIGHTNING,
                    Choice::Host(_) => icons::TERMINAL,
                };
                let avatar = egui::Rect::from_min_size(
                    rect.left_top() + Vec2::new(8.0, 7.0),
                    Vec2::splat(32.0),
                );
                ui::avatar(ui, avatar, icon, ui::theme::avatar_color(title));
                ui.painter().text(
                    rect.left_top() + Vec2::new(50.0, 8.0),
                    Align2::LEFT_TOP,
                    title,
                    egui::FontId::proportional(14.0),
                    p.text,
                );
                ui.painter().text(
                    rect.left_top() + Vec2::new(50.0, 26.0),
                    Align2::LEFT_TOP,
                    subtitle,
                    egui::FontId::proportional(12.0),
                    p.muted,
                );
                if i == state.selected {
                    ui.painter().text(
                        rect.right_center() - Vec2::new(12.0, 0.0),
                        Align2::RIGHT_CENTER,
                        "↵",
                        egui::FontId::proportional(14.0),
                        p.muted,
                    );
                }
                if row.clicked() {
                    picked = Some(i);
                }
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new("↑↓ para moverte · ↵ para conectar · Esc para cerrar")
                    .size(11.0)
                    .color(p.muted),
            );
        });
    close |= backdrop.should_close();

    if let Some(index) = picked {
        app.quick_connect = None;
        match choices.into_iter().nth(index).map(|(c, _, _)| c) {
            Some(Choice::Host(id)) => app.open_host(id),
            Some(Choice::AdHoc(target)) => app.open_adhoc(target),
            None => {}
        }
    } else if close {
        app.quick_connect = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(user: Option<&str>, host: &str, port: Option<u16>) -> Option<AdHocTarget> {
        Some(AdHocTarget {
            user: user.map(Into::into),
            host: host.into(),
            port,
        })
    }

    #[test]
    fn parses_common_forms() {
        assert_eq!(parse_target("db.local"), t(None, "db.local", None));
        assert_eq!(
            parse_target("ana@db.local"),
            t(Some("ana"), "db.local", None)
        );
        assert_eq!(
            parse_target("ana@db.local:2222"),
            t(Some("ana"), "db.local", Some(2222))
        );
        assert_eq!(
            parse_target("ssh ana@10.0.0.1 -p 2200"),
            t(Some("ana"), "10.0.0.1", Some(2200))
        );
        assert_eq!(
            parse_target("root@[::1]:22"),
            t(Some("root"), "::1", Some(22))
        );
    }

    #[test]
    fn rejects_invalid_input() {
        for bad in [
            "",
            "@host",
            "host:abc",
            "host:0",
            "dos palabras",
            "ana@ho st",
            "ssh -p",
            "h;rm -rf /",
        ] {
            assert_eq!(parse_target(bad), None, "{bad:?}");
        }
    }
}
