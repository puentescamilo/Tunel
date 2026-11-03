//! Dónde se ve cada pestaña: sola, en la vista dividida de la ventana principal (hasta
//! cuatro) o en una ventana propia, por ejemplo para llevarla a otra pantalla.

use crate::app::{Tab, TunelApp};
use crate::layout::{Direction, Layout};
use crate::ui;

/// Tamaño con el que se abre una ventana desacoplada.
const DETACHED_SIZE: [f32; 2] = [900.0, 600.0];

impl TunelApp {
    /// Si la pestaña activa está en la vista dividida, la vista; si no, `None`.
    pub fn shown_layout(&self) -> Option<&Layout> {
        let active = self.active?;
        self.layout.as_ref().filter(|l| l.contains(active))
    }

    /// Las pestañas que están a la vista: las de la ventana principal y las desacopladas.
    pub fn visible_tabs(&self) -> Vec<usize> {
        let main = match (self.shown_layout(), self.active) {
            (Some(layout), _) => layout.panes(),
            (None, Some(active)) => vec![active],
            (None, None) => Vec::new(),
        };
        main.into_iter()
            .chain(self.detached.iter().copied())
            .collect()
    }

    pub fn is_detached(&self, tab: usize) -> bool {
        self.detached.contains(&tab)
    }

    /// Se puede poner `tab` junto a lo que se ve ahora en la ventana principal.
    pub fn can_split_with(&self, tab: usize) -> bool {
        let Some(active) = self.active.filter(|a| *a != tab && !self.is_detached(*a)) else {
            return false;
        };
        let in_layout = self.layout.as_ref().is_some_and(|l| l.contains(tab));
        !in_layout && self.shown_layout().is_none_or(|l| !l.is_full()) && active < self.tabs.len()
    }

    /// Pone `tab` a la derecha o debajo del panel activo, y le da el foco.
    pub fn split_with(&mut self, tab: usize, direction: Direction) {
        if !self.can_split_with(tab) {
            return;
        }
        let Some(active) = self.active else {
            return;
        };
        let base = match self.layout.take() {
            Some(layout) if layout.contains(active) => layout,
            _ => Layout::Pane(active),
        };
        self.detached.retain(|t| *t != tab);
        self.layout = Some(base.split(active, tab, direction));
        self.focus_pane(tab);
    }

    /// Saca `tab` de la vista dividida; si queda un solo panel, deja de estar dividida.
    pub fn unsplit(&mut self, tab: usize) {
        let remaining = self.layout.take().and_then(|l| l.without(tab));
        let first = remaining.as_ref().map(|l| l.panes()[0]);
        self.layout = remaining.filter(|l| !matches!(l, Layout::Pane(_)));
        if self.active == Some(tab) {
            self.active = first.or(self.active);
        }
    }

    /// Abre `tab` en una ventana propia. En la principal queda su pestaña, para traerla.
    pub fn detach(&mut self, tab: usize) {
        if tab >= self.tabs.len() || self.is_detached(tab) {
            return;
        }
        let was_active = self.active == Some(tab);
        self.unsplit(tab);
        self.detached.push(tab);
        self.raise_window = Some(tab);
        if was_active {
            // Lo que estaba al lado, o la pestaña de antes que siga en esta ventana.
            self.active = self
                .shown_layout()
                .map(|l| l.panes()[0])
                .or_else(|| (0..self.tabs.len()).rev().find(|t| !self.is_detached(*t)));
        }
        self.wants_focus(tab);
    }

    /// Vuelve a traer `tab` a la ventana principal, como pestaña activa.
    pub fn attach(&mut self, tab: usize) {
        self.detached.retain(|t| *t != tab);
        if tab < self.tabs.len() {
            self.active = Some(tab);
            self.wants_focus(tab);
        }
    }

    /// Al elegir una pestaña desacoplada se trae al frente su ventana.
    pub fn bring_to_front(&self, ctx: &egui::Context, tab: usize) {
        if let Some(id) = self.viewport_id(tab) {
            ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Focus);
        }
    }

    /// Ajusta los paneles y las ventanas tras abrir o cerrar pestañas: `f` da el índice
    /// nuevo de cada pestaña, o `None` si ya no está.
    pub fn reindex(&mut self, f: impl Fn(usize) -> Option<usize>) {
        self.layout = self
            .layout
            .take()
            .and_then(|l| l.remap(&f))
            .filter(|l| !matches!(l, Layout::Pane(_)));
        self.detached = self.detached.iter().filter_map(|t| f(*t)).collect();
    }

    fn focus_pane(&mut self, tab: usize) {
        self.active = Some(tab);
        self.wants_focus(tab);
    }

    /// La terminal de `tab` toma el teclado en cuanto se dibuje, y ninguna otra lo pide.
    fn wants_focus(&mut self, tab: usize) {
        for (i, t) in self.tabs.iter_mut().enumerate() {
            if let Tab::Terminal(session) = t {
                session.wants_focus = i == tab;
            }
        }
    }

    fn viewport_id(&self, tab: usize) -> Option<egui::ViewportId> {
        let key = match self.tabs.get(tab)? {
            Tab::Terminal(session) => session.key,
            Tab::Sftp(sftp) => sftp.id,
            Tab::Pending(_) => return None,
        };
        Some(egui::ViewportId::from_hash_of(("pestaña", key)))
    }

    /// La vista dividida de la ventana principal, con franjas que se arrastran para
    /// repartir el espacio. El panel activo lleva un borde.
    pub fn show_layout(&mut self, ui: &mut egui::Ui) {
        let Some(layout) = self.shown_layout() else {
            return;
        };
        let p = ui::pal(ui);
        let area = ui.max_rect();
        let (panes, dividers) = layout.arrange(area);
        for (i, divider) in dividers.iter().enumerate() {
            let id = ui.scope_id().with(("divisor", i));
            let response = ui.interact(divider.rect, id, egui::Sense::drag());
            let cursor = match divider.direction {
                Direction::Right => egui::CursorIcon::ResizeHorizontal,
                Direction::Down => egui::CursorIcon::ResizeVertical,
            };
            let response = response.on_hover_cursor(cursor);
            let color = if response.hovered() || response.dragged() {
                p.accent
            } else {
                p.border
            };
            ui.painter().rect_filled(divider.rect, 0.0, color);
            if let (true, Some(pointer)) = (response.dragged(), response.interact_pointer_pos())
                && let Some(layout) = self.layout.as_mut()
            {
                layout.drag_divider(divider, pointer);
            }
        }
        let tabs = self.tabs.len();
        for (tab, rect) in panes {
            if tab >= self.tabs.len() {
                continue;
            }
            // Un clic en un panel lo hace el activo (atajos, snippets, «cerrar pestaña»).
            let pressed = ui.input(|i| i.pointer.any_pressed()) && ui.rect_contains_pointer(rect);
            if pressed {
                self.active = Some(tab);
            }
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(rect)
                    .id_salt(("panel", tab)),
            );
            child.set_clip_rect(rect);
            self.show_tab(&mut child, tab);
            if self.active == Some(tab) {
                ui.painter().rect_stroke(
                    rect,
                    0.0,
                    egui::Stroke::new(1.5, p.accent),
                    egui::StrokeKind::Inside,
                );
            }
            // Se cerró una pestaña desde su panel: los índices ya no valen hasta el próximo
            // fotograma.
            if self.tabs.len() != tabs {
                break;
            }
        }
    }

    /// Una ventana del sistema por cada pestaña desacoplada. Al cerrarla, la pestaña vuelve
    /// a la ventana principal sin desconectarse.
    pub fn show_detached(&mut self, ctx: &egui::Context) {
        let tabs = self.tabs.len();
        for tab in self.detached.clone() {
            let Some(id) = self.viewport_id(tab) else {
                continue;
            };
            let title = format!("{} — Túnel", self.tabs[tab].title());
            let builder = egui::ViewportBuilder::default()
                .with_title(title)
                .with_inner_size(DETACHED_SIZE)
                .with_min_inner_size([360.0, 240.0]);
            let closing = ctx.show_viewport_immediate(id, builder, |ui, class| {
                if class == egui::ViewportClass::EmbeddedWindow {
                    // Sin ventanas del sistema (pruebas): una ventana dentro de la principal.
                    ui.set_min_size(egui::vec2(DETACHED_SIZE[0] * 0.6, DETACHED_SIZE[1] * 0.6));
                    self.show_tab(ui, tab);
                    return false;
                }
                let frame = egui::Frame::central_panel(ui.style()).inner_margin(egui::Margin::ZERO);
                egui::CentralPanel::default()
                    .frame(frame)
                    .show(ui, |ui| self.show_tab(ui, tab));
                ui.input(|i| i.viewport().close_requested())
            });
            if self.tabs.len() != tabs {
                break;
            }
            // macOS da por tapada una ventana nueva hasta que pasa al frente, y mientras
            // tanto wgpu no pinta en ella: se queda en blanco.
            if self.raise_window == Some(tab) {
                self.raise_window = None;
                ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Focus);
            }
            if closing {
                self.attach(tab);
            }
        }
    }
}

/// Lo que ofrece el menú de una pestaña sobre dónde se ve.
pub fn place_menu(ui: &mut egui::Ui, app: &TunelApp, tab: usize) -> Option<Place> {
    use crate::ui::icons;
    let mut chosen = None;
    let mut item = |ui: &mut egui::Ui, icon: &str, label: &str, place: Place| {
        if ui.button(ui::with_icon(icon, label)).clicked() {
            chosen = Some(place);
            ui.close();
        }
    };
    if app.is_detached(tab) {
        item(
            ui,
            icons::ARROW_SQUARE_IN,
            "Volver a la ventana principal",
            Place::Attach,
        );
        return chosen;
    }
    if app.layout.as_ref().is_some_and(|l| l.contains(tab)) {
        item(
            ui,
            icons::X_SQUARE,
            "Quitar de la vista dividida",
            Place::Unsplit,
        );
    } else if app.can_split_with(tab) {
        item(
            ui,
            icons::SPLIT_RIGHT,
            "Dividir a la derecha",
            Place::Split(Direction::Right),
        );
        item(
            ui,
            icons::SPLIT_DOWN,
            "Dividir abajo",
            Place::Split(Direction::Down),
        );
    } else if app.shown_layout().is_some_and(Layout::is_full) {
        ui.add_enabled(
            false,
            egui::Button::new(ui::with_icon(icons::SPLIT_RIGHT, "Dividir (como mucho 4)")),
        );
    }
    item(
        ui,
        icons::ARROW_SQUARE_OUT,
        "Abrir en otra ventana",
        Place::Detach,
    );
    chosen
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Split(Direction),
    Unsplit,
    Detach,
    Attach,
}

pub fn apply(app: &mut TunelApp, tab: usize, place: Place) {
    match place {
        Place::Split(direction) => app.split_with(tab, direction),
        Place::Unsplit => app.unsplit(tab),
        Place::Detach => app.detach(tab),
        Place::Attach => app.attach(tab),
    }
}
