//! Vista dividida: hasta cuatro pestañas a la vista a la vez, partidas a la derecha o abajo.
//! Cada hoja es el índice de una pestaña; al abrir o cerrar pestañas se renumera con
//! [`Layout::remap`].

use egui::{Rect, Vec2, pos2};

pub const MAX_PANES: usize = 4;
/// Ningún panel baja de esta fracción de su espacio al arrastrar el divisor.
const MIN_RATIO: f32 = 0.15;
/// Grosor de la franja entre dos paneles, que se arrastra para cambiar su tamaño.
pub const DIVIDER: f32 = 6.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Uno al lado del otro.
    Right,
    /// Uno encima del otro.
    Down,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Layout {
    Pane(usize),
    Split {
        direction: Direction,
        /// Fracción del espacio para `first`.
        ratio: f32,
        first: Box<Layout>,
        second: Box<Layout>,
    },
}

/// Franja entre los dos lados de una división. `path` lleva hasta ella desde la raíz
/// (`false` = primer hijo) y `area` es el espacio de toda la división.
#[derive(Debug, Clone, PartialEq)]
pub struct Divider {
    pub path: Vec<bool>,
    pub rect: Rect,
    pub area: Rect,
    pub direction: Direction,
}

impl Layout {
    /// Las pestañas a la vista, de izquierda a derecha y de arriba abajo.
    pub fn panes(&self) -> Vec<usize> {
        match self {
            Layout::Pane(tab) => vec![*tab],
            Layout::Split { first, second, .. } => {
                let mut panes = first.panes();
                panes.extend(second.panes());
                panes
            }
        }
    }

    pub fn contains(&self, tab: usize) -> bool {
        self.panes().contains(&tab)
    }

    pub fn is_full(&self) -> bool {
        self.panes().len() >= MAX_PANES
    }

    /// Pone `new` a la derecha o debajo de `target`, partiendo su espacio por la mitad.
    /// Sin cambios si `target` no está, si `new` ya está o si no caben más.
    pub fn split(self, target: usize, new: usize, direction: Direction) -> Layout {
        if !self.contains(target) || self.contains(new) || self.is_full() {
            return self;
        }
        self.split_pane(target, new, direction)
    }

    fn split_pane(self, target: usize, new: usize, direction: Direction) -> Layout {
        match self {
            Layout::Pane(tab) if tab == target => Layout::Split {
                direction,
                ratio: 0.5,
                first: Box::new(Layout::Pane(tab)),
                second: Box::new(Layout::Pane(new)),
            },
            Layout::Pane(_) => self,
            Layout::Split {
                direction: d,
                ratio,
                first,
                second,
            } => Layout::Split {
                direction: d,
                ratio,
                first: Box::new(first.split_pane(target, new, direction)),
                second: Box::new(second.split_pane(target, new, direction)),
            },
        }
    }

    /// Sin el panel de `tab`: el otro lado de su división ocupa el sitio.
    pub fn without(self, tab: usize) -> Option<Layout> {
        self.remap(&|t| (t != tab).then_some(t))
    }

    /// Cambia cada pestaña por `f(pestaña)`; las que dan `None` dejan de estar.
    /// `None` si no queda ninguna.
    pub fn remap(self, f: &impl Fn(usize) -> Option<usize>) -> Option<Layout> {
        match self {
            Layout::Pane(tab) => f(tab).map(Layout::Pane),
            Layout::Split {
                direction,
                ratio,
                first,
                second,
            } => match (first.remap(f), second.remap(f)) {
                (Some(first), Some(second)) => Some(Layout::Split {
                    direction,
                    ratio,
                    first: Box::new(first),
                    second: Box::new(second),
                }),
                (one, other) => one.or(other),
            },
        }
    }

    /// Dónde va cada panel dentro de `rect`, y las franjas que los separan.
    pub fn arrange(&self, rect: Rect) -> (Vec<(usize, Rect)>, Vec<Divider>) {
        let mut panes = Vec::new();
        let mut dividers = Vec::new();
        self.arrange_into(rect, &mut Vec::new(), &mut panes, &mut dividers);
        (panes, dividers)
    }

    fn arrange_into(
        &self,
        rect: Rect,
        path: &mut Vec<bool>,
        panes: &mut Vec<(usize, Rect)>,
        dividers: &mut Vec<Divider>,
    ) {
        let Layout::Split {
            direction,
            ratio,
            first,
            second,
        } = self
        else {
            if let Layout::Pane(tab) = self {
                panes.push((*tab, rect));
            }
            return;
        };
        let (a, divider, b) = cut(rect, *direction, *ratio);
        dividers.push(Divider {
            path: path.clone(),
            rect: divider,
            area: rect,
            direction: *direction,
        });
        path.push(false);
        first.arrange_into(a, path, panes, dividers);
        path.pop();
        path.push(true);
        second.arrange_into(b, path, panes, dividers);
        path.pop();
    }

    /// Mueve la división de `path` para que su franja quede en `pointer`.
    pub fn drag_divider(&mut self, divider: &Divider, pointer: egui::Pos2) {
        let area = divider.area;
        let ratio = match divider.direction {
            Direction::Right => (pointer.x - area.left()) / area.width(),
            Direction::Down => (pointer.y - area.top()) / area.height(),
        };
        if let Some(Layout::Split { ratio: r, .. }) = self.at_mut(&divider.path) {
            *r = ratio.clamp(MIN_RATIO, 1.0 - MIN_RATIO);
        }
    }

    fn at_mut(&mut self, path: &[bool]) -> Option<&mut Layout> {
        let Some((&second, rest)) = path.split_first() else {
            return Some(self);
        };
        match self {
            Layout::Split {
                first, second: s, ..
            } => if second { s } else { first }.at_mut(rest),
            Layout::Pane(_) => None,
        }
    }
}

/// Parte `rect` en (primer lado, franja, segundo lado).
fn cut(rect: Rect, direction: Direction, ratio: f32) -> (Rect, Rect, Rect) {
    match direction {
        Direction::Right => {
            let x = rect.left() + (rect.width() - DIVIDER) * ratio;
            (
                Rect::from_min_max(rect.min, pos2(x, rect.bottom())),
                Rect::from_min_size(pos2(x, rect.top()), Vec2::new(DIVIDER, rect.height())),
                Rect::from_min_max(pos2(x + DIVIDER, rect.top()), rect.max),
            )
        }
        Direction::Down => {
            let y = rect.top() + (rect.height() - DIVIDER) * ratio;
            (
                Rect::from_min_max(rect.min, pos2(rect.right(), y)),
                Rect::from_min_size(pos2(rect.left(), y), Vec2::new(rect.width(), DIVIDER)),
                Rect::from_min_max(pos2(rect.left(), y + DIVIDER), rect.max),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn four() -> Layout {
        Layout::Pane(0)
            .split(0, 1, Direction::Right)
            .split(0, 2, Direction::Down)
            .split(1, 3, Direction::Down)
    }

    #[test]
    fn splitting_places_the_new_tab_next_to_its_target() {
        let layout = Layout::Pane(0).split(0, 1, Direction::Right);
        assert_eq!(layout.panes(), [0, 1]);
        let layout = layout.split(0, 2, Direction::Down);
        // El 2 queda debajo del 0, a la izquierda del 1.
        assert_eq!(layout.panes(), [0, 2, 1]);
    }

    #[test]
    fn no_more_than_four_panes_and_no_repeats() {
        let layout = four();
        assert_eq!(layout.panes().len(), MAX_PANES);
        assert!(layout.is_full());
        assert_eq!(layout.clone().split(0, 4, Direction::Right), layout);
        let two = Layout::Pane(0).split(0, 1, Direction::Right);
        assert_eq!(two.clone().split(0, 1, Direction::Down), two);
        // Un destino que no está no cambia nada.
        assert_eq!(two.clone().split(7, 2, Direction::Down), two);
    }

    #[test]
    fn removing_a_pane_gives_its_space_to_its_neighbour() {
        let layout = four().without(2).unwrap();
        assert_eq!(layout.panes(), [0, 1, 3]);
        let layout = layout.without(1).unwrap().without(3).unwrap();
        assert_eq!(layout, Layout::Pane(0));
        assert_eq!(layout.without(0), None);
    }

    #[test]
    fn closing_a_tab_renumbers_the_panes_after_it() {
        // Se cierra la pestaña 1: la 2 pasa a ser la 1 y la 3 la 2.
        let closed = 1;
        let layout = four()
            .remap(&|t| match t {
                t if t == closed => None,
                t if t > closed => Some(t - 1),
                t => Some(t),
            })
            .unwrap();
        assert_eq!(layout.panes(), [0, 1, 2]);
    }

    #[test]
    fn panes_fill_the_space_without_overlapping() {
        let rect = Rect::from_min_size(pos2(0.0, 0.0), Vec2::new(1006.0, 606.0));
        let (panes, dividers) = four().arrange(rect);
        assert_eq!(panes.len(), 4);
        assert_eq!(dividers.len(), 3);
        for (i, (_, a)) in panes.iter().enumerate() {
            assert!(rect.contains_rect(*a));
            for (_, b) in &panes[i + 1..] {
                assert!(
                    !a.intersects(*b) || a.intersect(*b).area() == 0.0,
                    "{a:?} {b:?}"
                );
            }
        }
        let area: f32 = panes.iter().map(|(_, r)| r.area()).sum::<f32>()
            + dividers.iter().map(|d| d.rect.area()).sum::<f32>();
        assert!((area - rect.area()).abs() < 1.0, "{area}");
    }

    #[test]
    fn dragging_a_divider_resizes_but_keeps_both_sides_visible() {
        let rect = Rect::from_min_size(pos2(0.0, 0.0), Vec2::new(1006.0, 600.0));
        let mut layout = Layout::Pane(0).split(0, 1, Direction::Right);
        let (_, dividers) = layout.arrange(rect);
        layout.drag_divider(&dividers[0], pos2(250.0, 300.0));
        let (panes, _) = layout.arrange(rect);
        assert!((panes[0].1.width() - 250.0).abs() < 2.0, "{:?}", panes[0].1);
        // Hasta el borde no: el panel se queda con un mínimo.
        layout.drag_divider(&dividers[0], pos2(1000.0, 300.0));
        let (panes, _) = layout.arrange(rect);
        assert!(panes[1].1.width() > 100.0, "{:?}", panes[1].1);
    }
}
