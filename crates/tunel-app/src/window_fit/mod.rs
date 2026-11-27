//! Que la ventana quepa en la pantalla a la que se lleva.
//!
//! Al pasar una ventana a una pantalla con otra escala, Windows propone un tamaño que cabe en
//! ella, pero winit lo descarta y conserva el tamaño lógico: una ventana grande del monitor al
//! 100 % llega al portátil al 150 % más grande que la pantalla. Y como sigue montada sobre la
//! pantalla de antes, el doble clic en la barra de título la maximiza en esa otra.
//!
//! Aquí, cuando cambia la escala de una ventana, se encoge si no cabe en su pantalla.
//!
//! En Windows eso no bastaba (0.14.0 y 0.16.1). Mientras se arrastra, la escala rebota entre
//! las dos pantallas y la ventana salta de sitio ([`dpi_move`]); el ajuste contaba como fuera
//! de la pantalla el borde invisible que Windows deja alrededor de la ventana; y deshacía el
//! acople a media pantalla. Allí se hace con las funciones del sistema ([`native`]): los
//! cambios de escala se aplican una sola vez, al soltar la ventana, y entonces se mete la
//! parte visible de la ventana en el área útil de su pantalla.

#[cfg_attr(not(windows), allow(dead_code))]
mod dpi_move;
#[cfg(windows)]
mod native;

/// La parte de la pantalla que puede ocupar: egui no da el área sin la barra de tareas.
const MONITOR_SHARE: f32 = 0.9;

/// El tamaño al que hay que llevar la ventana, o `None` si no hay que tocarla. Todo en puntos.
///
/// Solo actúa cuando la escala cambia, para no impedir que alguien abarque dos pantallas a
/// propósito; y nunca con la ventana maximizada o a pantalla completa, que ya ocupan la suya.
pub fn fitted_size(
    previous_scale: Option<f32>,
    scale: f32,
    inner: egui::Vec2,
    monitor: egui::Vec2,
    maximized: bool,
) -> Option<egui::Vec2> {
    let scale_changed = previous_scale.is_some_and(|previous| previous != scale);
    if !scale_changed || maximized {
        return None;
    }
    let max = monitor * MONITOR_SHARE;
    (inner.x > max.x || inner.y > max.y).then(|| inner.min(max))
}

/// Un rectángulo de la pantalla en píxeles, como los de Windows: `right` y `bottom` quedan
/// fuera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct ScreenRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl ScreenRect {
    pub fn width(&self) -> i32 {
        self.right - self.left
    }

    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }
}

/// Dónde poner la ventana `window` para que quepa entera en `work`, el área útil de su
/// pantalla; `None` si ya cabe. Si es más grande, se encoge a la parte [`MONITOR_SHARE`] de
/// la pantalla; después se mueve lo justo para que no se salga por ningún lado.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn fitted_rect(window: ScreenRect, work: ScreenRect) -> Option<ScreenRect> {
    let inside = window.left >= work.left
        && window.top >= work.top
        && window.right <= work.right
        && window.bottom <= work.bottom;
    if inside || work.width() <= 0 || work.height() <= 0 {
        return None;
    }
    let side = |size: i32, available: i32| {
        if size > available {
            (available as f32 * MONITOR_SHARE) as i32
        } else {
            size
        }
    };
    let width = side(window.width(), work.width());
    let height = side(window.height(), work.height());
    let left = window.left.clamp(work.left, work.right - width);
    let top = window.top.clamp(work.top, work.bottom - height);
    Some(ScreenRect {
        left,
        top,
        right: left + width,
        bottom: top + height,
    })
}

/// Como [`fitted_rect`], pero mirando solo la parte visible de la ventana, `frame`. En
/// Windows 10 y 11 la ventana tiene alrededor un borde invisible de unos píxeles, para poder
/// agarrarla; una ventana acoplada a media pantalla lo tiene fuera de ella y aun así cabe.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn fitted_window(
    window: ScreenRect,
    frame: ScreenRect,
    work: ScreenRect,
) -> Option<ScreenRect> {
    let target = fitted_rect(frame, work)?;
    Some(ScreenRect {
        left: target.left - (frame.left - window.left),
        top: target.top - (frame.top - window.top),
        right: target.right + (window.right - frame.right),
        bottom: target.bottom + (window.bottom - frame.bottom),
    })
}

/// Ajusta las ventanas que acaban de cambiar de escala para que quepan en su pantalla. Se
/// llama en cada fotograma desde cada ventana: la principal y las desacopladas.
pub fn tick(ctx: &egui::Context) {
    #[cfg(windows)]
    native::tick(ctx);
    #[cfg(not(windows))]
    fit_with_egui(ctx);
}

/// Encoge la ventana del `ctx` actual si acaba de cambiar de escala y no cabe en su pantalla.
#[cfg_attr(windows, allow(dead_code))]
fn fit_with_egui(ctx: &egui::Context) {
    let (scale, inner, monitor, maximized) = ctx.input(|i| {
        let viewport = i.viewport();
        (
            viewport.native_pixels_per_point,
            viewport.inner_rect.map(|r| r.size()),
            viewport.monitor_size,
            viewport.maximized.unwrap_or(false) || viewport.fullscreen.unwrap_or(false),
        )
    });
    let Some(scale) = scale else { return };
    let key = egui::Id::unique("tunel-escala-de-la-ventana").with(ctx.viewport_id());
    let previous = ctx.data_mut(|d| {
        let previous = d.get_temp::<f32>(key);
        d.insert_temp(key, scale);
        previous
    });
    let (Some(inner), Some(monitor)) = (inner, monitor) else {
        return;
    };
    if let Some(size) = fitted_size(previous, scale, inner, monitor, maximized) {
        tracing::info!("la ventana no cabe en su pantalla tras cambiar de escala: {size:?}");
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::vec2;

    /// Un monitor de 1920 × 1080 a la derecha del portátil, con la barra de tareas abajo.
    const MONITOR: ScreenRect = ScreenRect {
        left: 1920,
        top: 0,
        right: 3840,
        bottom: 1032,
    };

    fn rect(left: i32, top: i32, width: i32, height: i32) -> ScreenRect {
        ScreenRect {
            left,
            top,
            right: left + width,
            bottom: top + height,
        }
    }

    #[test]
    fn a_window_inside_its_screen_is_left_alone() {
        assert_eq!(fitted_rect(rect(2000, 100, 1200, 800), MONITOR), None);
    }

    #[test]
    fn a_window_bigger_than_the_screen_shrinks_and_moves_inside() {
        // Como en el vídeo: la ventana maximizada del portátil de 2880 × 1800 llega con su
        // tamaño en píxeles y abarca dos monitores.
        let fitted = fitted_rect(rect(1500, -20, 2880, 1800), MONITOR).unwrap();
        assert_eq!(fitted, rect(1920, 0, 1728, 928));
    }

    #[test]
    fn a_window_that_sticks_out_is_moved_without_resizing() {
        let fitted = fitted_rect(rect(3000, 600, 1200, 800), MONITOR).unwrap();
        assert_eq!(fitted, rect(2640, 232, 1200, 800));
    }

    #[test]
    fn only_the_side_that_does_not_fit_shrinks() {
        let fitted = fitted_rect(rect(2000, 0, 1000, 1500), MONITOR).unwrap();
        assert_eq!(fitted, rect(2000, 0, 1000, 928));
    }

    /// El borde invisible de Windows: 7 píxeles a los lados y abajo, ninguno arriba.
    fn with_border(frame: ScreenRect) -> ScreenRect {
        ScreenRect {
            left: frame.left - 7,
            top: frame.top,
            right: frame.right + 7,
            bottom: frame.bottom + 7,
        }
    }

    #[test]
    fn a_window_snapped_to_half_the_screen_fits_despite_its_invisible_border() {
        // Del registro: acoplada a la mitad izquierda del monitor, la 0.16.1 la encogía.
        let work = rect(0, 0, 1920, 1032);
        let frame = rect(0, 0, 960, 1032);
        assert_eq!(fitted_window(with_border(frame), frame, work), None);
    }

    #[test]
    fn the_visible_part_of_a_window_too_big_is_what_fits_in_the_screen() {
        // Del registro: la ventana llega al portátil al 150 % más alta que su pantalla.
        let laptop = ScreenRect {
            left: 1920,
            top: -118,
            right: 3840,
            bottom: 1010,
        };
        let frame = rect(2383, -118, 1451, 1513);
        let fitted = fitted_window(with_border(frame), frame, laptop).unwrap();
        assert_eq!(fitted, with_border(rect(2383, -118, 1451, 1015)));
    }

    const LAPTOP: egui::Vec2 = egui::Vec2::new(1280.0, 720.0);

    #[test]
    fn shrinks_a_window_that_no_longer_fits_after_a_scale_change() {
        let size = fitted_size(Some(1.0), 1.5, vec2(1800.0, 1000.0), LAPTOP, false);
        assert_eq!(size, Some(vec2(1152.0, 648.0)));
    }

    #[test]
    fn shrinks_only_the_side_that_does_not_fit() {
        let size = fitted_size(Some(1.0), 1.5, vec2(900.0, 1000.0), LAPTOP, false);
        assert_eq!(size, Some(vec2(900.0, 648.0)));
    }

    #[test]
    fn leaves_a_window_that_fits() {
        assert_eq!(
            fitted_size(Some(1.0), 1.5, vec2(1000.0, 600.0), LAPTOP, false),
            None
        );
    }

    #[test]
    fn leaves_the_window_alone_when_the_scale_does_not_change() {
        // Quien estira la ventana sobre dos pantallas con la misma escala lo hace a propósito.
        assert_eq!(
            fitted_size(Some(1.5), 1.5, vec2(3000.0, 1000.0), LAPTOP, false),
            None
        );
    }

    #[test]
    fn leaves_the_window_alone_on_the_first_frame() {
        // Al abrir, eframe ya la ajusta a la pantalla.
        assert_eq!(
            fitted_size(None, 1.5, vec2(3000.0, 1000.0), LAPTOP, false),
            None
        );
    }

    #[test]
    fn leaves_a_maximized_window_alone() {
        assert_eq!(
            fitted_size(Some(1.0), 1.5, vec2(3000.0, 1000.0), LAPTOP, true),
            None
        );
    }
}
