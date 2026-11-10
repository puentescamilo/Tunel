//! Que la ventana quepa en la pantalla a la que se lleva.
//!
//! Al pasar una ventana a una pantalla con otra escala, Windows propone un tamaño que cabe en
//! ella, pero winit lo descarta y conserva el tamaño lógico: una ventana grande del monitor al
//! 100 % llega al portátil al 150 % más grande que la pantalla. Y como sigue montada sobre la
//! pantalla de antes, el doble clic en la barra de título la maximiza en esa otra.
//!
//! Aquí, cuando cambia la escala de una ventana, se encoge si no cabe en su pantalla.

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

/// Encoge la ventana del `ctx` actual si acaba de cambiar de escala y no cabe en su pantalla.
/// Se llama en cada fotograma desde cada ventana: la principal y las desacopladas.
pub fn tick(ctx: &egui::Context) {
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
