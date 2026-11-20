//! Windows: meter en su pantalla las ventanas de Túnel que cambiaron de escala.
//!
//! En cada fotograma se recorren las ventanas de este hilo (la principal y las terminales
//! desacopladas) y se anota su DPI. Si cambió, la ventana queda pendiente; en cuanto no se
//! está arrastrando ni está maximizada o minimizada, se ajusta al área útil de la pantalla
//! en la que quedó (sin la barra de tareas) con [`super::fitted_rect`].

use super::{ScreenRect, fitted_rect};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use windows::Win32::Foundation::{HWND, LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, GUI_INMOVESIZE, GUITHREADINFO, GetGUIThreadInfo, GetWindowRect, IsIconic,
    IsWindowVisible, IsZoomed, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPos,
};
use windows::core::BOOL;

/// Cada cuánto se vuelve a mirar mientras hay una ventana pendiente: al soltar el ratón
/// egui puede no pintar otro fotograma por su cuenta.
const RECHECK: Duration = Duration::from_millis(150);

#[derive(Default)]
struct Watch {
    /// DPI de cada ventana en el fotograma anterior, por su identificador.
    dpi: HashMap<isize, u32>,
    /// Ventanas que cambiaron de escala y aún no se han ajustado.
    pending: HashSet<isize>,
}

thread_local! {
    static WATCH: RefCell<Watch> = RefCell::new(Watch::default());
}

pub fn tick(ctx: &egui::Context) {
    let windows = thread_windows();
    let moving = moving_or_resizing();
    let waiting = WATCH.with(|watch| {
        let mut watch = watch.borrow_mut();
        let mut dpi = HashMap::with_capacity(windows.len());
        for &id in &windows {
            let hwnd = HWND(id as *mut _);
            // SAFETY: `hwnd` es una ventana de este hilo que acaba de enumerarse.
            let now = unsafe { GetDpiForWindow(hwnd) };
            if now != 0 && watch.dpi.get(&id).is_some_and(|&before| before != now) {
                watch.pending.insert(id);
            }
            dpi.insert(id, now);
        }
        watch.dpi = dpi;
        let open: HashSet<isize> = windows.iter().copied().collect();
        watch.pending.retain(|id| open.contains(id));
        if !moving {
            watch.pending.retain(|&id| !try_fit(HWND(id as *mut _)));
        }
        !watch.pending.is_empty()
    });
    if waiting {
        ctx.request_repaint_after(RECHECK);
    }
}

/// Ajusta la ventana si se puede ya. Devuelve `true` si ya no está pendiente.
fn try_fit(hwnd: HWND) -> bool {
    // SAFETY: llamadas de solo lectura sobre una ventana de este hilo.
    let (maximized, minimized) = unsafe { (IsZoomed(hwnd).as_bool(), IsIconic(hwnd).as_bool()) };
    if minimized {
        return false;
    }
    if maximized {
        // Maximizada ya ocupa su pantalla, la que diga Windows.
        return true;
    }
    let Some((window, work)) = window_and_work_area(hwnd) else {
        return true;
    };
    let Some(target) = fitted_rect(window, work) else {
        return true;
    };
    tracing::info!(
        ?window,
        ?target,
        "la ventana no cabe en su pantalla tras cambiar de escala"
    );
    // SAFETY: mueve y redimensiona una ventana propia, sin cambiar su orden ni activarla.
    let moved = unsafe {
        SetWindowPos(
            hwnd,
            None,
            target.left,
            target.top,
            target.width(),
            target.height(),
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    if let Err(e) = moved {
        tracing::warn!(error = %e, "no se pudo ajustar la ventana a su pantalla");
    }
    true
}

fn window_and_work_area(hwnd: HWND) -> Option<(ScreenRect, ScreenRect)> {
    let mut window = RECT::default();
    // SAFETY: `window` es un RECT válido donde escribir.
    unsafe { GetWindowRect(hwnd, &mut window) }.ok()?;
    // SAFETY: con MONITOR_DEFAULTTONEAREST siempre devuelve un monitor.
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` lleva su tamaño en `cbSize`, como pide la función.
    if !unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
        return None;
    }
    Some((screen_rect(window), screen_rect(info.rcWork)))
}

fn screen_rect(r: RECT) -> ScreenRect {
    ScreenRect {
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
    }
}

/// Se está arrastrando o cambiando de tamaño alguna ventana de este hilo: aún no se toca.
fn moving_or_resizing() -> bool {
    let mut info = GUITHREADINFO {
        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` lleva su tamaño en `cbSize`; el hilo es el actual.
    let ok = unsafe { GetGUIThreadInfo(GetCurrentThreadId(), &mut info) }.is_ok();
    ok && info.flags.contains(GUI_INMOVESIZE)
}

/// Las ventanas visibles de nivel superior de este hilo.
fn thread_windows() -> Vec<isize> {
    unsafe extern "system" fn collect(hwnd: HWND, found: LPARAM) -> BOOL {
        // SAFETY: `found` es el puntero al Vec que se pasa abajo, vivo durante la llamada.
        let found = unsafe { &mut *(found.0 as *mut Vec<isize>) };
        // SAFETY: `hwnd` lo da el sistema durante la enumeración.
        if unsafe { IsWindowVisible(hwnd) }.as_bool() {
            found.push(hwnd.0 as isize);
        }
        BOOL(1)
    }
    let mut found: Vec<isize> = Vec::new();
    // SAFETY: el callback solo escribe en `found`, que vive hasta que termina la enumeración.
    unsafe {
        let _ = EnumThreadWindows(
            GetCurrentThreadId(),
            Some(collect),
            LPARAM(&mut found as *mut Vec<isize> as isize),
        );
    }
    found
}
