//! Windows: las ventanas de Túnel cambian de escala al soltarlas y caben en su pantalla.
//!
//! Cada ventana de este hilo (la principal y las terminales desacopladas) se subclasifica: su
//! procedimiento pasa antes por [`window_proc`], que ve los mensajes de arrastre y de cambio
//! de escala antes que winit. Mientras se arrastra, los cambios de escala se guardan
//! ([`super::dpi_move`]); al soltar, se aplica la escala de la pantalla donde quedó y la parte
//! visible de la ventana se mete en su área útil con [`super::fitted_window`]. Una ventana
//! acoplada a media pantalla conserva el sitio que le dio Windows.

use super::ScreenRect;
use super::dpi_move::{Message, MoveState, Reaction, react};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_EXTENDED_FRAME_BOUNDS, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, HMONITOR, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, GetDpiForWindow, MDT_EFFECTIVE_DPI};
use windows::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, DefWindowProcW, EnumThreadWindows, GWLP_WNDPROC, GetClassNameW, GetWindowRect,
    IsIconic, IsWindowVisible, IsZoomed, PostMessageW, RegisterWindowMessageW, SWP_NOACTIVATE,
    SWP_NOZORDER, SetWindowLongPtrW, SetWindowPos, WM_DPICHANGED, WM_ENTERSIZEMOVE,
    WM_EXITSIZEMOVE, WM_NCDESTROY, WNDPROC,
};
use windows::core::{BOOL, s, w};

/// Una ventana subclasificada: su procedimiento de antes (el de winit) y su estado.
#[derive(Clone, Copy)]
struct Hooked {
    original: isize,
    state: MoveState,
}

thread_local! {
    static HOOKED: RefCell<HashMap<isize, Hooked>> = RefCell::new(HashMap::new());
    static REFIT: Cell<u32> = const { Cell::new(0) };
}

/// Subclasifica las ventanas de este hilo que aún no lo están. Se llama en cada fotograma
/// desde cada ventana, así que también alcanza a las desacopladas al abrirse.
pub fn tick(_ctx: &egui::Context) {
    for id in thread_windows() {
        let known = HOOKED
            .try_with(|hooked| hooked.try_borrow().is_ok_and(|h| h.contains_key(&id)))
            .unwrap_or(true);
        if !known {
            hook(HWND(id as *mut _));
        }
    }
}

fn hook(hwnd: HWND) {
    // SAFETY: `hwnd` es una ventana de este hilo; `window_proc` cumple la firma de WNDPROC y
    // llama al procedimiento anterior, que se guarda aquí mismo antes de que llegue ningún
    // mensaje (cambiar GWLP_WNDPROC no envía mensajes a la ventana).
    let original =
        unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, window_proc as *const () as isize) };
    if original == 0 {
        tracing::warn!("no se pudo vigilar la escala de la ventana");
        return;
    }
    let hooked = Hooked {
        original,
        state: MoveState::default(),
    };
    let _ = HOOKED.try_with(|h| {
        h.try_borrow_mut()
            .map(|mut hooked_windows| hooked_windows.insert(hwnd.0 as isize, hooked))
    });
}

fn lookup(id: isize) -> Option<Hooked> {
    HOOKED
        .try_with(|h| h.try_borrow().ok()?.get(&id).copied())
        .ok()
        .flatten()
}

fn remember(id: isize, state: MoveState) {
    let _ = HOOKED.try_with(|h| {
        if let Ok(mut hooked) = h.try_borrow_mut()
            && let Some(entry) = hooked.get_mut(&id)
        {
            entry.state = state;
        }
    });
}

fn forget(id: isize) {
    let _ = HOOKED.try_with(|h| h.try_borrow_mut().map(|mut hooked| hooked.remove(&id)));
}

/// El mensaje con el que una ventana se pide a sí misma aplicar la escala pendiente.
fn refit_message() -> u32 {
    REFIT.with(|refit| {
        if refit.get() == 0 {
            // SAFETY: la cadena es un literal terminado en cero.
            refit.set(unsafe { RegisterWindowMessageW(w!("Tunel.EscalaAlSoltarLaVentana")) });
        }
        refit.get()
    })
}

fn classify(msg: u32) -> Option<Message> {
    match msg {
        WM_ENTERSIZEMOVE => Some(Message::EnterMove),
        WM_EXITSIZEMOVE => Some(Message::ExitMove),
        WM_DPICHANGED => Some(Message::DpiChanged),
        m if m != 0 && m == refit_message() => Some(Message::Refit),
        _ => None,
    }
}

/// El procedimiento de las ventanas subclasificadas. No toma prestado el estado mientras
/// llama a winit, que puede volver a entrar aquí o en [`tick`].
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let id = hwnd.0 as isize;
    let Some(hooked) = lookup(id) else {
        // SAFETY: el procedimiento por defecto acepta cualquier mensaje.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    };
    // SAFETY: `original` es el WNDPROC que devolvió SetWindowLongPtrW: no nulo y de la firma
    // de un procedimiento de ventana.
    let original: WNDPROC = unsafe { std::mem::transmute::<isize, WNDPROC>(hooked.original) };
    // SAFETY: se pasa a winit el mismo mensaje que llegó, con sus parámetros.
    let forward = || unsafe { CallWindowProcW(original, hwnd, msg, wparam, lparam) };
    if msg == WM_NCDESTROY {
        forget(id);
        return forward();
    }
    let Some(message) = classify(msg) else {
        return forward();
    };
    let (state, reaction) = react(hooked.state, message);
    remember(id, state);
    match reaction {
        Reaction::Forward => forward(),
        Reaction::Hold => LRESULT(0),
        Reaction::ForwardThenRefit => {
            let result = forward();
            // SAFETY: se envía a una ventana propia un mensaje registrado sin parámetros.
            if let Err(e) =
                unsafe { PostMessageW(Some(hwnd), refit_message(), WPARAM(0), LPARAM(0)) }
            {
                tracing::warn!(error = %e, "no se pudo aplicar la escala al soltar la ventana");
            }
            result
        }
        Reaction::ApplyScale => settle(hwnd, forward),
        Reaction::ApplyPendingScale => {
            settle(hwnd, || apply_monitor_scale(hwnd, original));
            LRESULT(0)
        }
    }
}

/// Avisa a winit de la escala de la pantalla donde quedó la ventana. Windows a veces no la
/// actualiza al acoplarla a media pantalla, así que se toma del monitor y no de la ventana.
fn apply_monitor_scale(hwnd: HWND, original: WNDPROC) -> LRESULT {
    let Some(before) = window_rect(hwnd) else {
        return LRESULT(0);
    };
    let dpi = monitor_dpi(hwnd).unwrap_or_else(|| {
        // SAFETY: lectura sobre una ventana propia.
        unsafe { GetDpiForWindow(hwnd) }
    });
    if dpi == 0 {
        return LRESULT(0);
    }
    let mut suggested = RECT {
        left: before.left,
        top: before.top,
        right: before.right,
        bottom: before.bottom,
    };
    let both = WPARAM(((dpi << 16) | dpi) as usize);
    // SAFETY: WM_DPICHANGED lleva el DPI en las dos mitades de `wparam` y en `lparam` un RECT
    // que vive durante la llamada. Si winit ya tiene esa escala, no hace nada.
    unsafe {
        CallWindowProcW(
            original,
            hwnd,
            WM_DPICHANGED,
            both,
            LPARAM(&mut suggested as *mut RECT as isize),
        )
    }
}

/// Deja que winit aplique la escala con `apply` y luego coloca la ventana: la acoplada vuelve
/// al sitio que le dio Windows y las demás se meten en su pantalla, la de antes de que winit
/// la agrandara.
fn settle(hwnd: HWND, apply: impl FnOnce() -> LRESULT) -> LRESULT {
    let before = window_rect(hwnd);
    // SAFETY: con MONITOR_DEFAULTTONEAREST siempre devuelve un monitor.
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    let arranged = is_arranged(hwnd);
    let result = apply();
    // SAFETY: lecturas sobre una ventana propia.
    let (maximized, minimized) = unsafe { (IsZoomed(hwnd).as_bool(), IsIconic(hwnd).as_bool()) };
    if maximized || minimized {
        return result;
    }
    let target = if arranged {
        before.filter(|&b| window_rect(hwnd) != Some(b))
    } else {
        fitted(hwnd, monitor)
    };
    if let Some(target) = target {
        move_window(hwnd, target);
    }
    result
}

fn fitted(hwnd: HWND, monitor: HMONITOR) -> Option<ScreenRect> {
    let window = window_rect(hwnd)?;
    let frame = visible_rect(hwnd)
        .filter(|&frame| is_border_of(window, frame))
        .unwrap_or(window);
    let work = work_area(monitor)?;
    let target = super::fitted_window(window, frame, work)?;
    tracing::info!(
        ?window,
        ?target,
        "la ventana no cabe en su pantalla tras cambiar de escala"
    );
    Some(target)
}

fn move_window(hwnd: HWND, target: ScreenRect) {
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
}

fn window_rect(hwnd: HWND) -> Option<ScreenRect> {
    let mut rect = RECT::default();
    // SAFETY: `rect` es un RECT válido donde escribir.
    unsafe { GetWindowRect(hwnd, &mut rect) }.ok()?;
    Some(screen_rect(rect))
}

/// La parte visible de la ventana, sin el borde invisible que Windows deja para agarrarla.
fn visible_rect(hwnd: HWND) -> Option<ScreenRect> {
    let mut rect = RECT::default();
    // SAFETY: se pide un RECT y se da el tamaño de un RECT.
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut rect as *mut RECT as *mut _,
            std::mem::size_of::<RECT>() as u32,
        )
    }
    .ok()?;
    Some(screen_rect(rect))
}

/// Si `frame` es `window` sin un borde fino: si DWM diera otra cosa, se usa la ventana entera.
fn is_border_of(window: ScreenRect, frame: ScreenRect) -> bool {
    const MAX_BORDER: i32 = 32;
    [
        frame.left - window.left,
        frame.top - window.top,
        window.right - frame.right,
        window.bottom - frame.bottom,
    ]
    .iter()
    .all(|side| (0..=MAX_BORDER).contains(side))
}

fn work_area(monitor: HMONITOR) -> Option<ScreenRect> {
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` lleva su tamaño en `cbSize`, como pide la función.
    unsafe { GetMonitorInfoW(monitor, &mut info) }
        .as_bool()
        .then(|| screen_rect(info.rcWork))
}

fn monitor_dpi(hwnd: HWND) -> Option<u32> {
    let (mut x, mut y) = (0, 0);
    // SAFETY: con MONITOR_DEFAULTTONEAREST siempre devuelve un monitor; `x` e `y` son
    // enteros donde escribir.
    unsafe {
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y)
    }
    .ok()?;
    (x != 0).then_some(x)
}

/// Si Windows la acopló a media pantalla o a una de sus distribuciones. `IsWindowArranged`
/// no existe en todas las versiones de Windows 10, así que se busca al usarla.
fn is_arranged(hwnd: HWND) -> bool {
    type IsWindowArranged = unsafe extern "system" fn(HWND) -> BOOL;
    // SAFETY: user32 ya está cargada en cualquier proceso con ventanas; si la función existe,
    // tiene la firma documentada.
    unsafe {
        let Ok(user32) = GetModuleHandleW(w!("user32.dll")) else {
            return false;
        };
        let Some(function) = GetProcAddress(user32, s!("IsWindowArranged")) else {
            return false;
        };
        let function: IsWindowArranged = std::mem::transmute(function);
        function(hwnd).as_bool()
    }
}

fn screen_rect(r: RECT) -> ScreenRect {
    ScreenRect {
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
    }
}

/// La clase con la que winit crea sus ventanas. Solo se tocan esas: no los diálogos del
/// sistema ni las ventanas del método de entrada, que también son de este hilo.
const WINIT_CLASS: &str = "Window Class";

/// Las ventanas visibles de nivel superior de este hilo creadas por winit.
fn thread_windows() -> Vec<isize> {
    unsafe extern "system" fn collect(hwnd: HWND, found: LPARAM) -> BOOL {
        // SAFETY: `found` es el puntero al Vec que se pasa abajo, vivo durante la llamada.
        let found = unsafe { &mut *(found.0 as *mut Vec<isize>) };
        // SAFETY: `hwnd` lo da el sistema durante la enumeración.
        if unsafe { IsWindowVisible(hwnd) }.as_bool() && is_winit_window(hwnd) {
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

fn is_winit_window(hwnd: HWND) -> bool {
    let mut name = [0u16; 64];
    // SAFETY: `name` es un búfer donde escribir; la función no pasa de su longitud.
    let len = unsafe { GetClassNameW(hwnd, &mut name) };
    usize::try_from(len).is_ok_and(|len| String::from_utf16_lossy(&name[..len]) == WINIT_CLASS)
}
