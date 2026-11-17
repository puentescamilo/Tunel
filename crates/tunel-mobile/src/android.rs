//! Lo que solo existe en Android: entregar al núcleo el contexto de la app para que HTTPS
//! compruebe los certificados con el almacén del sistema, y llevar los pánicos al registro
//! del sistema (logcat), que es donde se ven en Android.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObject};
use std::ffi::{CString, c_char, c_int};
use std::sync::Once;

/// `dev.tunel.android.core.NativeInit.init(context)`: la app la llama una vez al arrancar,
/// antes de cualquier conexión. Llamarla otra vez no hace nada.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunel_android_core_NativeInit_init<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    log_panics();
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(priority: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

/// `ANDROID_LOG_ERROR` de `android/log.h`.
const LOG_ERROR: c_int = 6;

/// En Android, la salida de error del proceso se pierde: sin esto, un pánico en una tarea de
/// fondo (una conexión) no deja rastro y la app se queda esperando.
fn log_panics() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            write_log(&format!("pánico en el núcleo: {info}"));
            previous(info);
        }));
    });
}

fn write_log(text: &str) {
    let text = CString::new(text.replace('\0', " ")).unwrap_or_default();
    // SAFETY: `tag` y `text` son cadenas C válidas terminadas en NUL que viven durante toda
    // la llamada; `__android_log_write` no guarda los punteros.
    unsafe {
        __android_log_write(LOG_ERROR, c"tunel".as_ptr(), text.as_ptr());
    }
}
