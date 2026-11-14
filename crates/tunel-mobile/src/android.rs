//! Lo que solo existe en Android: entregar al núcleo el contexto de la app para que HTTPS
//! compruebe los certificados con el almacén del sistema.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObject};

/// `dev.tunel.android.core.NativeInit.init(context)`: la app la llama una vez al arrancar,
/// antes de cualquier conexión. Llamarla otra vez no hace nada.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunel_android_core_NativeInit_init<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>()
}
