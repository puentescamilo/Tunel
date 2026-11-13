//! El entorno de tokio que comparten la sincronización y las sesiones SSH.

use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// Tokio para la red. Las funciones que lo usan con `block_on` bloquean: la app las llama
/// fuera del hilo principal. Las sesiones SSH corren en él como tareas.
pub(crate) fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("no se pudo iniciar el entorno de red")
    })
}

/// Los mensajes del núcleo empiezan en minúscula; en la app se muestran como frase.
pub(crate) fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}
