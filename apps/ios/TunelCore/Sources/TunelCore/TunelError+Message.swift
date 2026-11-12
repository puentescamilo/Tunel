import Foundation

extension TunelError {
    /// El mensaje del núcleo, el mismo que en Android.
    public var message: String { errorMessage(error: self) }
}

/// Lo que se muestra al usuario para cualquier error que salga del núcleo.
func userMessage(for error: any Error) -> String {
    (error as? TunelError)?.message ?? error.localizedDescription
}
