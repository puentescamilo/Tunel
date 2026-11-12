import Foundation

/// Cómo fue la última sincronización, para mostrarlo bajo la lista.
public enum SyncStatus: Equatable, Sendable {
    case idle
    case syncing
    case synced(at: Date, problems: [String], invitations: UInt32)
    case failed(String)
}

/// Unirse a la cuenta de Túnel y descargar lo sincronizado. Todo lo que habla con el
/// servidor corre fuera del hilo principal.
extension VaultStore {
    /// Cómo se puede entrar en `server`: proveedores y si admite contraseña.
    public func signInOptions(server: String) async throws -> SignInOptions {
        try await Self.background { try TunelCore.signInOptions(server: server) }
    }

    public func signIn(server: String, email: String, password: String) async throws {
        let vault = try openVault()
        try await Self.background {
            try vault.signInWithPassword(server: server, email: email, password: password)
        }
        await afterSignIn()
    }

    /// Empieza a entrar con un proveedor; la app abre `url()` en el navegador del sistema.
    public func beginProviderSignIn(server: String, providerId: String) async throws
        -> ProviderSignIn
    {
        try await Self.background { try ProviderSignIn.begin(server: server, providerId: providerId) }
    }

    /// El navegador volvió: canjea el código y devuelve el correo de la cuenta.
    public func providerReturned(_ signIn: ProviderSignIn, callback: URL) async throws -> String {
        let callback = callback.absoluteString
        return try await Self.background { try signIn.returned(callback: callback) }
    }

    /// Termina de entrar con un proveedor con la contraseña maestra de la cuenta. Si no es
    /// la correcta, se puede volver a intentar con el mismo `signIn`.
    public func finishProviderSignIn(_ signIn: ProviderSignIn, masterPassword: String) async throws {
        let vault = try openVault()
        try await Self.background {
            try vault.signInWithProvider(signIn: signIn, masterPassword: masterPassword)
        }
        await afterSignIn()
    }

    /// Descarga lo nuevo. Los errores se quedan en `syncStatus`: la lista sigue con lo que
    /// había.
    public func sync() async {
        guard let vault, account != nil, syncStatus != .syncing else { return }
        syncStatus = .syncing
        do {
            let report = try await Self.background { try vault.sync() }
            reload()
            syncStatus = .synced(
                at: Date(), problems: report.teamProblems, invitations: report.invitations)
        } catch {
            syncStatus = .failed(userMessage(for: error))
        }
    }

    /// Desvincula el dispositivo; lo descargado se borra.
    public func signOut() async throws {
        let vault = try openVault()
        try await Self.background { try vault.signOut() }
        syncStatus = .idle
        reload()
    }

    private func afterSignIn() async {
        reload()
        await sync()
    }

    private func openVault() throws -> Vault {
        guard let vault else { throw TunelError.NotSignedIn }
        return vault
    }

    /// Las llamadas al núcleo bloquean (Argon2id, red): fuera del hilo principal.
    nonisolated static func background<T: Sendable>(
        _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await Task.detached(priority: .userInitiated, operation: work).value
    }
}
