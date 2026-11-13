import Foundation
import Observation

/// Estado de la bóveda para la interfaz: si hay que crearla, desbloquearla o ya está abierta.
@MainActor
@Observable
public final class VaultStore {
    public enum State: Equatable, Sendable {
        /// No hay bóveda en este dispositivo.
        case needsSetup
        case locked
        case unlocked
    }

    public private(set) var state: State
    public private(set) var tree = HostTree(hosts: [], groups: [])
    /// Mientras se deriva la clave (tarda un momento): la interfaz desactiva el botón.
    public private(set) var isWorking = false
    /// La cuenta a la que está unido el dispositivo; `nil` si no lo está.
    public internal(set) var account: AccountInfo?
    public internal(set) var syncStatus: SyncStatus = .idle
    public var errorMessage: String?

    /// Cuánto puede estar la app en segundo plano sin bloquearse: lo justo para copiar algo
    /// de otra app y volver a la terminal.
    public static let backgroundGrace: TimeInterval = 180

    private let path: String
    @ObservationIgnored private var backgroundSince: Date?
    /// Abierta mientras `state` es `.unlocked`; la usa también la parte de la cuenta.
    var vault: Vault?

    public init(path: String) {
        self.path = path
        self.state = vaultExists(path: path) ? .locked : .needsSetup
    }

    /// Dónde guarda la app su bóveda: en Application Support, fuera de la copia en iCloud.
    public static func defaultPath() throws -> String {
        var dir = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        dir.appendPathComponent("Tunel", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        return dir.appendingPathComponent("vault.json").path
    }

    public func unlock(password: String) async {
        await open { [path] in try Vault.unlock(path: path, password: password) }
    }

    public func create(password: String, confirmation: String) async {
        guard password == confirmation else {
            errorMessage = "Las contraseñas no coinciden"
            return
        }
        await open { [path] in try Vault.create(path: path, password: password) }
    }

    /// Suelta la bóveda: el núcleo borra los secretos de la memoria y libera el archivo.
    public func lock() {
        guard state == .unlocked else { return }
        vault = nil
        tree = HostTree(hosts: [], groups: [])
        account = nil
        syncStatus = .idle
        state = .locked
    }

    public func didEnterBackground(at date: Date = .now) {
        backgroundSince = date
    }

    /// De vuelta en primer plano: si pasó más de `backgroundGrace`, se bloquea.
    public func didBecomeActive(at date: Date = .now) {
        defer { backgroundSince = nil }
        guard let since = backgroundSince,
            date.timeIntervalSince(since) >= Self.backgroundGrace
        else { return }
        lock()
    }

    /// Vuelve a leer hosts, grupos y cuenta de la bóveda abierta.
    func reload() {
        guard let vault else { return }
        tree = HostTree(hosts: vault.hosts(), groups: vault.groups())
        account = try? vault.account()
    }

    private func open(_ action: @escaping @Sendable () throws -> Vault) async {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        defer { isWorking = false }
        do {
            // Argon2id tarda: fuera del hilo principal para no congelar la interfaz.
            let opened = try await Task.detached(priority: .userInitiated, operation: action).value
            vault = opened
            reload()
            state = .unlocked
        } catch {
            errorMessage = userMessage(for: error)
        }
    }
}
