import Foundation

/// Crear, editar y borrar hosts de la bóveda personal. Los cambios suben a la cuenta en
/// cuanto se guardan, si el dispositivo está unido a una.
extension VaultStore {
    /// El host `id` tal como está ahora (después de editarlo, o de sincronizar).
    public func host(_ id: String) -> HostSummary? {
        tree.hosts.first { $0.id == id }
    }

    /// Solo los hosts personales: los de un Team se editan desde el escritorio.
    public func canEdit(_ host: HostSummary) -> Bool {
        host.team == nil && vault?.canEditHost(hostId: host.id) == true
    }

    public func newHostDraft(inGroup groupId: String?) -> HostDraft? {
        // Un grupo de Team no admite hosts personales.
        let personal = groupId.flatMap { tree.group($0) }.flatMap { $0.team == nil ? $0.id : nil }
        return vault?.newHostDraft(groupId: personal)
    }

    public func draft(for host: HostSummary) throws -> HostDraft {
        guard let vault else { throw TunelError.NotSignedIn }
        return try vault.hostDraft(hostId: host.id)
    }

    /// Identidades que puede usar un host personal.
    public func identities() -> [IdentitySummary] {
        vault?.identities() ?? []
    }

    /// Grupos donde puede ir un host personal.
    public func personalGroups() -> [GroupSummary] {
        (vault?.groups() ?? []).filter { $0.team == nil }
    }

    /// Guarda el host y lo devuelve como queda en la lista. Los errores del formulario
    /// llegan como `TunelError.InvalidHost`, con el mensaje para mostrar.
    @discardableResult
    public func save(_ draft: HostDraft) async throws -> HostSummary {
        guard let vault else { throw TunelError.NotSignedIn }
        let saved = try await Self.background { try vault.saveHost(draft: draft) }
        reload()
        uploadInBackground()
        return saved
    }

    public func delete(_ host: HostSummary) async throws {
        guard let vault else { throw TunelError.NotSignedIn }
        let id = host.id
        try await Self.background { try vault.deleteHost(hostId: id) }
        reload()
        uploadInBackground()
    }

    /// Sin esperar: si no hay red, el cambio queda en la cola y sube en la siguiente.
    private func uploadInBackground() {
        guard account != nil else { return }
        Task { await sync() }
    }
}
