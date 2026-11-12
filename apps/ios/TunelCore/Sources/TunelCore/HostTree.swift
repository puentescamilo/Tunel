import Foundation

/// Un grupo con sus subgrupos, para la barra lateral.
public struct GroupNode: Identifiable, Hashable, Sendable {
    public let group: GroupSummary
    /// `nil` si no tiene subgrupos, para que la lista no muestre la flecha de desplegar.
    public let children: [GroupNode]?

    public var id: String { group.id }
}

/// Los grupos de la bóveda en forma de árbol y los hosts de cada rama.
public struct HostTree: Sendable {
    public let hosts: [HostSummary]
    public let roots: [GroupNode]
    private let childrenByParent: [String: [GroupSummary]]
    private let groupsById: [String: GroupSummary]

    public init(hosts: [HostSummary], groups: [GroupSummary]) {
        let ids = Set(groups.map(\.id))
        // Un padre que ya no existe deja al grupo en la raíz, como en el escritorio.
        let byParent = Dictionary(grouping: groups) { group in
            group.parentId.flatMap { ids.contains($0) ? $0 : nil } ?? ""
        }
        self.hosts = hosts
        self.childrenByParent = byParent
        self.groupsById = Dictionary(groups.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        self.roots = Self.nodes(under: "", in: byParent, visited: [])
    }

    public func group(_ id: String) -> GroupSummary? { groupsById[id] }

    /// Los hosts del grupo y de todos sus subgrupos; con `nil`, todos los hosts.
    public func hosts(in groupId: String?, matching query: String = "") -> [HostSummary] {
        let inGroup: [HostSummary]
        if let groupId {
            let branch = descendants(of: groupId).union([groupId])
            inGroup = hosts.filter { $0.groupId.map(branch.contains) ?? false }
        } else {
            inGroup = hosts
        }
        let needle = query.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return inGroup }
        return inGroup.filter { $0.matches(needle) }
    }

    private func descendants(of groupId: String) -> Set<String> {
        var found: Set<String> = []
        var pending = [groupId]
        while let next = pending.popLast() {
            for child in childrenByParent[next] ?? [] where found.insert(child.id).inserted {
                pending.append(child.id)
            }
        }
        return found
    }

    /// `visited` corta los ciclos que pudiera traer una bóveda dañada.
    private static func nodes(
        under parent: String, in byParent: [String: [GroupSummary]], visited: Set<String>
    ) -> [GroupNode] {
        (byParent[parent] ?? [])
            .filter { !visited.contains($0.id) }
            .map { group in
                let children = nodes(
                    under: group.id, in: byParent, visited: visited.union([group.id]))
                return GroupNode(group: group, children: children.isEmpty ? nil : children)
            }
    }
}

extension HostSummary {
    /// La misma búsqueda que el escritorio: nombre, dirección o etiquetas, sin mayúsculas.
    func matches(_ query: String) -> Bool {
        let fields = [label, address] + tags
        return fields.contains { $0.localizedCaseInsensitiveContains(query) }
    }

    /// «dirección:puerto», o solo la dirección si el puerto es el habitual de SSH.
    public var endpoint: String {
        port == 22 || port == 0 ? address : "\(address):\(port)"
    }
}
