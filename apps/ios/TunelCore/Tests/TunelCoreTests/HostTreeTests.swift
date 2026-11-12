import Testing
@testable import TunelCore

private func group(_ id: String, parent: String? = nil) -> GroupSummary {
    GroupSummary(id: id, name: id.capitalized, parentId: parent, team: nil, icon: nil)
}

private func host(_ label: String, in group: String? = nil, tags: [String] = []) -> HostSummary {
    HostSummary(
        id: label, label: label, address: "\(label).example.com", port: 22,
        protocol: "SSH", groupId: group, team: nil, tags: tags)
}

@Test func subgroupsHangFromTheirParent() {
    let tree = HostTree(hosts: [], groups: [group("clientes"), group("acme", parent: "clientes")])

    #expect(tree.roots.map(\.id) == ["clientes"])
    #expect(tree.roots[0].children?.map(\.id) == ["acme"])
}

@Test func aGroupWithoutSubgroupsHasNoChildrenToExpand() {
    let tree = HostTree(hosts: [], groups: [group("solo")])

    #expect(tree.roots[0].children == nil)
}

@Test func aGroupWhoseParentIsGoneGoesToTheRoot() {
    let tree = HostTree(hosts: [], groups: [group("huérfano", parent: "borrado")])

    #expect(tree.roots.map(\.id) == ["huérfano"])
}

@Test func aGroupIncludesTheHostsOfItsSubgroups() {
    let tree = HostTree(
        hosts: [host("web", in: "acme"), host("db", in: "clientes"), host("suelto")],
        groups: [group("clientes"), group("acme", parent: "clientes")])

    #expect(Set(tree.hosts(in: "clientes").map(\.label)) == ["web", "db"])
    #expect(tree.hosts(in: "acme").map(\.label) == ["web"])
    #expect(tree.hosts(in: nil).count == 3)
}

@Test func aCycleInADamagedVaultDoesNotHang() {
    let tree = HostTree(
        hosts: [host("web", in: "a")], groups: [group("a", parent: "b"), group("b", parent: "a")])

    #expect(tree.hosts(in: "a").map(\.label) == ["web"])
}

@Test func searchingMatchesNameAddressAndTagsWithinTheGroup() {
    let tree = HostTree(
        hosts: [host("web", in: "acme", tags: ["producción"]), host("db", in: "acme"), host("otro")],
        groups: [group("acme")])

    #expect(tree.hosts(in: "acme", matching: "PRODUCCIÓN").map(\.label) == ["web"])
    #expect(tree.hosts(in: "acme", matching: "db.example").map(\.label) == ["db"])
    #expect(tree.hosts(in: "acme", matching: "  ").count == 2)
}

@Test func theEndpointHidesTheUsualSshPort() {
    var summary = host("web")
    #expect(summary.endpoint == "web.example.com")
    summary.port = 2222
    #expect(summary.endpoint == "web.example.com:2222")
}

@Test func aGroupIsFoundByItsId() {
    let tree = HostTree(hosts: [], groups: [group("acme")])

    #expect(tree.group("acme")?.name == "Acme")
    #expect(tree.group("otro") == nil)
}
