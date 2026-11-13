import Foundation
import Testing
@testable import TunelCore

@MainActor
private func openStore() async throws -> VaultStore {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let store = VaultStore(path: dir.appendingPathComponent("vault.json").path)
    await store.create(password: "correcta-caballo", confirmation: "correcta-caballo")
    return store
}

@MainActor
@Test func aNewHostAppearsInTheListAndCanBeEditedAgain() async throws {
    let store = try await openStore()
    var draft = try #require(store.newHostDraft(inGroup: nil))
    draft.label = "bastion"
    draft.address = "bastion.example.com"
    draft.newUsername = "ops"

    let saved = try await store.save(draft)

    #expect(store.tree.hosts.map(\.label) == ["bastion"])
    #expect(store.canEdit(saved))
    #expect(store.identities().map(\.username) == ["ops"])
    var again = try store.draft(for: saved)
    #expect(again.identityId != nil)
    again.label = "salto"
    try await store.save(again)
    #expect(store.host(saved.id)?.label == "salto")
}

@MainActor
@Test func aJumpHostIsSavedInOrder() async throws {
    let store = try await openStore()
    var jump = try #require(store.newHostDraft(inGroup: nil))
    jump.address = "jump.example.com"
    let first = try await store.save(jump)
    var target = try #require(store.newHostDraft(inGroup: nil))
    target.address = "10.0.0.5"
    target.jumpHostIds = [first.id]

    let saved = try await store.save(target)

    #expect(try store.draft(for: saved).jumpHostIds == [first.id])
}

@MainActor
@Test func anInvalidHostExplainsWhy() async throws {
    let store = try await openStore()
    var draft = try #require(store.newHostDraft(inGroup: nil))
    draft.address = "dos palabras"

    await #expect {
        try await store.save(draft)
    } throws: { error in
        (error as? TunelError)?.message == "La dirección no puede tener espacios"
    }
    #expect(store.tree.hosts.isEmpty)
}

@MainActor
@Test func deletingRemovesTheHost() async throws {
    let store = try await openStore()
    var draft = try #require(store.newHostDraft(inGroup: nil))
    draft.address = "viejo.example.com"
    let saved = try await store.save(draft)

    try await store.delete(saved)

    #expect(store.tree.hosts.isEmpty)
    #expect(store.host(saved.id) == nil)
}
