import Foundation
import Testing
@testable import TunelCore

@MainActor
private func unlockedStore() async throws -> VaultStore {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let store = VaultStore(path: dir.appendingPathComponent("vault.json").path)
    await store.create(password: "correcta-caballo", confirmation: "correcta-caballo")
    return store
}

private let missingHost = HostSummary(
    id: UUID().uuidString, label: "web-01", address: "10.0.0.1", port: 22,
    protocol: "SSH", groupId: nil, team: nil, tags: [])

private let question = HostKeyQuestion(
    host: "10.0.0.1", port: 22, algorithm: "ssh-ed25519", fingerprint: "SHA256:abc",
    expected: nil)

/// Espera a que el hilo principal entregue lo que el puente puso en cola.
@MainActor
private func drainMainQueue() async {
    await withCheckedContinuation { done in DispatchQueue.main.async { done.resume() } }
}

@MainActor
@Test func aHostThatIsNoLongerInTheVaultClosesWithTheReason() async throws {
    let store = try await unlockedStore()
    let terminal = try #require(store.terminal(for: missingHost))

    terminal.connect()

    #expect(terminal.state == .closed(error: "Ese host ya no está en la bóveda"))
}

@MainActor
@Test func withTheVaultLockedThereIsNoTerminal() async throws {
    let store = try await unlockedStore()
    store.lock()

    #expect(store.terminal(for: missingHost) == nil)
}

@MainActor
@Test func outputBeforeTheScreenIsReadyIsKeptInOrder() async throws {
    let store = try await unlockedStore()
    let terminal = try #require(store.terminal(for: missingHost))
    let bridge = ListenerBridge(model: terminal, generation: 0)
    var received = Data()

    bridge.output(data: Data("hola ".utf8))
    bridge.output(data: Data("mundo".utf8))
    await drainMainQueue()
    terminal.onOutput = { received.append($0) }

    #expect(String(decoding: received, as: UTF8.self) == "hola mundo")
}

@MainActor
@Test func theQuestionsAndTheEndOfTheSessionReachTheModel() async throws {
    let store = try await unlockedStore()
    let terminal = try #require(store.terminal(for: missingHost))
    let bridge = ListenerBridge(model: terminal, generation: 0)

    bridge.hostKey(question: question)
    await drainMainQueue()
    #expect(terminal.hostKeyQuestion == question)

    bridge.connected()
    await drainMainQueue()
    #expect(terminal.state == .connected)

    bridge.closed(error: "Conexión perdida")
    await drainMainQueue()
    #expect(terminal.state == .closed(error: "Conexión perdida"))
    #expect(terminal.hostKeyQuestion == nil)
}

@MainActor
@Test func whatArrivesFromAnEarlierConnectionIsIgnored() async throws {
    let store = try await unlockedStore()
    let terminal = try #require(store.terminal(for: missingHost))
    terminal.connect()
    let state = terminal.state

    ListenerBridge(model: terminal, generation: 0).connected()
    await drainMainQueue()

    #expect(terminal.state == state)
}

@MainActor
@Test func aShortTripToAnotherAppDoesNotLockTheVault() async throws {
    let store = try await unlockedStore()
    let left = Date()

    store.didEnterBackground(at: left)
    store.didBecomeActive(at: left.addingTimeInterval(VaultStore.backgroundGrace - 1))

    #expect(store.state == .unlocked)
}

@MainActor
@Test func aLongTimeInTheBackgroundLocksTheVault() async throws {
    let store = try await unlockedStore()
    let left = Date()

    store.didEnterBackground(at: left)
    store.didBecomeActive(at: left.addingTimeInterval(VaultStore.backgroundGrace))

    #expect(store.state == .locked)
}
