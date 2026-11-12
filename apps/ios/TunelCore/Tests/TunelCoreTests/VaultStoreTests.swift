import Foundation
import Testing
@testable import TunelCore

private func temporaryPath() throws -> String {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent("vault.json").path
}

@MainActor
@Test func withoutAVaultItAsksToCreateOne() async throws {
    let store = VaultStore(path: try temporaryPath())

    #expect(store.state == .needsSetup)
    await store.create(password: "correcta-caballo", confirmation: "correcta-caballo")

    #expect(store.state == .unlocked)
    #expect(store.errorMessage == nil)
}

@MainActor
@Test func mismatchedPasswordsDoNotCreateTheVault() async throws {
    let path = try temporaryPath()
    let store = VaultStore(path: path)

    await store.create(password: "correcta-caballo", confirmation: "correcta-caballa")

    #expect(store.state == .needsSetup)
    #expect(store.errorMessage == "Las contraseñas no coinciden")
    #expect(!vaultExists(path: path))
}

@MainActor
@Test func lockingAndUnlockingAgainWorksWithTheRightPassword() async throws {
    let path = try temporaryPath()
    let store = VaultStore(path: path)
    await store.create(password: "correcta-caballo", confirmation: "correcta-caballo")

    store.lock()
    #expect(store.state == .locked)
    await store.unlock(password: "correcta-caballo")

    #expect(store.state == .unlocked)
}

@MainActor
@Test func aWrongPasswordShowsTheCoreMessage() async throws {
    let path = try temporaryPath()
    let store = VaultStore(path: path)
    await store.create(password: "correcta-caballo", confirmation: "correcta-caballo")
    store.lock()

    await store.unlock(password: "otra-contraseña")

    #expect(store.state == .locked)
    #expect(store.errorMessage == "Contraseña maestra incorrecta")
}

@MainActor
@Test func anExistingVaultStartsLocked() async throws {
    let path = try temporaryPath()
    do { _ = try Vault.create(path: path, password: "correcta-caballo") }

    #expect(VaultStore(path: path).state == .locked)
}
