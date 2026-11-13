import Foundation
import Testing
@testable import TunelCore

/// Un llavero en memoria: la «cara» se acepta o se cancela según `accepts`.
private final class FakeKeychain: BiometricKeychain, @unchecked Sendable {
    var accepts = true
    var items: [String: Data] = [:]

    func availableKind() -> BiometryKind? { .faceID }

    func authenticate(reason: String) async throws -> Bool { accepts }

    func replace(with key: Data, id: String) throws {
        items = [id: key]
    }

    func load(id: String, reason: String) async throws -> Data? {
        guard accepts else { return nil }
        guard let key = items[id] else { throw BiometricKeychainError.missing }
        return key
    }

    func removeAll() { items = [:] }
}

private let password = "correcta-caballo"

@MainActor
private func unlockedStore(keychain: FakeKeychain) async throws -> VaultStore {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let store = VaultStore(path: dir.appendingPathComponent("vault.json").path, keychain: keychain)
    await store.create(password: password, confirmation: password)
    return store
}

@MainActor
@Test func faceIdOpensTheVaultOnceEnabled() async throws {
    let keychain = FakeKeychain()
    let store = try await unlockedStore(keychain: keychain)

    await store.setBiometricUnlock(true)
    #expect(store.biometricEnabled)
    #expect(keychain.items.count == 1)
    store.lock()
    #expect(store.biometricReady)
    await store.unlockWithBiometrics()

    #expect(store.state == .unlocked)
    #expect(store.errorMessage == nil)
}

@MainActor
@Test func cancellingFaceIdLeavesTheVaultLockedWithoutComplaining() async throws {
    let keychain = FakeKeychain()
    let store = try await unlockedStore(keychain: keychain)
    await store.setBiometricUnlock(true)
    store.lock()

    keychain.accepts = false
    await store.unlockWithBiometrics()

    #expect(store.state == .locked)
    #expect(store.errorMessage == nil)
}

@MainActor
@Test func cancellingTheConfirmationDoesNotEnableIt() async throws {
    let keychain = FakeKeychain()
    let store = try await unlockedStore(keychain: keychain)

    keychain.accepts = false
    await store.setBiometricUnlock(true)

    #expect(!store.biometricEnabled)
    #expect(keychain.items.isEmpty)
}

@MainActor
@Test func aKeychainWithoutTheKeyExplainsWhatToDo() async throws {
    let keychain = FakeKeychain()
    let store = try await unlockedStore(keychain: keychain)
    await store.setBiometricUnlock(true)
    store.lock()

    // Como cuando se registra otra cara: iOS invalida la clave.
    keychain.items = [:]
    await store.unlockWithBiometrics()

    #expect(store.state == .locked)
    #expect(store.errorMessage?.contains("Face ID ya no tiene la clave") == true)
}

@MainActor
@Test func disablingForgetsTheKeyAndStopsOfferingIt() async throws {
    let keychain = FakeKeychain()
    let store = try await unlockedStore(keychain: keychain)
    await store.setBiometricUnlock(true)

    await store.setBiometricUnlock(false)
    store.lock()

    #expect(!store.biometricEnabled)
    #expect(keychain.items.isEmpty)
    #expect(!store.biometricReady)
    #expect(!store.biometricWaitsForPassword)
}

@MainActor
@Test func onlyALockAfterTheGracePeriodPromptsFaceIdByItself() async throws {
    let store = try await unlockedStore(keychain: FakeKeychain())
    let start = Date()

    store.lock()
    #expect(!store.promptsBiometricsOnAppear)

    await store.unlock(password: password)
    store.didEnterBackground(at: start)
    store.didBecomeActive(at: start.addingTimeInterval(VaultStore.backgroundGrace))
    #expect(store.state == .locked)
    #expect(store.promptsBiometricsOnAppear)
}
