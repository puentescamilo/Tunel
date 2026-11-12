// Comprueba desde Swift que el núcleo en Rust se llama bien: crear, abrir y leer la bóveda.
import Foundation
import Testing
import TunelCore

private func temporaryVaultPath() throws -> String {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent("vault.json").path
}

@Test func aNewVaultIsEmptyAndCanBeOpenedAgain() throws {
    let path = try temporaryVaultPath()
    #expect(!vaultExists(path: path))

    // Se suelta al salir del bloque, y con ella el cerrojo del archivo.
    do {
        let created = try Vault.create(path: path, password: "correcta-caballo")
        #expect(created.hosts().isEmpty)
    }

    #expect(vaultExists(path: path))
    let reopened = try Vault.unlock(path: path, password: "correcta-caballo")
    #expect(reopened.groups().isEmpty)
}

@Test func aWrongPasswordThrowsWrongPassword() throws {
    let path = try temporaryVaultPath()
    do { _ = try Vault.create(path: path, password: "correcta-caballo") }

    #expect(throws: TunelError.WrongPassword) {
        try Vault.unlock(path: path, password: "otra-contraseña")
    }
}

@Test func anOpenVaultCannotBeOpenedTwice() throws {
    let path = try temporaryVaultPath()
    let open = try Vault.create(path: path, password: "correcta-caballo")

    #expect(throws: TunelError.Locked) {
        try Vault.unlock(path: path, password: "correcta-caballo")
    }
    withExtendedLifetime(open) {}
}

@Test func aShortPasswordIsRejectedWithTheMinimumLength() throws {
    let path = try temporaryVaultPath()

    #expect(throws: TunelError.WeakPassword(min: minPasswordLength())) {
        try Vault.create(path: path, password: "corta")
    }
}

@Test func theCoreReportsItsVersion() {
    #expect(!coreVersion().isEmpty)
}
