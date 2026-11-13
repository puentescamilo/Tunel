import Foundation

/// Desbloqueo con Face ID o Touch ID. El núcleo guarda junto a la bóveda su clave sellada; la
/// clave que abre ese sello está en el llavero y solo sale tras la cara o la huella.
extension VaultStore {
    /// Pide Face ID y abre la bóveda. Si se cancela, no pasa nada: queda la contraseña.
    public func unlockWithBiometrics() async {
        guard let kind = biometricKind, biometricReady, !isWorking,
            let id = biometricId(path: path)
        else { return }
        promptsBiometricsOnAppear = false
        errorMessage = nil
        let key: Data
        do {
            guard let loaded = try await keychain.load(id: id, reason: "Desbloquear Túnel")
            else { return }
            key = loaded
        } catch BiometricKeychainError.missing {
            errorMessage =
                "\(kind.name) ya no tiene la clave de la bóveda (¿cambiaron las caras o huellas registradas?). Entra con la contraseña y vuelve a activarlo en Ajustes."
            return
        } catch {
            errorMessage = "\(kind.name) no pudo abrir la bóveda. Entra con la contraseña."
            return
        }
        await open { [path] in try Vault.unlockBiometric(path: path, key: key) }
        if state != .unlocked { refreshBiometricReady() }
    }

    /// Activa o quita Face ID para la bóveda abierta. Activarlo pide la cara una vez, para
    /// comprobar que funciona.
    public func setBiometricUnlock(_ enabled: Bool) async {
        guard let vault, let kind = biometricKind else { return }
        errorMessage = nil
        guard enabled else {
            disableBiometrics(vault)
            return
        }
        do {
            guard try await keychain.authenticate(reason: "Activar el desbloqueo con \(kind.name)")
            else { return }
            let saved = try vault.enableBiometric()
            do {
                try keychain.replace(with: saved.key, id: saved.id)
            } catch {
                // Sin la clave en el llavero, el archivo no sirve para nada.
                try? vault.disableBiometric()
                throw error
            }
            biometricEnabled = true
        } catch {
            biometricEnabled = vault.biometricEnabled()
            errorMessage = "No se pudo activar \(kind.name): \(userMessage(for: error))"
        }
    }

    private func disableBiometrics(_ vault: Vault) {
        do {
            try vault.disableBiometric()
        } catch {
            errorMessage = userMessage(for: error)
        }
        keychain.removeAll()
        biometricEnabled = vault.biometricEnabled()
    }

    func refreshBiometricReady() {
        let enabled = state == .locked && biometricKind != nil && biometricId(path: path) != nil
        biometricReady = enabled && TunelCore.biometricReady(path: path)
        biometricWaitsForPassword = enabled && !biometricReady
    }
}
