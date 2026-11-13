import Foundation
import LocalAuthentication
import Security

/// Qué biometría tiene el dispositivo.
public enum BiometryKind: Sendable, Equatable {
    case faceID
    case touchID
    case opticID

    /// El nombre que usa Apple, para los textos de la interfaz.
    public var name: String {
        switch self {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        }
    }

    public var symbol: String {
        switch self {
        case .faceID: "faceid"
        case .touchID: "touchid"
        case .opticID: "opticid"
        }
    }
}

public enum BiometricKeychainError: Error, Equatable {
    /// El llavero ya no tiene la clave: se borró, o cambiaron las caras o huellas registradas.
    case missing
    case failed(OSStatus)
}

/// Dónde guarda la app la clave que abre la bóveda sin contraseña. En el dispositivo, el
/// llavero de iOS; en las pruebas, uno en memoria.
public protocol BiometricKeychain: Sendable {
    /// La biometría configurada, o `nil` si no hay o no está activada.
    func availableKind() -> BiometryKind?
    /// Pide la cara o la huella. `false` si se cancela.
    func authenticate(reason: String) async throws -> Bool
    /// Guarda `key` con el nombre `id`, en lugar de cualquier clave anterior.
    func replace(with key: Data, id: String) throws
    /// La clave `id`, tras pedir la cara o la huella. `nil` si se cancela.
    func load(id: String, reason: String) async throws -> Data?
    func removeAll()
}

/// El llavero de iOS. La clave solo sale tras Face ID o Touch ID, no pasa a copias de
/// seguridad ni a otros dispositivos, y deja de servir si cambian las caras o huellas
/// registradas o si se quita el código del dispositivo.
public struct SystemBiometricKeychain: BiometricKeychain {
    private static let service = "dev.tunel.biometria"

    public init() {}

    public func availableKind() -> BiometryKind? {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        else { return nil }
        switch context.biometryType {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        default: return nil
        }
    }

    public func authenticate(reason: String) async throws -> Bool {
        do {
            return try await LAContext().evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError where Self.isCancel(error) {
            return false
        }
    }

    public func replace(with key: Data, id: String) throws {
        removeAll()
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error)
        else { throw BiometricKeychainError.failed(errSecParam) }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: id,
            kSecAttrAccessControl: access,
            kSecValueData: key,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw BiometricKeychainError.failed(status) }
    }

    public func load(id: String, reason: String) async throws -> Data? {
        // SecItemCopyMatching espera a que el usuario responda: fuera del hilo principal.
        try await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            context.localizedReason = reason
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: Self.service,
                kSecAttrAccount: id,
                kSecReturnData: true,
                kSecUseAuthenticationContext: context,
            ]
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let data = result as? Data else { throw BiometricKeychainError.missing }
                return data
            case errSecUserCanceled: return nil
            case errSecItemNotFound: throw BiometricKeychainError.missing
            default: throw BiometricKeychainError.failed(status)
            }
        }.value
    }

    public func removeAll() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func isCancel(_ error: LAError) -> Bool {
        [.userCancel, .appCancel, .systemCancel, .userFallback].contains(error.code)
    }
}
