import SwiftUI
import TunelCore

/// Seguridad del dispositivo y versión.
struct SettingsView: View {
    let store: VaultStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if let kind = store.biometricKind {
                        Toggle(isOn: biometricBinding) {
                            Label("Desbloquear con \(kind.name)", systemImage: kind.symbol)
                        }
                        .disabled(store.isWorking)
                    } else {
                        Label(
                            "Configura Face ID o Touch ID en los Ajustes del dispositivo para abrir la bóveda sin contraseña.",
                            systemImage: "faceid"
                        )
                        .foregroundStyle(.secondary)
                    }
                    if let message = store.errorMessage {
                        Text(message).foregroundStyle(.red)
                    }
                } header: {
                    Text("Seguridad")
                } footer: {
                    Text(
                        "La primera vez de cada día se pide la contraseña maestra, para no olvidarla. La bóveda se bloquea si sales de Túnel más de \(Int(VaultStore.backgroundGrace / 60)) minutos."
                    )
                }
                Section("Acerca de") {
                    LabeledContent("Versión", value: coreVersion())
                }
            }
            .navigationTitle("Ajustes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Cerrar") { dismiss() }
                }
            }
        }
    }

    private var biometricBinding: Binding<Bool> {
        Binding(
            get: { store.biometricEnabled },
            set: { enabled in Task { await store.setBiometricUnlock(enabled) } }
        )
    }
}
