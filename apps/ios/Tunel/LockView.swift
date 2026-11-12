import SwiftUI
import TunelCore

/// Crear la bóveda la primera vez, o desbloquearla con la contraseña maestra.
struct LockView: View {
    @Bindable var store: VaultStore
    @State private var password = ""
    @State private var confirmation = ""
    @FocusState private var focused: Field?

    private enum Field { case password, confirmation }

    private var isCreating: Bool { store.state == .needsSetup }

    private var canSubmit: Bool {
        !store.isWorking && !password.isEmpty && (!isCreating || !confirmation.isEmpty)
    }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
            VStack(spacing: 6) {
                Text(isCreating ? "Crea tu bóveda" : "Túnel está bloqueado")
                    .font(.title2.bold())
                Text(
                    isCreating
                        ? "La contraseña maestra cifra tus hosts y credenciales en este dispositivo. Si la olvidas, no se puede recuperar."
                        : "Escribe tu contraseña maestra."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            }

            VStack(spacing: 12) {
                SecureField("Contraseña maestra", text: $password)
                    .textContentType(isCreating ? .newPassword : .password)
                    .focused($focused, equals: .password)
                    .submitLabel(isCreating ? .next : .go)
                    .onSubmit { isCreating ? (focused = .confirmation) : submit() }
                if isCreating {
                    SecureField("Repite la contraseña", text: $confirmation)
                        .textContentType(.newPassword)
                        .focused($focused, equals: .confirmation)
                        .submitLabel(.go)
                        .onSubmit(submit)
                    Text("Al menos \(minPasswordLength()) caracteres.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .textFieldStyle(.roundedBorder)

            if let message = store.errorMessage {
                Label(message, systemImage: "exclamationmark.circle")
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            Button(action: submit) {
                Group {
                    if store.isWorking {
                        ProgressView()
                    } else {
                        Text(isCreating ? "Crear bóveda" : "Desbloquear")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!canSubmit)
            Spacer()
        }
        .padding(24)
        .frame(maxWidth: 420)
        .onAppear { focused = .password }
    }

    private func submit() {
        guard canSubmit else { return }
        Task {
            if isCreating {
                await store.create(password: password, confirmation: confirmation)
            } else {
                await store.unlock(password: password)
            }
            // La contraseña no se queda en la pantalla, se haya abierto o no.
            if store.state == .unlocked || store.errorMessage != nil {
                password = ""
                confirmation = ""
            }
        }
    }
}
