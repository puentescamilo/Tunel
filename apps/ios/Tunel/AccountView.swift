import AuthenticationServices
import SwiftUI
import TunelCore

/// Unir el dispositivo a la cuenta de Túnel, o ver con qué cuenta está unido.
struct AccountView: View {
    let store: VaultStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if let account = store.account {
                    AccountDetail(store: store, account: account)
                } else {
                    SignInForm(store: store)
                }
            }
            .navigationTitle("Cuenta de Túnel")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Cerrar") { dismiss() }
                }
            }
        }
    }
}

// MARK: - Unido

private struct AccountDetail: View {
    let store: VaultStore
    let account: AccountInfo
    @State private var confirmingSignOut = false
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Correo", value: account.email)
                LabeledContent("Servidor", value: account.server)
                LabeledContent("Entra con", value: account.providerName ?? "Contraseña")
            }
            Section("Sincronización") {
                SyncStatusRow(status: store.syncStatus)
                Button("Sincronizar ahora") { Task { await store.sync() } }
                    .disabled(store.syncStatus == .syncing)
            }
            if !account.teams.isEmpty {
                Section("Teams") {
                    ForEach(account.teams, id: \.self) { Label($0, systemImage: "person.2") }
                }
            }
            Section {
                Button("Salir de la cuenta", role: .destructive) { confirmingSignOut = true }
            } footer: {
                Text("Se borran de este dispositivo los hosts y credenciales de la cuenta. En tus otros equipos no cambia nada.")
            }
            if let errorMessage {
                Text(errorMessage).foregroundStyle(.red)
            }
        }
        .confirmationDialog(
            "¿Salir de la cuenta en este dispositivo?", isPresented: $confirmingSignOut,
            titleVisibility: .visible
        ) {
            Button("Salir y borrar lo descargado", role: .destructive) {
                Task {
                    do { try await store.signOut() } catch { errorMessage = message(for: error) }
                }
            }
        }
    }
}

struct SyncStatusRow: View {
    let status: SyncStatus

    var body: some View {
        switch status {
        case .idle:
            Text("Sin sincronizar todavía").foregroundStyle(.secondary)
        case .syncing:
            HStack {
                ProgressView()
                Text("Sincronizando…").foregroundStyle(.secondary)
            }
        case .synced(let at, let problems, let invitations):
            VStack(alignment: .leading, spacing: 4) {
                Text("Sincronizado \(at.formatted(.relative(presentation: .named)))")
                ForEach(problems, id: \.self) { problem in
                    Label(problem, systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
                if invitations > 0 {
                    Text(
                        invitations == 1
                            ? "Tienes una invitación a un Team: acéptala desde Túnel en el escritorio."
                            : "Tienes \(invitations) invitaciones a Teams: acéptalas desde Túnel en el escritorio."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
        }
    }
}

// MARK: - Sin unir

private struct SignInForm: View {
    let store: VaultStore
    @Environment(\.webAuthenticationSession) private var webAuthenticationSession

    /// El último servidor usado; no es secreto.
    @AppStorage("servidor") private var server = ""
    @State private var options: SignInOptions?
    @State private var email = ""
    @State private var password = ""
    @State private var pending: PendingProvider?
    @State private var masterPassword = ""
    @State private var isWorking = false
    @State private var errorMessage: String?

    /// Volvió el navegador de un proveedor: falta la contraseña maestra.
    private struct PendingProvider {
        let signIn: ProviderSignIn
        let email: String
    }

    var body: some View {
        Form {
            if let pending {
                masterPasswordSection(pending)
            } else {
                Section {
                    TextField("https://tunel.ejemplo.com", text: $server)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: server) { options = nil }
                } header: {
                    Text("Servidor")
                } footer: {
                    Text("El mismo que tienes en Túnel en el escritorio, en Ajustes → Sincronización.")
                }
                if let options {
                    providerSection(options)
                    if options.passwordLogin { passwordSection }
                } else {
                    Button("Continuar") { run { options = try await store.signInOptions(server: server) } }
                        .disabled(server.trimmingCharacters(in: .whitespaces).isEmpty || isWorking)
                }
            }
            if isWorking {
                HStack {
                    ProgressView()
                    Text("Un momento…").foregroundStyle(.secondary)
                }
            }
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.circle").foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder
    private func providerSection(_ options: SignInOptions) -> some View {
        if !options.providers.isEmpty {
            Section {
                ForEach(options.providers, id: \.id) { provider in
                    Button("Entrar con \(provider.name)") { signIn(with: provider) }
                        .disabled(isWorking)
                }
            }
        }
    }

    private var passwordSection: some View {
        Section {
            TextField("Correo", text: $email)
                .keyboardType(.emailAddress)
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            SecureField("Contraseña de la cuenta", text: $password)
                .textContentType(.password)
            Button("Entrar") {
                run {
                    try await store.signIn(server: server, email: email, password: password)
                    password = ""
                }
            }
            .disabled(email.isEmpty || password.isEmpty || isWorking)
        } header: {
            Text("Con correo y contraseña")
        }
    }

    private func masterPasswordSection(_ pending: PendingProvider) -> some View {
        Section {
            SecureField("Contraseña maestra", text: $masterPassword)
                .textContentType(.password)
            Button("Unir este dispositivo") {
                run {
                    try await store.finishProviderSignIn(
                        pending.signIn, masterPassword: masterPassword)
                    masterPassword = ""
                    self.pending = nil
                }
            }
            .disabled(masterPassword.isEmpty || isWorking)
            Button("Cancelar", role: .cancel) {
                masterPassword = ""
                self.pending = nil
            }
        } header: {
            Text(pending.email)
        } footer: {
            Text("La contraseña maestra de tu cuenta de Túnel, la misma que usas en el escritorio. Con ella se descifran tus datos en este dispositivo; el servidor no la conoce.")
        }
    }

    private func signIn(with provider: Provider) {
        run {
            let signIn = try await store.beginProviderSignIn(server: server, providerId: provider.id)
            guard let url = URL(string: signIn.url()) else { return }
            let callback: URL
            do {
                callback = try await webAuthenticationSession.authenticate(
                    using: url, callbackURLScheme: signIn.callbackScheme())
            } catch ASWebAuthenticationSessionError.canceledLogin {
                return
            }
            let email = try await store.providerReturned(signIn, callback: callback)
            pending = PendingProvider(signIn: signIn, email: email)
        }
    }

    /// Ejecuta `work` mostrando que trabaja y el error, si lo hay.
    private func run(_ work: @escaping @MainActor () async throws -> Void) {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        Task {
            defer { isWorking = false }
            do { try await work() } catch { errorMessage = message(for: error) }
        }
    }
}

private func message(for error: any Error) -> String {
    (error as? TunelError)?.message ?? error.localizedDescription
}
