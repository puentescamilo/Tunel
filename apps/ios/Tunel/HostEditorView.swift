import SwiftUI
import TunelCore

/// Un formulario abierto, para `.sheet(item:)`: cada apertura es distinta.
struct HostEditing: Identifiable {
    let id = UUID()
    let draft: HostDraft
}

/// El formulario para crear o editar un host personal.
struct HostEditorView: View {
    let store: VaultStore
    /// Se llama con el host guardado, o con `nil` si se borró.
    let onFinish: (HostSummary?) -> Void

    @State private var draft: HostDraft
    @State private var port: String
    @State private var tags: String
    @State private var credential: Credential
    @State private var errorMessage: String?
    @State private var saving = false
    @State private var confirmingDelete = false
    @Environment(\.dismiss) private var dismiss

    private let identities: [IdentitySummary]
    private let groups: [GroupSummary]

    private static let protocols = ["SSH", "Mosh", "Telnet"]

    /// Qué credencial usa el host.
    private enum Credential: Hashable {
        case none
        case identity(String)
        case new
    }

    init(store: VaultStore, draft: HostDraft, onFinish: @escaping (HostSummary?) -> Void) {
        self.store = store
        self.onFinish = onFinish
        self.identities = store.identities()
        self.groups = store.personalGroups()
        _draft = State(initialValue: draft)
        _port = State(initialValue: draft.port.map(String.init) ?? "")
        _tags = State(initialValue: draft.tags.joined(separator: ", "))
        _credential = State(initialValue: draft.identityId.map(Credential.identity) ?? .none)
    }

    private var isNew: Bool { draft.id == nil }

    var body: some View {
        NavigationStack {
            Form {
                general
                credentials
                Section("Grupo") {
                    Picker("Grupo", selection: $draft.groupId) {
                        Text("Sin grupo").tag(String?.none)
                        ForEach(groups, id: \.id) { Text($0.name).tag(Optional($0.id)) }
                    }
                }
                JumpHostsSection(store: store, hostId: draft.id, selected: $draft.jumpHostIds)
                Section("Etiquetas") {
                    TextField("prod, web", text: $tags)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section("Notas") {
                    TextField("Notas", text: $draft.notes, axis: .vertical)
                        .lineLimit(3...8)
                }
                if !isNew {
                    Section {
                        Button("Borrar host", role: .destructive) { confirmingDelete = true }
                    }
                }
            }
            .navigationTitle(isNew ? "Nuevo host" : "Editar host")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancelar") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if saving {
                        ProgressView()
                    } else {
                        Button("Guardar", action: save)
                            .disabled(draft.address.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .alert("No se pudo guardar", isPresented: errorShown) {
                Button("Aceptar", role: .cancel) {}
            } message: {
                Text(errorMessage ?? "")
            }
            .confirmationDialog(
                "¿Borrar «\(draft.label.isEmpty ? draft.address : draft.label)»?",
                isPresented: $confirmingDelete, titleVisibility: .visible
            ) {
                Button("Borrar", role: .destructive, action: delete)
            } message: {
                Text("Se borra también de tus otros equipos. Los hosts que saltaban por él dejan de hacerlo.")
            }
        }
        .interactiveDismissDisabled(saving)
    }

    private var general: some View {
        Section {
            TextField("Nombre", text: $draft.label)
            TextField("Dirección (nombre o IP)", text: $draft.address)
                .textContentType(.URL)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            TextField("Puerto (opcional)", text: $port)
                .keyboardType(.numberPad)
            Picker("Protocolo", selection: $draft.protocol) {
                ForEach(Self.protocols, id: \.self) { Text($0) }
            }
        }
    }

    private var credentials: some View {
        Section {
            Picker("Credencial", selection: $credential) {
                Text("Ninguna").tag(Credential.none)
                ForEach(identities, id: \.id) { identity in
                    Text(identity.username.isEmpty ? identity.label : "\(identity.label) (\(identity.username))")
                        .tag(Credential.identity(identity.id))
                }
                Text("Nueva…").tag(Credential.new)
            }
            if credential == .new {
                TextField("Usuario", text: $draft.newUsername)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                SecureField("Contraseña (opcional)", text: $draft.newPassword)
                    .textContentType(.password)
            }
        } header: {
            Text("Credencial")
        } footer: {
            if credential == .new {
                Text("Se guarda como una identidad nueva. Las claves SSH se añaden desde el escritorio.")
            }
        }
    }

    private var errorShown: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    private func save() {
        let trimmedPort = port.trimmingCharacters(in: .whitespaces)
        var final = draft
        if trimmedPort.isEmpty {
            final.port = nil
        } else if let value = UInt16(trimmedPort), value > 0 {
            final.port = value
        } else {
            errorMessage = "El puerto tiene que estar entre 1 y 65535"
            return
        }
        final.tags = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        switch credential {
        case .none:
            final.identityId = nil
            final.newUsername = ""
        case .identity(let id):
            final.identityId = id
            final.newUsername = ""
        case .new:
            guard !final.newUsername.trimmingCharacters(in: .whitespaces).isEmpty else {
                errorMessage = "Escribe el usuario de la credencial nueva"
                return
            }
            final.identityId = nil
        }
        if final.newUsername.isEmpty { final.newPassword = "" }
        saving = true
        Task {
            defer { saving = false }
            do {
                let saved = try await store.save(final)
                onFinish(saved)
                dismiss()
            } catch {
                errorMessage = (error as? TunelError)?.message ?? error.localizedDescription
            }
        }
    }

    private func delete() {
        guard let id = draft.id, let host = store.host(id) else { return }
        saving = true
        Task {
            defer { saving = false }
            do {
                try await store.delete(host)
                onFinish(nil)
                dismiss()
            } catch {
                errorMessage = (error as? TunelError)?.message ?? error.localizedDescription
            }
        }
    }
}

/// Los jump hosts, en orden de salto: se añaden desde un menú, se reordenan y se quitan.
private struct JumpHostsSection: View {
    let store: VaultStore
    let hostId: String?
    @Binding var selected: [String]

    private var candidates: [HostSummary] {
        store.tree.hosts.filter { host in
            host.id != hostId && !selected.contains(host.id)
                && (host.protocol == "SSH" || host.protocol == "Mosh")
        }
    }

    var body: some View {
        Section {
            ForEach(selected, id: \.self) { id in
                Label(store.host(id)?.label ?? "Host borrado", systemImage: "arrow.turn.down.right")
            }
            .onDelete { selected.remove(atOffsets: $0) }
            .onMove { selected.move(fromOffsets: $0, toOffset: $1) }
            Menu("Añadir salto", systemImage: "plus") {
                ForEach(candidates, id: \.id) { host in
                    Button(host.label) { selected.append(host.id) }
                }
            }
            .disabled(candidates.isEmpty)
        } header: {
            Text("Saltar a través de")
        } footer: {
            Text(selected.isEmpty
                ? "Para llegar a un servidor que solo es accesible desde otro (ProxyJump)."
                : "Se salta en este orden. Desliza para quitar uno; mantén pulsado para moverlo.")
        }
    }
}
