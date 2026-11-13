import SwiftUI
import TunelCore

/// Los datos de un host y el botón para abrir su terminal.
struct HostDetailView: View {
    /// Como estaba al abrir; lo que se muestra es `host`, que sigue los cambios.
    let initial: HostSummary
    let store: VaultStore
    @State private var terminal: TerminalModel?
    @State private var editing: HostEditing?
    @State private var errorMessage: String?
    @Environment(\.dismiss) private var dismiss

    init(host: HostSummary, store: VaultStore) {
        self.initial = host
        self.store = store
    }

    private var host: HostSummary { store.host(initial.id) ?? initial }

    /// Lo que la terminal del móvil puede abrir; Mosh se abre por SSH.
    private var canConnect: Bool { host.protocol == "SSH" || host.protocol == "Mosh" }

    var body: some View {
        Form {
            Section {
                Button("Conectar", systemImage: "terminal") { terminal = store.terminal(for: host) }
                    .disabled(!canConnect)
            } footer: {
                if !canConnect {
                    Text("Los hosts \(host.protocol) todavía no se pueden abrir en este dispositivo.")
                }
            }
            Section {
                LabeledContent("Dirección", value: host.address)
                LabeledContent("Puerto", value: "\(host.port)")
                LabeledContent("Protocolo", value: host.protocol)
                if host.team != nil {
                    LabeledContent("De un Team", value: "Sí")
                }
            }
            if !host.tags.isEmpty {
                Section("Etiquetas") {
                    Text(host.tags.joined(separator: " · "))
                }
            }
            if host.team != nil {
                Section {
                } footer: {
                    Text("Los hosts de un Team se editan desde Túnel en el escritorio.")
                }
            }
        }
        .navigationTitle(host.label)
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(item: $terminal) { TerminalScreen(terminal: $0) }
        .toolbar {
            if store.canEdit(host) {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Editar", action: edit)
                }
            }
        }
        .sheet(item: $editing) { editing in
            HostEditorView(store: store, draft: editing.draft) { saved in
                // Borrado: ya no hay nada que mostrar aquí.
                if saved == nil { dismiss() }
            }
        }
        .alert("No se puede editar", isPresented: errorShown) {
            Button("Aceptar", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private func edit() {
        do {
            editing = HostEditing(draft: try store.draft(for: host))
        } catch {
            errorMessage = (error as? TunelError)?.message ?? error.localizedDescription
        }
    }

    private var errorShown: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }
}
