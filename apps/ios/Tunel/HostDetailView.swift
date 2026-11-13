import SwiftUI
import TunelCore

/// Los datos de un host y el botón para abrir su terminal.
struct HostDetailView: View {
    let host: HostSummary
    let store: VaultStore
    @State private var terminal: TerminalModel?

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
        }
        .navigationTitle(host.label)
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(item: $terminal) { TerminalScreen(terminal: $0) }
    }
}
