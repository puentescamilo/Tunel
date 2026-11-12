import SwiftUI
import TunelCore

/// Los datos de un host. Conectar llega con la terminal.
struct HostDetailView: View {
    let host: HostSummary

    var body: some View {
        Form {
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
    }
}
