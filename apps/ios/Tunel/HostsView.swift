import SwiftUI
import TunelCore

/// Grupos a la izquierda y hosts a la derecha en iPad; en iPhone, una pantalla tras otra.
struct HostsView: View {
    let store: VaultStore
    @State private var showingAccount = false

    /// `allHosts` es la entrada «Todos los hosts»; el resto, el id de un grupo.
    @State private var selection: String? = Self.allHosts
    @State private var query = ""

    private static let allHosts = "todos"

    private var tree: HostTree { store.tree }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Todos los hosts", systemImage: "server.rack")
                    .tag(Self.allHosts)
                if !tree.roots.isEmpty {
                    Section("Grupos") {
                        OutlineGroup(tree.roots, children: \.children) { node in
                            Label(node.group.name, systemImage: node.group.symbol)
                                .tag(node.id)
                        }
                    }
                }
            }
            .navigationTitle("Túnel")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cuenta", systemImage: "person.crop.circle") { showingAccount = true }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Bloquear", systemImage: "lock", action: store.lock)
                }
            }
            .safeAreaInset(edge: .bottom) {
                if store.account != nil {
                    SyncStatusRow(status: store.syncStatus)
                        .font(.footnote)
                        .padding(.horizontal)
                        .padding(.vertical, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.bar)
                }
            }
        } detail: {
            NavigationStack {
                HostList(
                    hosts: tree.hosts(in: groupId, matching: query),
                    hasAccount: store.account != nil,
                    onSignIn: { showingAccount = true }
                )
                .navigationTitle(title)
                .searchable(text: $query, prompt: "Nombre, dirección o etiqueta")
                .refreshable { await store.sync() }
            }
        }
        .sheet(isPresented: $showingAccount) { AccountView(store: store) }
        // Al desbloquear, lo nuevo de la cuenta.
        .task { await store.sync() }
    }

    private var groupId: String? { selection == Self.allHosts ? nil : selection }

    private var title: String {
        guard let groupId else { return "Todos los hosts" }
        return tree.group(groupId)?.name ?? "Hosts"
    }
}

private struct HostList: View {
    let hosts: [HostSummary]
    let hasAccount: Bool
    let onSignIn: () -> Void

    var body: some View {
        if hosts.isEmpty && !hasAccount {
            ContentUnavailableView {
                Label("Une tu cuenta de Túnel", systemImage: "person.crop.circle.badge.plus")
            } description: {
                Text("Tus hosts, identidades y Teams llegan desde tu cuenta.")
            } actions: {
                Button("Iniciar sesión", action: onSignIn).buttonStyle(.borderedProminent)
            }
        } else if hosts.isEmpty {
            ContentUnavailableView(
                "No hay hosts", systemImage: "server.rack",
                description: Text("Desliza hacia abajo para sincronizar."))
        } else {
            List(hosts, id: \.id) { host in
                NavigationLink(value: host) { HostRow(host: host) }
            }
            .navigationDestination(for: HostSummary.self) { HostDetailView(host: $0) }
        }
    }
}

private struct HostRow: View {
    let host: HostSummary

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: host.team == nil ? "server.rack" : "person.2")
                .foregroundStyle(.tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.label).font(.body)
                Text(host.endpoint)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if host.protocol != "SSH" {
                Text(host.protocol)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
            }
        }
    }
}

extension GroupSummary {
    /// Un símbolo del sistema parecido al icono de Phosphor que tiene en el escritorio.
    var symbol: String {
        switch icon {
        case "database": "cylinder.split.1x2"
        case "cloud": "cloud"
        case "globe": "globe"
        case "house": "house"
        case "briefcase": "briefcase"
        case "lock", "shield": "lock.shield"
        case "terminal": "terminal"
        default: "folder"
        }
    }
}
