import SwiftUI
import TunelCore

@main
struct TunelApp: App {
    @State private var store: VaultStore?
    @State private var startupError: String?
    @Environment(\.scenePhase) private var scenePhase

    init() {
        do {
            _store = State(initialValue: VaultStore(path: try VaultStore.defaultPath()))
        } catch {
            _startupError = State(initialValue: error.localizedDescription)
        }
    }

    var body: some Scene {
        WindowGroup {
            Group {
                if let store {
                    RootView(store: store)
                } else {
                    ContentUnavailableView(
                        "No se pudo preparar la bóveda",
                        systemImage: "exclamationmark.triangle",
                        description: Text(startupError ?? ""))
                }
            }
            .onChange(of: scenePhase) { _, phase in
                // Al salir de la app se bloquea: en el selector de apps no se ven los hosts.
                if phase == .background { store?.lock() }
            }
        }
    }
}

struct RootView: View {
    let store: VaultStore

    var body: some View {
        switch store.state {
        case .needsSetup, .locked:
            LockView(store: store)
        case .unlocked:
            HostsView(tree: store.tree, onLock: store.lock)
        }
    }
}
