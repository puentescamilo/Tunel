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
            // En el selector de apps no se ve lo que hay en pantalla.
            .overlay { if scenePhase != .active { PrivacyCover() } }
            .onChange(of: scenePhase) { _, phase in
                // Un viaje corto a otra app no bloquea, para no perder la terminal; uno largo, sí.
                switch phase {
                case .background: store?.didEnterBackground()
                case .active: store?.didBecomeActive()
                default: break
                }
            }
        }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
        }
        .ignoresSafeArea()
    }
}

struct RootView: View {
    let store: VaultStore

    var body: some View {
        switch store.state {
        case .needsSetup, .locked:
            LockView(store: store)
        case .unlocked:
            HostsView(store: store)
        }
    }
}
