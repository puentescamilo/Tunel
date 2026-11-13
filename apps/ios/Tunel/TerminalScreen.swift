import SwiftTerm
import SwiftUI
import TunelCore

/// La terminal de un host. La barra sobre el teclado (Esc, Ctrl, Tab y flechas) es la de
/// SwiftTerm.
struct TerminalScreen: View {
    let terminal: TerminalModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var started = false

    var body: some View {
        TerminalSurface(terminal: terminal)
            .overlay { StatusOverlay(terminal: terminal) }
            .navigationTitle(terminal.host.label)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if case .closed = terminal.state {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Reconectar", systemImage: "arrow.clockwise", action: terminal.connect)
                    }
                }
            }
            .alert(
                hostKeyTitle, isPresented: hostKeyShown, presenting: terminal.hostKeyQuestion
            ) { question in
                Button(
                    question.expected == nil ? "Confiar y conectar" : "Aceptar la clave nueva",
                    role: question.expected == nil ? nil : .destructive
                ) { terminal.answerHostKey(accept: true) }
                Button("Cancelar", role: .cancel) { terminal.answerHostKey(accept: false) }
            } message: { question in
                Text(hostKeyMessage(question))
            }
            .sheet(isPresented: loginShown) {
                if let question = terminal.loginQuestion {
                    LoginSheet(question: question, answer: terminal.answerLogin)
                }
            }
            .onAppear {
                guard !started else { return }
                started = true
                terminal.connect()
            }
            .onDisappear(perform: terminal.close)
            .onChange(of: scenePhase) { _, phase in
                switch phase {
                case .background: terminal.didEnterBackground()
                case .active: terminal.didBecomeActive()
                default: break
                }
            }
    }

    private var hostKeyTitle: String {
        terminal.hostKeyQuestion?.expected == nil
            ? "Primera conexión a este servidor"
            : "La clave del servidor ha cambiado"
    }

    private func hostKeyMessage(_ question: HostKeyQuestion) -> String {
        let endpoint = question.port == 22 ? question.host : "\(question.host):\(question.port)"
        let presented = "\(endpoint)\n\(question.algorithm)\n\(question.fingerprint)"
        guard let expected = question.expected else {
            return "Comprueba que la huella es la del servidor antes de confiar en ella.\n\n\(presented)"
        }
        return "Alguien podría estar interceptando la conexión. Acepta solo si sabes que el servidor se reinstaló o cambió de clave.\n\n\(presented)\n\nAntes:\n\(expected)"
    }

    /// Cerrar la alerta sin elegir equivale a cancelar.
    private var hostKeyShown: Binding<Bool> {
        Binding(
            get: { terminal.hostKeyQuestion != nil },
            set: { shown in if !shown, terminal.hostKeyQuestion != nil { terminal.answerHostKey(accept: false) } }
        )
    }

    private var loginShown: Binding<Bool> {
        Binding(
            get: { terminal.loginQuestion != nil },
            set: { shown in if !shown, terminal.loginQuestion != nil { terminal.answerLogin(nil) } }
        )
    }
}

/// Mientras conecta o cuando la sesión terminó, encima de la terminal.
private struct StatusOverlay: View {
    let terminal: TerminalModel

    var body: some View {
        switch terminal.state {
        case .connected:
            EmptyView()
        case .connecting:
            if terminal.hostKeyQuestion == nil, terminal.loginQuestion == nil {
                ProgressView("Conectando con \(terminal.host.endpoint)…")
                    .padding()
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            }
        case .closed(let error):
            VStack(spacing: 12) {
                Label(
                    error ?? "Sesión cerrada",
                    systemImage: error == nil ? "checkmark.circle" : "exclamationmark.triangle"
                )
                .multilineTextAlignment(.center)
                Button("Reconectar", action: terminal.connect)
                    .buttonStyle(.borderedProminent)
            }
            .padding()
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .padding()
        }
    }
}

/// El servidor pide datos para entrar: una casilla por pregunta.
private struct LoginSheet: View {
    let question: LoginQuestion
    let answer: ([String]?) -> Void
    @State private var answers: [String]

    init(question: LoginQuestion, answer: @escaping ([String]?) -> Void) {
        self.question = question
        self.answer = answer
        _answers = State(initialValue: Array(repeating: "", count: question.prompts.count))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(question.prompts.indices, id: \.self) { index in
                        let prompt = question.prompts[index]
                        if prompt.echo {
                            TextField(prompt.text, text: $answers[index])
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        } else {
                            SecureField(prompt.text, text: $answers[index])
                        }
                    }
                } header: {
                    Text(question.host)
                } footer: {
                    if !question.instructions.isEmpty { Text(question.instructions) }
                }
            }
            .navigationTitle("Iniciar sesión")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancelar") { answer(nil) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Entrar") { answer(answers) }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

/// La vista de SwiftTerm: pinta lo que llega y pasa lo tecleado y el tamaño a la sesión.
private struct TerminalSurface: UIViewRepresentable {
    let terminal: TerminalModel

    private static let fontSize: CGFloat = 13

    func makeCoordinator() -> Coordinator { Coordinator(terminal: terminal) }

    func makeUIView(context: Context) -> TerminalView {
        let view = TerminalView(frame: .zero)
        view.terminalDelegate = context.coordinator
        view.font = UIFont.monospacedSystemFont(ofSize: Self.fontSize, weight: .regular)
        terminal.onOutput = { [weak view] data in view?.feed(byteArray: ArraySlice(data)) }
        // Con el teclado ya abierto al entrar.
        DispatchQueue.main.async { _ = view.becomeFirstResponder() }
        return view
    }

    func updateUIView(_ view: TerminalView, context: Context) {}

    static func dismantleUIView(_ view: TerminalView, coordinator: Coordinator) {
        coordinator.terminal.onOutput = nil
    }

    @MainActor
    final class Coordinator: NSObject, @preconcurrency TerminalViewDelegate {
        let terminal: TerminalModel

        init(terminal: TerminalModel) {
            self.terminal = terminal
        }

        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            terminal.send(Data(data))
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            terminal.resize(cols: newCols, rows: newRows)
        }

        /// Solo enlaces web: un servidor no debe poder abrir otras apps.
        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
            guard let url = URL(string: link), ["http", "https"].contains(url.scheme?.lowercased())
            else { return }
            UIApplication.shared.open(url)
        }

        func setTerminalTitle(source: TerminalView, title: String) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func scrolled(source: TerminalView, position: Double) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    }
}
