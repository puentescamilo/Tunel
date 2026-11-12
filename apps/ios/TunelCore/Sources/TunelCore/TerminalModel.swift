import Foundation
import Observation

/// En qué punto está la sesión de terminal.
public enum TerminalState: Equatable, Sendable {
    case connecting
    case connected
    /// Terminó; `error` es `nil` si se cerró con normalidad (por ejemplo, con `exit`).
    case closed(error: String?)
}

/// Una sesión SSH para la pantalla de terminal. La conexión la hace el núcleo; aquí solo se
/// lleva el estado, las preguntas pendientes y el paso de bytes.
@MainActor
@Observable
public final class TerminalModel {
    public let host: HostSummary
    public private(set) var state: TerminalState = .connecting
    /// El servidor presenta una clave desconocida o distinta: hay que preguntar.
    public private(set) var hostKeyQuestion: HostKeyQuestion?
    /// El servidor pide datos para entrar (contraseña, código…).
    public private(set) var loginQuestion: LoginQuestion?

    /// Lo que llega del servidor. Lo que llegue antes de que la pantalla se lo pida se
    /// guarda y se entrega entonces.
    @ObservationIgnored public var onOutput: ((Data) -> Void)? {
        didSet { flushPending() }
    }

    /// Sin retener la bóveda: si la app se bloquea, la sesión no impide volver a abrirla.
    @ObservationIgnored private weak var vault: Vault?
    @ObservationIgnored private var session: TerminalSession?
    @ObservationIgnored private var pending: [Data] = []
    @ObservationIgnored private var size: (cols: UInt16, rows: UInt16) = (80, 24)
    /// Cada conexión tiene su número: lo que llegue de una anterior se descarta.
    @ObservationIgnored private var generation = 0
    /// La app pasó a segundo plano con la sesión abierta.
    @ObservationIgnored private var wasInBackground = false

    init(host: HostSummary, vault: Vault) {
        self.host = host
        self.vault = vault
    }

    /// Conecta con el tamaño actual de la pantalla. Si ya había una sesión, la cierra antes.
    public func connect() {
        session?.close()
        session = nil
        hostKeyQuestion = nil
        loginQuestion = nil
        generation += 1
        state = .connecting
        guard let vault else {
            state = .closed(error: "La bóveda está bloqueada")
            return
        }
        let listener = ListenerBridge(model: self, generation: generation)
        do {
            session = try vault.openTerminal(
                hostId: host.id, cols: size.cols, rows: size.rows, listener: listener)
        } catch {
            state = .closed(error: userMessage(for: error))
        }
    }

    public func send(_ data: Data) {
        session?.send(data: data)
    }

    public func resize(cols: Int, rows: Int) {
        guard cols > 0, rows > 0 else { return }
        let newSize = (UInt16(clamping: cols), UInt16(clamping: rows))
        guard newSize != size else { return }
        size = newSize
        session?.resize(cols: newSize.0, rows: newSize.1)
    }

    public func answerHostKey(accept: Bool) {
        hostKeyQuestion = nil
        do {
            try session?.answerHostKey(accept: accept)
        } catch {
            finish(error: userMessage(for: error))
        }
    }

    /// `nil` cancela.
    public func answerLogin(_ answers: [String]?) {
        loginQuestion = nil
        session?.answerLogin(answers: answers)
    }

    public func close() {
        session?.close()
        session = nil
    }

    /// iOS corta la conexión poco después de pasar a segundo plano.
    public func didEnterBackground() {
        wasInBackground = true
    }

    /// De vuelta en primer plano: si la conexión se cortó mientras tanto, se reconecta.
    public func didBecomeActive() {
        defer { wasInBackground = false }
        guard wasInBackground, case .closed = state else { return }
        connect()
    }

    // MARK: - Lo que cuenta el núcleo

    fileprivate func handle(_ event: TerminalEvent, generation: Int) {
        guard generation == self.generation else { return }
        switch event {
        case .connected:
            state = .connected
        case .output(let data):
            if let onOutput { onOutput(data) } else { pending.append(data) }
        case .hostKey(let question):
            hostKeyQuestion = question
        case .login(let question):
            loginQuestion = question
        case .closed(let error):
            finish(error: error)
        }
    }

    private func finish(error: String?) {
        hostKeyQuestion = nil
        loginQuestion = nil
        session = nil
        state = .closed(error: error)
    }

    private func flushPending() {
        guard let onOutput, !pending.isEmpty else { return }
        let waiting = pending
        pending = []
        waiting.forEach(onOutput)
    }
}

extension VaultStore {
    /// Una sesión de terminal para `host`, sin conectar todavía.
    public func terminal(for host: HostSummary) -> TerminalModel? {
        vault.map { TerminalModel(host: host, vault: $0) }
    }
}

enum TerminalEvent: Sendable {
    case connected
    case output(Data)
    case hostKey(HostKeyQuestion)
    case login(LoginQuestion)
    case closed(String?)
}

/// Recibe los avisos del núcleo, que llegan desde sus hilos, y los pasa en orden al hilo
/// principal.
final class ListenerBridge: TerminalListener, @unchecked Sendable {
    // Solo se lee en el hilo principal.
    private weak var model: TerminalModel?
    private let generation: Int

    init(model: TerminalModel, generation: Int) {
        self.model = model
        self.generation = generation
    }

    func connected() { deliver(.connected) }
    func output(data: Data) { deliver(.output(data)) }
    func hostKey(question: HostKeyQuestion) { deliver(.hostKey(question)) }
    func login(question: LoginQuestion) { deliver(.login(question)) }
    func closed(error: String?) { deliver(.closed(error)) }

    /// `DispatchQueue.main` respeta el orden de llegada; varias `Task` no lo garantizan.
    func deliver(_ event: TerminalEvent) {
        DispatchQueue.main.async { [self] in
            MainActor.assumeIsolated {
                model?.handle(event, generation: generation)
            }
        }
    }
}

/// Por identidad: para navegar a la pantalla de una sesión concreta.
extension TerminalModel: Hashable {
    nonisolated public static func == (lhs: TerminalModel, rhs: TerminalModel) -> Bool {
        lhs === rhs
    }

    nonisolated public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }
}
