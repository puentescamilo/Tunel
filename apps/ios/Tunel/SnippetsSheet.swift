import SwiftUI
import TunelCore

/// Elegir un snippet y enviarlo a la terminal. Si tiene variables, primero pide sus valores.
struct SnippetsSheet: View {
    let terminal: TerminalModel
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var path: [SnippetSummary] = []
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack(path: $path) {
            list
                .navigationTitle("Snippets")
                .navigationBarTitleDisplayMode(.inline)
                .searchable(text: $query, prompt: "Buscar por nombre, comando o etiqueta")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cerrar") { dismiss() }
                    }
                }
                .navigationDestination(for: SnippetSummary.self) { snippet in
                    SnippetVariablesForm(snippet: snippet, terminal: terminal) { dismiss() }
                }
                .alert(
                    "No se pudo enviar el snippet",
                    isPresented: Binding(
                        get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
                ) {
                    Button("Aceptar", role: .cancel) {}
                } message: {
                    Text(errorMessage ?? "")
                }
        }
    }

    @ViewBuilder
    private var list: some View {
        let snippets = terminal.snippets(matching: query)
        if snippets.isEmpty {
            if query.isEmpty {
                ContentUnavailableView(
                    "Sin snippets", systemImage: "text.page",
                    description: Text(
                        "Los snippets que crees en Túnel del escritorio llegan aquí al sincronizar."))
            } else {
                ContentUnavailableView.search(text: query)
            }
        } else {
            List(snippets, id: \.id) { snippet in
                Button { choose(snippet) } label: { SnippetRow(snippet: snippet) }
                    .tint(.primary)
            }
        }
    }

    private func choose(_ snippet: SnippetSummary) {
        guard snippet.variables.isEmpty else {
            path.append(snippet)
            return
        }
        do {
            try terminal.run(snippet)
            dismiss()
        } catch {
            errorMessage = userMessage(for: error)
        }
    }
}

private struct SnippetRow: View {
    let snippet: SnippetSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(snippet.label).font(.body.weight(.medium))
                if snippet.team != nil {
                    Image(systemName: "person.2")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("De un Team")
                }
                Spacer()
                if !snippet.variables.isEmpty {
                    Image(systemName: "curlybraces")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Pide valores")
                }
            }
            Text(snippet.script)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(.vertical, 2)
    }
}

/// Una casilla por variable, con el último valor usado, y el comando tal como se enviará.
private struct SnippetVariablesForm: View {
    let snippet: SnippetSummary
    let terminal: TerminalModel
    let sent: () -> Void
    @State private var fields: [SnippetVariable] = []
    @State private var errorMessage: String?
    @FocusState private var focused: String?

    var body: some View {
        Form {
            Section("Valores") {
                ForEach($fields, id: \.name) { $field in
                    TextField(field.name, text: $field.value)
                        .font(.body.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($focused, equals: field.name)
                        .submitLabel(.send)
                        .onSubmit(send)
                }
            }
            Section("Se enviará") {
                Text(preview)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
            if let errorMessage {
                Section { Text(errorMessage).foregroundStyle(.red) }
            }
        }
        .navigationTitle(snippet.label)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Enviar", action: send)
            }
        }
        .onAppear(perform: load)
    }

    private var preview: String {
        snippetPreview(script: snippet.script, values: values)
    }

    private var values: [String: String] {
        Dictionary(fields.map { ($0.name, $0.value) }, uniquingKeysWith: { first, _ in first })
    }

    private func load() {
        guard fields.isEmpty else { return }
        do {
            fields = try terminal.variables(of: snippet)
            focused = fields.first(where: { $0.value.isEmpty })?.name ?? fields.first?.name
        } catch {
            errorMessage = userMessage(for: error)
        }
    }

    private func send() {
        do {
            try terminal.run(snippet, values: values)
            sent()
        } catch {
            errorMessage = userMessage(for: error)
        }
    }
}
