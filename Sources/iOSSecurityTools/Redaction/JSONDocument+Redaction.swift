extension JSONDocument {
    /// The values to hide in the document: the whole value of every member whose name hides it
    /// (see ``FieldName``), at any depth, inside arrays and for every repetition of a name, and
    /// secret fields written inside the strings that are kept.
    func secretSpans(using redactor: SensitiveDataRedactor, compatibility: CompatibilityText) -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        collect(root, into: &spans, redactor: redactor, compatibility: compatibility)
        return spans
    }

    private func collect(
        _ node: Node, into spans: inout [SensitiveDataRedactor.Span], redactor: SensitiveDataRedactor, compatibility: CompatibilityText
    ) {
        switch node.value {
        case .object(let members):
            for member in members {
                if FieldName.hidesValue(text(of: member.name)) {
                    spans.append(hiding(member.value))
                } else {
                    collect(member.value, into: &spans, redactor: redactor, compatibility: compatibility)
                }
            }
        case .array(let elements):
            for element in elements { collect(element, into: &spans, redactor: redactor, compatibility: compatibility) }
        case .string(let token):
            spans += stringSpans(token, redactor: redactor, compatibility: compatibility)
        case .number, .boolean, .null:
            break
        }
    }

    /// A string keeps its quotes and shows `[redacted]`; any other value becomes the string
    /// `"[redacted]"`, so the document stays valid JSON.
    private func hiding(_ node: Node) -> SensitiveDataRedactor.Span {
        if case .string(let token) = node.value {
            return SensitiveDataRedactor.Span(
                start: token.content.lowerBound, end: token.content.upperBound, kind: .secretFields, replacement: SensitiveDataRedactor.replacement
            )
        }
        return SensitiveDataRedactor.Span(
            start: node.range.lowerBound, end: node.range.upperBound, kind: .secretFields, replacement: "\"\(SensitiveDataRedactor.replacement)\""
        )
    }

    /// A string without escapes is read in place with the free-text rule. A string with escapes
    /// is decoded and redacted as text of its own (which may be JSON again, as GraphQL clients
    /// send `variables`); when anything in it is hidden, the whole string is written again.
    private func stringSpans(
        _ token: StringToken, redactor: SensitiveDataRedactor, compatibility: CompatibilityText
    ) -> [SensitiveDataRedactor.Span] {
        guard let decoded = token.decoded else {
            return FreeTextFields(scalars: scalars, bounds: token.content, compatibility: compatibility).spans()
        }
        let inner = redactor.spans(in: decoded, compatibility: compatibility)
        guard !inner.isEmpty else { return [] }
        let kind = inner.reduce(into: SensitiveDataRedactor.Kinds()) { $0.formUnion($1.kind) }
        let redacted = SensitiveDataRedactor.replacing(inner, in: decoded)
        return [SensitiveDataRedactor.Span(
            start: token.content.lowerBound, end: token.content.upperBound, kind: kind, replacement: Self.escaped(redacted)
        )]
    }

    /// The text as the content of a JSON string.
    static func escaped(_ text: String) -> String {
        var output = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": output.append(contentsOf: "\\\"".unicodeScalars)
            case "\\": output.append(contentsOf: "\\\\".unicodeScalars)
            case "\n": output.append(contentsOf: "\\n".unicodeScalars)
            case "\r": output.append(contentsOf: "\\r".unicodeScalars)
            case "\t": output.append(contentsOf: "\\t".unicodeScalars)
            case _ where scalar.value < 0x20:
                let hex = String(scalar.value, radix: 16)
                output.append(contentsOf: ("\\u" + String(repeating: "0", count: 4 - hex.count) + hex).unicodeScalars)
            default: output.append(scalar)
            }
        }
        return String(output)
    }
}
