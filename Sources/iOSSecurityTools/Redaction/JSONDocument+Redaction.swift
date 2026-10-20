extension JSONDocument {
    /// The replacements that redact the document. Every replacement covers one whole token or
    /// value and is valid JSON in its place, so the redacted document is still JSON:
    ///
    /// - The value of every member whose name hides it (see ``FieldName``), at any depth, inside
    ///   arrays and for every repetition of a name, becomes the string `"[redacted]"`, whatever its
    ///   type. So does the `value`, `val` or `v` of an object whose `name`, `key`, `field`,
    ///   `header`, `param`, `k` or `n` is such a name (`{"name":"X-Api-Key","value":…}`), and every
    ///   element of an array after a string that names a secret or cannot be read
    ///   (`["password","…"]`).
    /// - Names and strings are free text: one in which anything is found is written again, escaped,
    ///   with the free-text rule applied to its decoded text, which may hold JSON again. They are
    ///   read with the document's ``nesting`` and the objects and arrays around them, so JSON in
    ///   them that goes past a limit of the budget hides the whole string.
    /// - A number that holds a card number or a long token becomes a string with its mask.
    func secretSpans(using redactor: SensitiveDataRedactor, compatibility: CompatibilityText) -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        collect(root, nesting: nesting, into: &spans, redactor: redactor, compatibility: compatibility)
        return spans
    }

    /// Collects the replacements of a value inside the objects and arrays that `nesting` counts.
    /// The recursion follows the document, whose depth the reader bounded.
    private func collect(
        _ node: Node, nesting: Nesting, into spans: inout [SensitiveDataRedactor.Span], redactor: SensitiveDataRedactor,
        compatibility: CompatibilityText
    ) {
        let readsNames = redactor.kinds.contains(.secretFields)
        let inside = nesting.enteringContainer()
        switch node.value {
        case .object(let members):
            let hidesPairValue = readsNames && hidesPairValue(in: members)
            for member in members {
                spans += stringSpans(member.name, role: .name, nesting: inside, redactor: redactor, compatibility: compatibility)
                let name = text(of: member.name)
                if readsNames, FieldName.hidesValue(name) || (hidesPairValue && Self.isPairPart(name, Self.pairValueNames)) {
                    spans.append(Self.hiding(member.value))
                } else {
                    collect(member.value, nesting: inside, into: &spans, redactor: redactor, compatibility: compatibility)
                }
            }
        case .array(let elements):
            var hidesRest = false
            for element in elements {
                guard !hidesRest else {
                    spans.append(Self.hiding(element))
                    continue
                }
                collect(element, nesting: inside, into: &spans, redactor: redactor, compatibility: compatibility)
                if readsNames, case .string(let token) = element.value {
                    hidesRest = FreeTextScanner.mentionsSecret(text(of: token), compatibility: compatibility)
                }
            }
        case .string(let token):
            spans += stringSpans(token, role: .text, nesting: nesting, redactor: redactor, compatibility: compatibility)
        case .number:
            spans += numberSpans(node, redactor: redactor, compatibility: compatibility)
        case .boolean, .null:
            break
        }
    }

    private static let pairNameNames: Set<String> = ["name", "key", "field", "header", "param", "k", "n"]
    private static let pairValueNames: Set<String> = ["value", "val", "v"]

    /// Whether the object is a name and value pair, as HTTP archives write headers and
    /// configurations write environment variables, whose name hides its value.
    private func hidesPairValue(in members: [Member]) -> Bool {
        members.contains { member in
            guard Self.isPairPart(text(of: member.name), Self.pairNameNames), case .string(let token) = member.value.value else { return false }
            return FieldName.hidesValue(text(of: token))
        }
    }

    private static func isPairPart(_ name: [Unicode.Scalar], _ names: Set<String>) -> Bool {
        name.count <= 6 && names.contains(String(String.UnicodeScalarView(name)).lowercased())
    }

    /// Any value, quotes and brackets included, becomes the string `"[redacted]"`.
    private static func hiding(_ node: Node) -> SensitiveDataRedactor.Span {
        SensitiveDataRedactor.Span(
            start: node.range.lowerBound, end: node.range.upperBound, kind: .secretFields, replacement: "\"\(SensitiveDataRedactor.replacement)\""
        )
    }

    /// A name or string whose decoded text the free-text rule changes is written again, escaped.
    private func stringSpans(
        _ token: StringToken, role: FreeTextScanner.Role, nesting: Nesting, redactor: SensitiveDataRedactor, compatibility: CompatibilityText
    ) -> [SensitiveDataRedactor.Span] {
        guard let (redacted, kind) = redactor.redactedText(text(of: token), compatibility: compatibility, role: role, nesting: nesting) else {
            return []
        }
        return [SensitiveDataRedactor.Span(start: token.content.lowerBound, end: token.content.upperBound, kind: kind, replacement: Self.escaped(redacted))]
    }

    /// A number with a card number or a long token in it becomes a string with the mask, since a
    /// mask is not a number.
    private func numberSpans(_ node: Node, redactor: SensitiveDataRedactor, compatibility: CompatibilityText) -> [SensitiveDataRedactor.Span] {
        let digits = Array(scalars[node.range])
        let found = SensitiveDataRedactor.merged(redactor.detectorSpans(in: NormalizedText(digits, compatibility: compatibility)))
        guard !found.isEmpty else { return [] }
        let kind = found.reduce(into: SensitiveDataRedactor.Kinds()) { $0.formUnion($1.kind) }
        let masked = SensitiveDataRedactor.replacing(found, in: digits)
        return [SensitiveDataRedactor.Span(start: node.range.lowerBound, end: node.range.upperBound, kind: kind, replacement: "\"\(Self.escaped(masked))\"")]
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
