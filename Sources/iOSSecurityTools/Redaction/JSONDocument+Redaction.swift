extension JSONDocument {
    /// The replacements that redact the document. Every replacement covers one whole token or
    /// value and is valid JSON in its place, so the redacted document is still JSON:
    ///
    /// - The value of every member whose name hides it (see ``FieldName``), at any depth, inside
    ///   arrays and for every repetition of a name, becomes the string `"[redacted]"`, whatever its
    ///   type.
    /// - **Names written as values** (see ``WrittenName``). In an object with a member whose value
    ///   is a name that names a secret, the values of the other members are hidden whole, whatever
    ///   their names: an object has no order, so what belongs to the name cannot be told. The
    ///   value of a member that holds a name (`name`, `key`, `field`, `label`, `type`, `header`,
    ///   `param`, `path`, `id`, `k`, `n`, or a member whose own name is not plain ASCII) is read by
    ///   the key rule, so a name that is not plain ASCII (`Şifre`, `ⓟⓘⓝ`, `🔑`, `Password:`)
    ///   names a secret, and so does an array or object there, which cannot be read as a name. Of
    ///   a `path`, every part between `/` is read that way, as JSON Patch (RFC 6902) and SCIM
    ///   PatchOp (RFC 7644) write it (`/user/password`, `/apiKeys/0`). The value of any other
    ///   member counts when it is a name whose words name a secret or cannot be read
    ///   (`{"ParameterKey":"DbPassword","ParameterValue":…}`): a string of letters, digits and
    ///   symbols whose compatibility form is a letter or digit, with spaces and `_`, `-`, `.` and
    ///   `/`, and any punctuation around it (`"Password:"`). The names of pairs stay (`name`,
    ///   `key`, `field`, `header`, `param`, `path`, `k`, `n` with a string), and so does an `op`
    ///   that names a JSON Patch or SCIM operation.
    /// - **Arrays.** The second element of a two-element array whose first is a string that the
    ///   key rule hides is hidden whole (`[["Authorization","…"]]`, as fetch headers and
    ///   `URLSearchParams` entries are written), and so is every element of an array after a
    ///   string that names a secret or cannot be read (`["password","…"]`).
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
            collectMembers(members, nesting: inside, into: &spans, redactor: redactor, compatibility: compatibility)
        case .array(let elements):
            let isHiddenPair = readsNames && elements.count == 2 && namesPairValue(elements[0], compatibility: compatibility)
            var hidesRest = false
            for (index, element) in elements.enumerated() {
                guard !hidesRest, !(isHiddenPair && index == 1) else {
                    spans.append(Self.hiding(element))
                    continue
                }
                collect(element, nesting: inside, into: &spans, redactor: redactor, compatibility: compatibility)
                // The last element names nothing after it, so it is not read again as a name.
                if readsNames, index + 1 < elements.count, case .string(let token) = element.value {
                    hidesRest = WrittenName.namesSecret(text(of: token), in: .element, compatibility: compatibility)
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

    /// The members of an object, inside the objects and arrays that `nesting` counts. A value is
    /// hidden whole when its name hides it or when another member names a secret.
    private func collectMembers(
        _ members: [Member], nesting: Nesting, into spans: inout [SensitiveDataRedactor.Span], redactor: SensitiveDataRedactor,
        compatibility: CompatibilityText
    ) {
        let readsNames = redactor.kinds.contains(.secretFields)
        let naming = readsNames ? namingFields(members, compatibility: compatibility) : nil
        for (index, member) in members.enumerated() {
            spans += stringSpans(member.name, role: .name, nesting: nesting, redactor: redactor, compatibility: compatibility)
            if readsNames, FieldName.hidesValue(text(of: member.name)) || naming?.hidesValue(at: index) == true {
                spans.append(Self.hiding(member.value))
            } else {
                collect(member.value, nesting: nesting, into: &spans, redactor: redactor, compatibility: compatibility)
            }
        }
    }

    private func namingFields(_ members: [Member], compatibility: CompatibilityText) -> NamingFields {
        NamingFields(members.map { member in
            let value: NamingFields.Value = switch member.value.value {
            case .string(let token): .string(text(of: token))
            case .object, .array: .structure
            case .number, .boolean, .null: .other
            }
            return (text(of: member.name), value)
        }, compatibility: compatibility)
    }

    /// Whether the first element of a two-element array names its second: a string that the key
    /// rule hides.
    private func namesPairValue(_ node: Node, compatibility: CompatibilityText) -> Bool {
        guard case .string(let token) = node.value else { return false }
        return WrittenName.namesSecret(text(of: token), in: .pairName, compatibility: compatibility)
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
