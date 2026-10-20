extension JSONDocument {
    /// The replacements that redact the document. Every replacement covers one whole token or
    /// value and is valid JSON in its place, so the redacted document is still JSON:
    ///
    /// - The value of every member whose name hides it (see ``FieldName``), at any depth, inside
    ///   arrays and for every repetition of a name, becomes the string `"[redacted]"`, whatever its
    ///   type.
    /// - **Name and value pairs.** In an object whose `name`, `key`, `field`, `header`, `param`,
    ///   `path`, `k` or `n` is a string that hides a value by the same rule, every `value`, `val`,
    ///   `values`, `content`, `data`, `secret` and `v` is hidden whole, as HTTP archives write
    ///   headers (`{"name":"X-Api-Key","value":…}`). Of a `path`, the part after its last `/`
    ///   is the name, as JSON Patch (RFC 6902) and SCIM PatchOp (RFC 7644) write it:
    ///   `{"op":"replace","path":"/user/password","value":…}`; a secret part before it hides the
    ///   value too (`/apiKeys/0`), as the value goes inside it. A name that is an array or an
    ///   object cannot be read, so it hides the value too. The second element of a two-element
    ///   array whose first is such a string is hidden whole (`[["Authorization","…"]]`, as fetch
    ///   headers and `URLSearchParams` entries are written), and so is every element of an array
    ///   after a string that names a secret or cannot be read (`["password","…"]`).
    /// - **A secret name written as a value.** In an object with a member whose value is a name
    ///   that names a secret or cannot be read, read as free text reads its words
    ///   (`{"label":"Password","input":…}`, `{"ParameterKey":"DbPassword","ParameterValue":…}`),
    ///   the values of the other members are hidden whole, whatever their names: an object has no
    ///   order, so what belongs to the name cannot be told. A name here is a string of letters,
    ///   marks, digits, spaces and `_`, `-`, `.` and `/`, with any punctuation around it
    ///   (`"Password:"`); a sentence or JSON in a string is read as free text instead. The
    ///   members that hold names stay (`name`, `key`, `field`, `header`, `param`, `path`, `k`, `n`
    ///   with a string), and so does an `op` that names a JSON Patch or SCIM operation (`add`,
    ///   `remove`, `replace`, `move`, `copy`, `test`).
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
            let isHiddenPair = readsNames && elements.count == 2 && hidesValue(namedBy: elements[0])
            var hidesRest = false
            for (index, element) in elements.enumerated() {
                guard !hidesRest, !(isHiddenPair && index == 1) else {
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

    /// The members of an object, inside the objects and arrays that `nesting` counts. A value is
    /// hidden whole when its name hides it, when the object pairs a name that hides it with the
    /// value, or when another member names a secret.
    private func collectMembers(
        _ members: [Member], nesting: Nesting, into spans: inout [SensitiveDataRedactor.Span], redactor: SensitiveDataRedactor,
        compatibility: CompatibilityText
    ) {
        let readsNames = redactor.kinds.contains(.secretFields)
        let hidesPairValue = readsNames && hidesPairValue(in: members)
        let naming = readsNames ? namingMembers(members, compatibility: compatibility) : []
        for (index, member) in members.enumerated() {
            spans += stringSpans(member.name, role: .name, nesting: nesting, redactor: redactor, compatibility: compatibility)
            let name = text(of: member.name)
            // Another member names a secret: two do, or the one that does is not this one.
            let followsName = (naming.count > 1 || naming.first.map { $0 != index } == true) && !staysBesideName(member)
            if readsNames, FieldName.hidesValue(name) || (hidesPairValue && Self.isPairPart(name, Self.pairValueNames)) || followsName {
                spans.append(Self.hiding(member.value))
            } else {
                collect(member.value, nesting: nesting, into: &spans, redactor: redactor, compatibility: compatibility)
            }
        }
    }

    private static let pairNameNames: Set<String> = ["name", "key", "field", "header", "param", "path", "k", "n"]
    private static let pairValueNames: Set<String> = ["value", "val", "values", "content", "data", "secret", "v"]
    private static let longestPairPart = (pairNameNames.union(pairValueNames)).map(\.count).max() ?? 0

    /// Whether the object is a name and value pair, as HTTP archives write headers, JSON Patch
    /// and SCIM write operations and configurations write environment variables, whose name hides
    /// its value: a name that hides a value by the key rule, or one that is an array or object.
    private func hidesPairValue(in members: [Member]) -> Bool {
        members.contains { member in
            let name = text(of: member.name)
            guard Self.isPairPart(name, Self.pairNameNames) else { return false }
            switch member.value.value {
            case .string(let token):
                let named = text(of: token)
                return Self.isPairPart(name, ["path"]) ? Self.pathHidesValue(named) : FieldName.hidesValue(named)
            case .object, .array: return true
            case .number, .boolean, .null: return false
            }
        }
    }

    /// The members whose value is a name that names a secret or cannot be read.
    private func namingMembers(_ members: [Member], compatibility: CompatibilityText) -> [Int] {
        members.indices.filter { index in
            guard case .string(let token) = members[index].value.value else { return false }
            let value = text(of: token)
            return Self.isName(value) && FreeTextScanner.nameNamesSecret(value, compatibility: compatibility)
        }
    }

    /// Whether a string is a name rather than a sentence or a document: at most
    /// ``PlainName/maximumKeyLength`` scalars without a line break, and once the punctuation and
    /// spaces around it are left out, without `:`, `=`, `,`, `;`, quotes or brackets, which pair a
    /// key with a value or hold one (`Error: token expired`, `{"password":…}`).
    private static func isName(_ scalars: [Unicode.Scalar]) -> Bool {
        guard scalars.count <= PlainName.maximumKeyLength,
              let first = scalars.firstIndex(where: ScalarClass.isLetterOrNumber),
              let last = scalars.lastIndex(where: ScalarClass.isLetterOrNumber)
        else { return false }
        return !scalars.contains { $0 == "\n" || $0 == "\r" } && !scalars[first...last].contains { notInNames.contains($0) }
    }

    private static let notInNames = Set(":=,;\"'()[]{}<>".unicodeScalars)

    private static let operations: Set<String> = ["add", "remove", "replace", "move", "copy", "test"]

    /// Whether a member stays beside a name that names a secret: one that holds a name (`name`,
    /// `key`, `path`, … with a string), or the `op` of a JSON Patch or SCIM operation.
    private func staysBesideName(_ member: Member) -> Bool {
        guard case .string(let token) = member.value.value else { return false }
        let name = text(of: member.name)
        if Self.isPairPart(name, Self.pairNameNames) { return true }
        guard Self.isPairPart(name, ["op"]) else { return false }
        let operation = text(of: token)
        return operation.count <= 7 && Self.operations.contains(String(String.UnicodeScalarView(operation)).lowercased())
    }

    /// Whether a value names a field whose value is hidden: a string that is not plain ASCII or
    /// names a secret.
    private func hidesValue(namedBy node: Node) -> Bool {
        guard case .string(let token) = node.value else { return false }
        return FieldName.hidesValue(text(of: token))
    }

    /// Whether a JSON Pointer or SCIM path leads to a value that is hidden: one of its parts
    /// between `/` hides a value by the key rule. The last part names the field (`/user/password`,
    /// SCIM `password`), and a part before it holds the field (`/apiKeys/0`, `/password/hint`), so
    /// the value is inside a secret either way. Array indexes (`0`, and `-` for the end) name
    /// nothing. An empty path, which stands for the whole document, hides the value.
    private static func pathHidesValue(_ path: [Unicode.Scalar]) -> Bool {
        var parts = path.split(separator: "/", omittingEmptySubsequences: false)
        if path.first == "/" { parts.removeFirst() }
        return parts.contains { part in !(part.count == 1 && part.first == "-") && FieldName.hidesValue(part) }
    }

    private static func isPairPart(_ name: [Unicode.Scalar], _ names: Set<String>) -> Bool {
        name.count <= longestPairPart && names.contains(String(String.UnicodeScalarView(name)).lowercased())
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
