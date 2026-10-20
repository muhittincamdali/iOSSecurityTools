import Foundation

extension SensitiveDataRedactor {
    /// Returns a request or response body as text with its sensitive data hidden, for a log.
    ///
    /// The body is read with a parser chosen by its content type:
    ///
    /// - **JSON** (`application/json`, `text/json`, `…+json`): read as ``SensitiveDataRedactor``
    ///   describes under "Structured input". A hidden value of any type becomes the string
    ///   `"[redacted]"`, and a string or name is written again escaped, so the output is still
    ///   valid JSON.
    /// - **Forms** (`application/x-www-form-urlencoded`): fields are split at `&` and at the first
    ///   `=`, and names and values are decoded (`+` is a space, then percent-decoding as UTF-8).
    ///   A field whose decoded name hides its value shows `name=[redacted]`; other values, names
    ///   and fields without `=` are read as free text. The body is read only when it is strict:
    ///   printable ASCII without `;`, every `%` the start of an escape, and no name spelled two
    ///   ways (`a.b` and `a_b`, `pass%77ord` and `password`, `Note` and `note`).
    /// - **Multipart form data**: every part is written again with its field name and its
    ///   `type/subtype`; other part headers show `[redacted]` unless they are
    ///   `Content-Length` or `Content-Transfer-Encoding`. A part whose name hides its value
    ///   shows `[redacted]`, and any other part is read by its own content type (`text/plain`
    ///   when it has none). Uploaded files, nested multipart bodies, parts in a transfer encoding
    ///   other than `7bit`, `8bit` or `binary` and parts of other types are omitted like a body.
    ///   The body is read only with a single unquoted `boundary` of at most 70 characters, and
    ///   only when every `--boundary` in it, in any case, is a delimiter line that follows a CRLF.
    /// - **Plain text** (`text/plain`): free text, as ``redact(_:)`` reads it.
    /// - **No content type**: JSON when the whole body parses as a JSON object or array.
    ///
    /// Anything else is omitted: a body that is not UTF-8, has another content type (XML, HTML,
    /// binary data), is larger than ``maximumBodySize`` or cannot be parsed completely — cut off,
    /// malformed, nested deeper than 64 levels (see "Limits" in ``SensitiveDataRedactor``) — and a
    /// body that a common server parser (PHP, Werkzeug, Rack, Go, busboy) could split into fields
    /// differently, such as a multipart body with `--boundary` after a bare LF or CR, or a form
    /// with a `;`. The result is then a note such as `[body omitted: 1234 bytes, application/xml]`.
    /// Without a parse that every server agrees with, a secret in it cannot be found reliably.
    ///
    /// - Parameters:
    ///   - body: The body as sent or received.
    ///   - contentType: The value of the `Content-Type` header, if there is one.
    /// - Returns: The body as text with its sensitive data hidden, or a line that says it was
    ///   omitted. An empty body returns an empty string.
    public func redact(body: Data, contentType: String?) -> String {
        guard !body.isEmpty else { return "" }
        let mediaType = contentType.flatMap(MediaType.init)
        let described = contentType == nil ? "no content type" : mediaType?.essence ?? "unreadable content type"
        guard body.count <= Self.maximumBodySize else { return Self.omitted(body.count, described) }
        let nesting = Nesting.document(length: Self.scalarCount(body))
        let result = contentType == nil
            ? redactedJSON(body, allowsFragments: false, nesting: nesting)
            : mediaType.flatMap { redacted(body, as: $0, nesting: nesting) }
        return result ?? Self.omitted(body.count, described)
    }

    static func omitted(_ count: Int, _ type: String) -> String {
        "[body omitted: \(count) \(count == 1 ? "byte" : "bytes"), \(type)]"
    }

    /// The number of scalars in UTF-8 bytes: the bytes that do not continue a scalar. Bytes that
    /// are not UTF-8 count as one scalar each, as they would decode to one replacement character.
    static func scalarCount(_ bytes: some Sequence<UInt8>) -> Int {
        bytes.reduce(0) { $0 + ($1 & 0xC0 == 0x80 ? 0 : 1) }
    }

    /// A body of a known type, or nil when it is omitted. `nesting` is the body's own: a body
    /// passed in is ``Nesting/document``, a multipart part one level deeper.
    func redacted(_ body: Data, as type: MediaType, nesting: Nesting) -> String? {
        if type.isMultipartFormData { return redactedMultipart(body, type, nesting: nesting) }
        guard type.isUTF8 else { return nil }
        if type.isJSON { return redactedJSON(body, allowsFragments: true, nesting: nesting) }
        if type.isForm { return redactedForm(body, nesting: nesting) }
        if type.isPlainText { return String(data: body, encoding: .utf8).map { redact($0, nesting: nesting) } }
        return nil
    }

    private func redactedJSON(_ body: Data, allowsFragments: Bool, nesting: Nesting) -> String? {
        guard let text = String(data: body, encoding: .utf8) else { return nil }
        let scalars = Array(text.unicodeScalars)
        guard let document = try? JSONDocument(scalars, allowsFragments: allowsFragments, nesting: nesting) else { return nil }
        let spans = Self.merged(document.secretSpans(using: self, compatibility: CompatibilityText()))
        return spans.isEmpty ? text : Self.replacing(spans, in: scalars)
    }

    // MARK: Forms

    /// Only a body that ``isStrictForm(_:)`` accepts is read, so no server splits it otherwise.
    /// Fields are split at `&` and `=` scalar by scalar, as a server reads the bytes.
    private func redactedForm(_ body: Data, nesting: Nesting) -> String? {
        guard let text = String(data: body, encoding: .utf8), Self.isStrictForm(text) else { return nil }
        var fields: [FormField] = []
        for raw in text.unicodeScalars.split(separator: "&", omittingEmptySubsequences: false) {
            guard let field = FormField(raw) else { return nil }
            fields.append(field)
        }
        let naming = kinds.contains(.secretFields) ? Self.namingFields(fields.map { ($0.name, $0.value) }) : nil
        return fields.indices.map { index in
            redacted(fields[index], hidesValue: naming?.hidesValue(at: index) == true, nesting: nesting)
        }.joined(separator: "&")
    }

    /// The fields of a form or a URL query that name a secret in their value, as
    /// `label=Password&value=…` does (see ``NamingFields``).
    static func namingFields(_ fields: [(name: String, value: String?)]) -> NamingFields {
        NamingFields(fields.map { field in
            (Array(field.name.unicodeScalars), field.value.map { .string(Array($0.unicodeScalars)) } ?? .other)
        }, compatibility: CompatibilityText())
    }

    /// A form field, as sent and decoded: `+` is a space, then percent-decoding as UTF-8.
    private struct FormField {
        let rawName: Substring
        let rawValue: Substring?
        let name: String
        let value: String?

        init?(_ field: Substring.UnicodeScalarView) {
            guard let equals = field.firstIndex(of: "=") else {
                rawName = Substring(field)
                rawValue = nil
                guard let name = SensitiveDataRedactor.formDecoded(rawName) else { return nil }
                self.name = name
                value = nil
                return
            }
            rawName = Substring(field[..<equals])
            let rawValue = Substring(field[field.index(after: equals)...])
            guard let name = SensitiveDataRedactor.formDecoded(rawName), let value = SensitiveDataRedactor.formDecoded(rawValue) else { return nil }
            self.rawValue = rawValue
            self.name = name
            self.value = value
        }
    }

    /// A field is a name, `=` and a value. The name is free text too, since it can hold a field or
    /// a card number of its own (`password%3Dhunter2=x`, `{"password":"…"}` sent as a form); a
    /// field without `=` is free text. The value is hidden when the name hides it or another field
    /// names a secret.
    private func redacted(_ field: FormField, hidesValue: Bool, nesting: Nesting) -> String {
        guard let rawValue = field.rawValue, let value = field.value else {
            return shown(field.name, as: redact(field.name, nesting: nesting), raw: field.rawName)
        }
        let shownName = shown(field.name, as: redactedName(field.name, nesting: nesting), raw: field.rawName)
        if kinds.contains(.secretFields), hidesValue || FieldName.hidesValue(field.name.unicodeScalars) { return shownName + "=" + Self.replacement }
        return shownName + "=" + shown(value, as: redact(value, nesting: nesting), raw: rawValue)
    }

    /// Decoded text after redaction: as sent when nothing was found, encoded again otherwise.
    private func shown(_ text: String, as redacted: String, raw: Substring) -> String {
        redacted == text ? String(raw) : Self.formEncoded(redacted)
    }
}
