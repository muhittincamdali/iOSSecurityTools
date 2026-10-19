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
    ///   `=`, Unicode scalar by scalar as a server reads the bytes (also where a combining mark
    ///   follows), and names and values are decoded (`+` is a space, then percent-decoding as
    ///   UTF-8).
    ///   A field whose decoded name hides its value shows `name=[redacted]`; other values, names
    ///   and fields without `=` are read as free text.
    /// - **Multipart form data**: every part is written again with its field name and its
    ///   `type/subtype`; other part headers show `[redacted]` unless they are
    ///   `Content-Length` or `Content-Transfer-Encoding`. A part whose name hides its value
    ///   shows `[redacted]`, and any other part is read by its own content type (`text/plain`
    ///   when it has none). Uploaded files, nested multipart bodies, parts in a transfer encoding
    ///   other than `7bit`, `8bit` or `binary` and parts of other types are omitted like a body.
    /// - **Plain text** (`text/plain`): free text, as ``redact(_:)`` reads it.
    /// - **No content type**: JSON when the whole body parses as a JSON object or array.
    ///
    /// Anything else is omitted: a body that is not UTF-8, has another content type (XML, HTML,
    /// binary data), is larger than ``maximumBodySize`` or cannot be parsed completely — cut off,
    /// malformed, nested deeper than 256 levels, a multipart body servers could split differently.
    /// The result is then a note such as `[body omitted: 1234 bytes, application/xml]`. Without a
    /// parse, a secret in it cannot be found reliably.
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
        let result = contentType == nil ? redactedJSON(body, allowsFragments: false) : mediaType.flatMap { redacted(body, as: $0) }
        return result ?? Self.omitted(body.count, described)
    }

    static func omitted(_ count: Int, _ type: String) -> String {
        "[body omitted: \(count) \(count == 1 ? "byte" : "bytes"), \(type)]"
    }

    func redacted(_ body: Data, as type: MediaType) -> String? {
        if type.isMultipartFormData { return redactedMultipart(body, type) }
        guard type.isUTF8 else { return nil }
        if type.isJSON { return redactedJSON(body, allowsFragments: true) }
        if type.isForm { return redactedForm(body) }
        if type.isPlainText { return String(data: body, encoding: .utf8).map(redact) }
        return nil
    }

    private func redactedJSON(_ body: Data, allowsFragments: Bool) -> String? {
        guard let text = String(data: body, encoding: .utf8) else { return nil }
        let scalars = Array(text.unicodeScalars)
        guard let document = JSONDocument(scalars, allowsFragments: allowsFragments) else { return nil }
        let spans = Self.merged(document.secretSpans(using: self, compatibility: CompatibilityText()))
        return spans.isEmpty ? text : Self.replacing(spans, in: scalars)
    }

    // MARK: Forms

    /// Fields are split at `&` and `=` scalar by scalar, as a server reads the bytes: split by
    /// `Character`, `&` or `=` followed by a combining mark would be one character and no
    /// delimiter, and `note=hi&\u{301}status=hunter2` would read as one field.
    private func redactedForm(_ body: Data) -> String? {
        guard let text = String(data: body, encoding: .utf8) else { return nil }
        var fields: [String] = []
        for field in text.unicodeScalars.split(separator: "&", omittingEmptySubsequences: false) {
            guard let redacted = redactedFormField(field) else { return nil }
            fields.append(redacted)
        }
        return fields.joined(separator: "&")
    }

    /// A field is a name, `=` and a value. The name is free text too, since it can hold a field or
    /// a card number of its own (`password%3Dhunter2=x`, `{"password":"…"}` sent as a form); a
    /// field without `=` is free text.
    private func redactedFormField(_ field: Substring.UnicodeScalarView) -> String? {
        guard let equals = field.firstIndex(of: "=") else {
            let raw = Substring(field)
            guard let text = Self.formDecoded(raw) else { return nil }
            return shown(text, as: redact(text), raw: raw)
        }
        let rawName = Substring(field[..<equals])
        let rawValue = Substring(field[field.index(after: equals)...])
        guard let name = Self.formDecoded(rawName), let value = Self.formDecoded(rawValue) else { return nil }
        let shownName = shown(name, as: redactedName(name), raw: rawName)
        if kinds.contains(.secretFields), FieldName.hidesValue(name.unicodeScalars) { return shownName + "=" + Self.replacement }
        return shownName + "=" + shown(value, as: redact(value), raw: rawValue)
    }

    /// Decoded text after redaction: as sent when nothing was found, encoded again otherwise.
    private func shown(_ text: String, as redacted: String, raw: Substring) -> String {
        redacted == text ? String(raw) : Self.formEncoded(redacted)
    }
}
