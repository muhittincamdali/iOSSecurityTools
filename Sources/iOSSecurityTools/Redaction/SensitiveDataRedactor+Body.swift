import Foundation

extension SensitiveDataRedactor {
    /// Returns a request or response body as text with its sensitive data hidden, for a log.
    ///
    /// The body is read with a parser chosen by its content type:
    ///
    /// - **JSON** (`application/json`, `text/json`, `…+json`): read as ``SensitiveDataRedactor``
    ///   describes under "Structured text". A hidden string keeps its quotes; any other hidden
    ///   value becomes the string `"[redacted]"`, so the output is still JSON.
    /// - **Forms** (`application/x-www-form-urlencoded`): fields are split at `&` and at the first
    ///   `=`, and names and values are decoded (`+` is a space, then percent-decoding as UTF-8).
    ///   A field whose decoded name hides its value shows `name=[redacted]`. Servers that also
    ///   split at `;` read `a=1;password=…` as two fields, so the value of a field with a
    ///   `;`-separated piece whose name hides it is hidden too. A value that is kept is redacted
    ///   as text.
    /// - **Multipart form data**: every part is read by its own content type (`text/plain` when
    ///   it has none and no file name) and a part whose `name` hides its value shows
    ///   `[redacted]`. Uploaded files and parts of other types are omitted like a body.
    /// - **Plain text** (`text/plain`): the free-text rule.
    /// - **No content type**: JSON when the whole body parses as JSON, otherwise a form when it
    ///   parses as one.
    ///
    /// A body that is not UTF-8, has another content type (XML, HTML, binary data) or cannot be
    /// parsed completely — cut off, malformed, nested deeper than 256 levels, a multipart body
    /// servers could split differently — is omitted: `[body omitted: 1234 bytes, application/xml]`.
    /// Without a parse, a secret in it cannot be found reliably.
    ///
    /// - Parameters:
    ///   - body: The body as sent or received.
    ///   - contentType: The value of the `Content-Type` header, if there is one.
    /// - Returns: The body as text with its sensitive data hidden, or a line that says it was
    ///   omitted. An empty body returns an empty string.
    public func redact(body: Data, contentType: String?) -> String {
        guard !body.isEmpty else { return "" }
        guard let contentType else {
            return redactedJSON(body) ?? redactedForm(body, requiresFormShape: true) ?? Self.omitted(body.count, "no content type")
        }
        guard let mediaType = MediaType(contentType) else { return Self.omitted(body.count, "unreadable content type") }
        return redacted(body, as: mediaType) ?? Self.omitted(body.count, mediaType.essence)
    }

    static func omitted(_ count: Int, _ type: String) -> String {
        "[body omitted: \(count) \(count == 1 ? "byte" : "bytes"), \(type)]"
    }

    private func redacted(_ body: Data, as type: MediaType) -> String? {
        if type.isMultipartFormData { return redactedMultipart(body, type) }
        guard type.isUTF8 else { return nil }
        if type.isJSON { return redactedJSON(body) }
        if type.isForm { return redactedForm(body, requiresFormShape: false) }
        if type.isPlainText { return String(data: body, encoding: .utf8).map(redact) }
        return nil
    }

    private func redactedJSON(_ body: Data) -> String? {
        guard let text = String(data: body, encoding: .utf8) else { return nil }
        let scalars = Array(text.unicodeScalars)
        guard let document = JSONDocument(scalars, allowsFragments: true) else { return nil }
        let spans = spans(in: scalars, compatibility: CompatibilityText(), document: document)
        return spans.isEmpty ? text : Self.replacing(spans, in: scalars)
    }

    // MARK: Forms

    /// - Parameter requiresFormShape: For a body without a content type: only text with an `=`
    ///   and without whitespace or control characters is read as a form.
    private func redactedForm(_ body: Data, requiresFormShape: Bool) -> String? {
        guard let text = String(data: body, encoding: .utf8) else { return nil }
        if requiresFormShape {
            guard text.contains("="), !text.unicodeScalars.contains(where: { $0.properties.isWhitespace || $0.value < 0x20 }) else { return nil }
        }
        var fields: [String] = []
        for field in text.split(separator: "&", omittingEmptySubsequences: false) {
            guard let redacted = redactedFormField(field) else { return nil }
            fields.append(redacted)
        }
        return fields.joined(separator: "&")
    }

    private func redactedFormField(_ field: Substring) -> String? {
        guard let equals = field.firstIndex(of: "=") else { return Self.formDecoded(field) == nil ? nil : String(field) }
        let rawName = field[..<equals]
        guard let name = Self.formDecoded(rawName), let value = Self.formDecoded(field[field.index(after: equals)...]) else { return nil }
        var hides = false
        if kinds.contains(.secretFields) {
            hides = FieldName.hidesValue(name.unicodeScalars)
            for piece in field.split(separator: ";").dropFirst() {
                guard let pieceEquals = piece.firstIndex(of: "=") else { continue }
                guard let pieceName = Self.formDecoded(piece[..<pieceEquals]) else { return nil }
                hides = hides || FieldName.hidesValue(pieceName.unicodeScalars)
            }
        }
        if hides { return rawName + "=" + Self.replacement }
        let redacted = redact(value)
        return redacted == value ? String(field) : rawName + "=" + Self.formEncoded(redacted)
    }

    /// `+` as a space, then percent-decoding as UTF-8; nil for a bad `%` escape or bytes that are
    /// not UTF-8.
    private static func formDecoded(_ text: Substring) -> String? {
        text.replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }

    /// Percent-encodes what form decoding would change, keeping `[` and `]` readable.
    private static func formEncoded(_ text: String) -> String {
        var output = ""
        for byte in text.utf8 {
            if ASCII.isAlphanumeric(byte) || "*-._[]".utf8.contains(byte) {
                output.unicodeScalars.append(Unicode.Scalar(byte))
            } else if byte == UInt8(ascii: " ") {
                output += "+"
            } else {
                output += "%" + String(byte, radix: 16, uppercase: true).leftPadded(to: 2)
            }
        }
        return output
    }

    // MARK: Multipart

    private func redactedMultipart(_ body: Data, _ type: MediaType) -> String? {
        let boundaries = type.values(of: "boundary")
        guard boundaries.count == 1, let boundary = boundaries.first, MultipartBody.isValidBoundary(boundary),
              !type.parameters.contains(where: { $0.name == "boundary*" }),
              let multipart = MultipartBody(Array(body), boundary: boundary)
        else { return nil }
        var output = ""
        for part in multipart.parts {
            output += "--\(boundary)\r\n"
            if !part.headers.isEmpty { output += redact(part.headers) + "\r\n" }
            output += "\r\n" + redactedContent(of: part) + "\r\n"
        }
        return output + "--\(boundary)--"
    }

    private func redactedContent(of part: MultipartBody.Part) -> String {
        if kinds.contains(.secretFields), FieldName.hidesValue(part.name.unicodeScalars) { return Self.replacement }
        let defaultType = part.filename == nil ? "text/plain" : "application/octet-stream"
        guard let type = part.contentType ?? MediaType(defaultType) else { return Self.omitted(part.content.count, defaultType) }
        guard part.filename == nil, !type.essence.hasPrefix("multipart/") else { return Self.omitted(part.content.count, type.essence) }
        return redacted(Data(part.content), as: type) ?? Self.omitted(part.content.count, type.essence)
    }
}

private extension String {
    func leftPadded(to length: Int) -> String {
        String(repeating: "0", count: max(0, length - count)) + self
    }
}
