import Foundation

/// Multipart bodies, written again part by part from what the parser read.
extension SensitiveDataRedactor {
    /// The part headers whose values are written, each by its shape (see
    /// ``shownValue(ofPartHeader:_:)``), besides the field name and the content type.
    private static let keptPartHeaders: Set<String> = ["content-length", "content-transfer-encoding"]

    /// The names of the other part headers that are written; any other name is a key that is not
    /// allowed, so it is written as `[redacted]` with its value.
    private static let namedPartHeaders: Set<String> = keptPartHeaders.union([
        "content-description", "content-encoding", "content-id", "content-language", "content-location",
    ])

    /// The transfer encodings of MIME (RFC 2045 §6.1): the only values of
    /// `Content-Transfer-Encoding` that are written.
    private static let transferEncodingNames: Set<String> = ["7bit", "8bit", "binary", "base64", "quoted-printable"]

    /// The transfer encodings that leave the content as it is.
    private static let identityTransferEncodings: Set<String> = ["7bit", "8bit", "binary"]

    /// The body is read only with one plain `boundary` parameter: servers differ in which of
    /// several they take, and in whether they undo the quotes and `\` escapes of a quoted one.
    func redactedMultipart(_ body: Data, _ type: MediaType, nesting: Nesting, compatibility: CompatibilityText) -> String? {
        let parameters = type.parameters.filter { $0.name == "boundary" || $0.name == "boundary*" }
        guard parameters.count == 1, let parameter = parameters.first, parameter.name == "boundary", !parameter.isQuoted,
              MultipartBody.isValidBoundary(parameter.value),
              let multipart = MultipartBody(Array(body), boundary: parameter.value)
        else { return nil }
        let boundary = parameter.value
        let naming = kinds.contains(.secretFields) ? NamingFields(multipart.parts.lazy.map(Self.namingField), compatibility: compatibility) : nil
        var output = ""
        for (index, part) in multipart.parts.enumerated() {
            output += "--\(boundary)\r\n"
            output += renderedHeaders(of: part, nesting: nesting, compatibility: compatibility).map { $0 + "\r\n" }.joined()
            let hidesValue = naming?.hidesValue(at: index, of: Self.namingField(part)) == true
            output += "\r\n" + (hidesValue ? Self.replacement : redactedContent(of: part, nesting: nesting, compatibility: compatibility)) + "\r\n"
        }
        return output + "--\(boundary)--"
    }

    /// The disposition with only the field name, read as free text; the content type as
    /// `type/subtype`; other headers by name when the name is one of ``namedPartHeaders`` and as
    /// `[redacted]` otherwise, their values hidden unless they are kept, and then written by their
    /// shape. A file name is never written. Header names are keys of the part: a name outside the
    /// list, such as one that holds a card number or a token, is never written.
    private func renderedHeaders(of part: MultipartBody.Part, nesting: Nesting, compatibility: CompatibilityText) -> [String] {
        let fieldName = redactedName(part.name, nesting: nesting, compatibility: compatibility)
        var lines = ["Content-Disposition: form-data; name=\"\(Self.quotedStringContent(fieldName))\""]
        if let contentType = part.contentType { lines.append("Content-Type: " + contentType.essence) }
        for header in part.headers {
            let name = header.name.lowercased()
            guard name != "content-disposition", name != "content-type" else { continue }
            let shownName = Self.namedPartHeaders.contains(name) ? header.name : Self.replacement
            lines.append(shownName + ": " + (Self.keptPartHeaders.contains(name) ? Self.shownValue(ofPartHeader: name, header.value) : Self.replacement))
        }
        return lines
    }

    /// The value written for a kept part header, by its shape alone: a `Content-Length` of one to
    /// ``quietWordLength`` ASCII digits as it is, and a `Content-Transfer-Encoding` that is one of
    /// ``transferEncodingNames`` in lowercase, without the white space around them. Any other value
    /// is ``replacement``. The value is not read as free text, where a value that no rule finds
    /// was written as it is (`Content-Length: 12 hunter2`, `Content-Transfer-Encoding: hunter2`).
    /// No value detector finds anything in a word of twelve digits (the shortest card number has
    /// 13), so a card number written as a length does not show, and no part of a terabyte is in a
    /// body that is read.
    private static func shownValue(ofPartHeader name: String, _ value: String) -> String {
        guard name == "content-length" else { return transferEncoding(value) ?? replacement }
        let digits = value.trimmingCharacters(in: .whitespaces)
        guard (1...quietWordLength).contains(digits.utf8.count), digits.utf8.allSatisfy(ASCII.isDigit) else { return replacement }
        return digits
    }

    /// The transfer encoding a `Content-Transfer-Encoding` value names, lowercased: one of
    /// ``transferEncodingNames`` in ASCII letters of either case, with white space around it; nil
    /// for any other value. The same reading decides what is written and whether the content is
    /// read.
    private static func transferEncoding(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard trimmed.utf8.allSatisfy({ $0 < 0x80 }) else { return nil }
        let name = String(decoding: trimmed.utf8.map(ASCII.lowercased), as: UTF8.self)
        return transferEncodingNames.contains(name) ? name : nil
    }

    /// The content of a part, read as a body one level inside the multipart body. A part is a
    /// document found in the body, so it takes its length from the reading budget, and is omitted
    /// when the budget does not cover it.
    private func redactedContent(of part: MultipartBody.Part, nesting: Nesting, compatibility: CompatibilityText) -> String {
        if kinds.contains(.secretFields), FieldName.hidesValue(part.name.unicodeScalars) { return Self.replacement }
        let defaultType = part.filename == nil ? "text/plain" : "application/octet-stream"
        guard let type = part.contentType ?? MediaType(defaultType) else { return Self.omitted(part.content.count, defaultType) }
        let encodings = Self.transferEncodings(of: part)
        guard part.filename == nil, !type.essence.hasPrefix("multipart/"), Self.keepsContent(encodings),
              let inner = nesting.enteringDocument(), inner.reads(Self.scalarCount(part.content))
        else {
            return Self.omitted(part.content.count, type.essence)
        }
        return redacted(Data(part.content), as: type, nesting: inner, compatibility: compatibility) ?? Self.omitted(part.content.count, type.essence)
    }

    /// The parts that name the field another part holds (`label` and `value` parts). A part's
    /// content is read as a name only when it is plain UTF-8 text without a transfer encoding;
    /// any other content of a part that holds a name (`label` in base64, as JSON, in another
    /// charset, as a file) cannot be read as one, so it counts as naming a secret, as an array or
    /// object does in JSON.
    private static func namingField(_ part: MultipartBody.Part) -> NamingFields.Field {
        let value: NamingFields.Value = plainText(of: part).map { .string(Array($0.unicodeScalars)) } ?? .structure
        return (Array(part.name.unicodeScalars), value)
    }

    /// The content of a field sent as plain UTF-8 text without a transfer encoding; nil for a
    /// file, a part of another type or charset, or encoded content.
    private static func plainText(of part: MultipartBody.Part) -> String? {
        guard part.filename == nil, part.contentType.map(\.isPlainText) ?? true, part.contentType?.isUTF8 ?? true else { return nil }
        guard keepsContent(transferEncodings(of: part)) else { return nil }
        return String(bytes: part.content, encoding: .utf8)
    }

    /// The transfer encodings a part names (see ``transferEncoding(_:)``), nil for a value that
    /// names none; servers differ in which of several they read.
    private static func transferEncodings(of part: MultipartBody.Part) -> [String?] {
        part.headers.filter { $0.name.lowercased() == "content-transfer-encoding" }.map { transferEncoding($0.value) }
    }

    /// Whether the transfer encodings of a part leave its content as it is: at most one, and that
    /// one `7bit`, `8bit` or `binary`.
    private static func keepsContent(_ encodings: [String?]) -> Bool {
        encodings.count <= 1 && encodings.allSatisfy { $0.map(identityTransferEncodings.contains) == true }
    }

    /// The text with `"` and `\` escaped, for a quoted header parameter.
    private static func quotedStringContent(_ text: String) -> String {
        var escaped = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if scalar == "\"" || scalar == "\\" { escaped.append("\\") }
            escaped.append(scalar)
        }
        return String(escaped)
    }
}
