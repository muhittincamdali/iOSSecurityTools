import Foundation

/// Multipart bodies, written again part by part from what the parser read.
extension SensitiveDataRedactor {
    /// The part headers whose values are kept, besides the field name and the content type.
    private static let keptPartHeaders: Set<String> = ["content-length", "content-transfer-encoding"]

    /// The transfer encodings that leave the content as it is.
    private static let identityTransferEncodings: Set<String> = ["7bit", "8bit", "binary"]

    /// The body is read only with one plain `boundary` parameter: servers differ in which of
    /// several they take, and in whether they undo the quotes and `\` escapes of a quoted one.
    func redactedMultipart(_ body: Data, _ type: MediaType, nesting: Nesting) -> String? {
        let parameters = type.parameters.filter { $0.name == "boundary" || $0.name == "boundary*" }
        guard parameters.count == 1, let parameter = parameters.first, parameter.name == "boundary", !parameter.isQuoted,
              MultipartBody.isValidBoundary(parameter.value),
              let multipart = MultipartBody(Array(body), boundary: parameter.value)
        else { return nil }
        let boundary = parameter.value
        let naming = kinds.contains(.secretFields) ? Self.namingFields(multipart.parts.map { ($0.name, Self.plainText(of: $0)) }) : nil
        var output = ""
        for (index, part) in multipart.parts.enumerated() {
            output += "--\(boundary)\r\n"
            output += renderedHeaders(of: part, nesting: nesting).map { $0 + "\r\n" }.joined()
            let hidesValue = naming?.hidesValue(at: index) == true
            output += "\r\n" + (hidesValue ? Self.replacement : redactedContent(of: part, nesting: nesting)) + "\r\n"
        }
        return output + "--\(boundary)--"
    }

    /// The disposition with only the field name, read as free text; the content type as
    /// `type/subtype`; other headers by name, their values hidden unless they are kept. A file
    /// name is never written.
    private func renderedHeaders(of part: MultipartBody.Part, nesting: Nesting) -> [String] {
        var lines = ["Content-Disposition: form-data; name=\"\(Self.quotedStringContent(redactedName(part.name, nesting: nesting)))\""]
        if let contentType = part.contentType { lines.append("Content-Type: " + contentType.essence) }
        for header in part.headers {
            let name = header.name.lowercased()
            guard name != "content-disposition", name != "content-type" else { continue }
            let value = header.value.trimmingCharacters(in: .whitespaces)
            lines.append(header.name + ": " + (Self.keptPartHeaders.contains(name) ? redact(value, nesting: nesting) : Self.replacement))
        }
        return lines
    }

    /// The content of a part, read as a body one level inside the multipart body. A part is a
    /// document found in the body, so it takes its length from the reading budget, and is omitted
    /// when the budget does not cover it.
    private func redactedContent(of part: MultipartBody.Part, nesting: Nesting) -> String {
        if kinds.contains(.secretFields), FieldName.hidesValue(part.name.unicodeScalars) { return Self.replacement }
        let defaultType = part.filename == nil ? "text/plain" : "application/octet-stream"
        guard let type = part.contentType ?? MediaType(defaultType) else { return Self.omitted(part.content.count, defaultType) }
        // Servers differ in which of several transfer encodings they read.
        let encodings = part.headers.filter { $0.name.lowercased() == "content-transfer-encoding" }
            .map { $0.value.trimmingCharacters(in: .whitespaces).lowercased() }
        guard part.filename == nil, !type.essence.hasPrefix("multipart/"), encodings.allSatisfy(Self.identityTransferEncodings.contains),
              encodings.count <= 1, let inner = nesting.enteringDocument(), inner.reads(Self.scalarCount(part.content))
        else {
            return Self.omitted(part.content.count, type.essence)
        }
        return redacted(Data(part.content), as: type, nesting: inner) ?? Self.omitted(part.content.count, type.essence)
    }

    /// The content of a field sent as plain text, which may name the field another part holds
    /// (`label` and `value` parts); nil for a file or a part of another type.
    private static func plainText(of part: MultipartBody.Part) -> String? {
        guard part.filename == nil, part.contentType.map(\.isPlainText) ?? true else { return nil }
        return String(bytes: part.content, encoding: .utf8)
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
