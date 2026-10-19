import Foundation

extension SensitiveDataRedactor {
    /// Returns a URL as text for a log, with its credentials, query values and identifiers hidden.
    ///
    /// The URL is read with `URLComponents`:
    ///
    /// - The user name and password (`user:password@`) and the fragment (`#…`) are never written,
    ///   whatever ``kinds`` holds.
    /// - **Query:** a parameter keeps its value only when its name, decoded, is plain ASCII and on
    ///   ``allowedQueryParameters``, which is empty by default; any other value is
    ///   `[redacted]`, and so is a parameter without `=` that is not on the list. A name that is not
    ///   plain ASCII, or holds a card number, an address or a token, is `[redacted]` as well.
    /// - **Path:** a segment that looks like an identifier or a secret becomes `:id`: a UUID, a
    ///   number of six or more digits, a token of 16 or more letters and digits, a run of 32 or more
    ///   hex or base64 characters, a JSON Web Token, anything the value detectors find, and text
    ///   the free-text rule would change. The segment after one that names a secret is a value
    ///   too and becomes `:id` whatever it looks like (`/pin/4831`, `/token/…/info`). Parameters
    ///   after a `;` are read like query parameters.
    /// - With ``URLDetail/hostOnly`` only the scheme, host and port are written.
    ///
    /// The query and path rules above belong to ``Kinds/secretFields``. Without it the URL is read
    /// the same way, but only the value detectors that ``kinds`` turns on run: a path segment in
    /// which they find something becomes `:id`, and what they find in a decoded query name or
    /// value is replaced and encoded again (`card=%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2+1111`).
    ///
    /// A URL that `URLComponents` cannot parse is written as ``unparsedURL``.
    ///
    /// ```swift
    /// redactor.redact(url: URL(string: "https://bob:pw@example.com/users/12345678/reset?code=x#y")!)
    /// // https://example.com/users/:id/reset?code=[redacted]
    /// ```
    public func redact(url: URL) -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return Self.unparsedURL }
        return redacted(components)
    }

    /// A URL written in text, recorded as ``redact(url:)`` records it.
    func redactedURL(_ text: String) -> String {
        guard let components = URLComponents(string: text) else { return Self.unparsedURL }
        return redacted(components)
    }

    private func redacted(_ components: URLComponents) -> String {
        guard let scheme = components.scheme, let host = components.percentEncodedHost else { return Self.unparsedURL }
        var result = scheme + "://" + host
        if let port = components.port { result += ":\(port)" }
        guard urlDetail == .full else { return result }
        let hidesByName = kinds.contains(.secretFields)
        let path = components.percentEncodedPath
        result += hidesByName ? redacted(path: path) : scanned(path: path)
        if let items = components.percentEncodedQueryItems {
            let parameters = items.map { item in
                hidesByName ? redacted(parameter: item.name, value: item.value) : scanned(parameter: item.name, value: item.value)
            }
            result += "?" + parameters.joined(separator: "&")
        }
        return result
    }

    // MARK: Without secret fields

    /// The path when only the value detectors run: a segment in which they find something, or that
    /// does not decode, becomes `:id`.
    private func scanned(path: String) -> String {
        path.split(separator: "/", omittingEmptySubsequences: false)
            .map { holdsSecret(String($0)) ? Self.identifierPlaceholder : String($0) }
            .joined(separator: "/")
    }

    /// A query parameter when only the value detectors run.
    private func scanned(parameter rawName: String, value rawValue: String?) -> String {
        let name = scanned(rawName)
        return rawValue.map { name + "=" + scanned($0) } ?? name
    }

    /// A percent-encoded query name or value with what the value detectors find in it replaced;
    /// `[redacted]` when it does not decode.
    private func scanned(_ raw: String) -> String {
        guard let decoded = Self.formDecoded(raw) else { return Self.replacement }
        let redacted = redact(decoded)
        return redacted == decoded ? raw : Self.formEncoded(redacted)
    }

    /// The path segment by segment. A segment after one that names a secret or cannot be read
    /// (`/pin/4831`, `/password-reset/…`, `/token/…/info`) is a value, so it becomes `:id`
    /// whatever it looks like.
    private func redacted(path: String) -> String {
        var segments: [String] = []
        var followsLabel = false
        for raw in path.split(separator: "/", omittingEmptySubsequences: false) {
            let segment = String(raw)
            guard !segment.isEmpty else {
                segments.append(segment)
                continue
            }
            segments.append(followsLabel ? Self.identifierPlaceholder : redacted(pathSegment: segment))
            followsLabel = Self.isSecretLabel(segment)
        }
        return segments.joined(separator: "/")
    }

    /// Whether the decoded segment, read as free text, has a word that holds a secret name or
    /// cannot be read; a segment that does not decode counts too.
    private static func isSecretLabel(_ segment: String) -> Bool {
        let name = segment.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
        guard let decoded = name.removingPercentEncoding else { return true }
        return FreeTextScanner.mentionsSecret(Array(decoded.unicodeScalars), compatibility: CompatibilityText())
    }

    /// A path segment, or `:id` when it looks like an identifier or a secret. Parameters after a
    /// `;`, as in `cart;jsessionid=…`, are read like query parameters.
    private func redacted(pathSegment segment: String) -> String {
        let parts = segment.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
        let base = String(parts[0])
        var result = Self.isIdentifierLike(base) || holdsSecret(base) ? Self.identifierPlaceholder : base
        guard parts.count == 2 else { return result }
        let parameters = parts[1].split(separator: ";", omittingEmptySubsequences: false).map { parameter in
            let pair = parameter.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return redacted(parameter: String(pair[0]), value: pair.count == 2 ? String(pair[1]) : nil)
        }
        result += ";" + parameters.joined(separator: ";")
        return result
    }

    /// Whether the decoded segment holds something the free-text rule hides, or does not decode.
    private func holdsSecret(_ segment: String) -> Bool {
        guard let decoded = segment.removingPercentEncoding else { return true }
        return redact(decoded) != decoded
    }

    /// `name=value` from a query or path parameter, both percent-encoded.
    private func redacted(parameter rawName: String, value rawValue: String?) -> String {
        let name = Self.formDecoded(rawName)
        let shownName = name.map { PlainName($0.unicodeScalars) != nil && redactedName($0) == $0 } == true ? rawName : Self.replacement
        let allowed = name.flatMap { FieldName.allowableFold($0.unicodeScalars) }.map(allowedQueryParameters.contains) ?? false
        guard let rawValue else { return allowed ? shownName : Self.replacement }
        guard !rawValue.isEmpty else { return shownName + "=" }
        guard allowed, let value = Self.formDecoded(rawValue) else { return shownName + "=" + Self.replacement }
        let redactedValue = redact(value)
        return shownName + "=" + (redactedValue == value ? rawValue : Self.formEncoded(redactedValue))
    }

    /// Path segments of letters and digits at least this long are treated as tokens.
    static let mixedTokenLength = 16

    /// Whether a decoded path segment is a UUID, a number of six or more digits, a token of 16 or
    /// more letters and digits, or holds something the value detectors find. A segment that does
    /// not decode counts as one too.
    static func isIdentifierLike(_ segment: String) -> Bool {
        guard let decoded = segment.removingPercentEncoding else { return true }
        let scalars = Array(decoded.unicodeScalars)
        guard !scalars.isEmpty else { return false }
        if UUID(uuidString: decoded) != nil { return true }
        let bytes = scalars.map { $0.isASCII ? UInt8($0.value) : CompatibilityText.unreadable }
        if bytes.count >= 6, bytes.allSatisfy(ASCII.isDigit) { return true }
        let isToken = bytes.allSatisfy { ASCII.isAlphanumeric($0) || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_") }
        if isToken, bytes.count >= mixedTokenLength, bytes.contains(where: ASCII.isLetter), bytes.contains(where: ASCII.isDigit) { return true }
        return !SensitiveDataRedactor().detectorSpans(in: NormalizedText(scalars, compatibility: CompatibilityText())).isEmpty
    }

    // MARK: Form encoding

    /// `+` as a space, then percent-decoding as UTF-8; nil for a bad `%` escape or bytes that are
    /// not UTF-8.
    static func formDecoded(_ text: some StringProtocol) -> String? {
        text.replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }

    /// Percent-encodes what form decoding would change, keeping `[` and `]` readable.
    static func formEncoded(_ text: String) -> String {
        var output = ""
        for byte in text.utf8 {
            if ASCII.isAlphanumeric(byte) || "*-._[]".utf8.contains(byte) {
                output.unicodeScalars.append(Unicode.Scalar(byte))
            } else if byte == UInt8(ascii: " ") {
                output += "+"
            } else {
                output += "%" + (byte < 0x10 ? "0" : "") + String(byte, radix: 16, uppercase: true)
            }
        }
        return output
    }
}
