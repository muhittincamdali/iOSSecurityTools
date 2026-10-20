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
    ///   plain ASCII, or holds a card number, an address or a token, is `[redacted]` as well. A
    ///   query that servers could split into fields differently is written as `?[redacted]`, as
    ///   ``redact(body:contentType:)`` describes for forms: one with a `;`, a `%` that does not
    ///   start an escape, or a name spelled two ways.
    /// - **Path:** a segment that looks like an identifier or a secret becomes `:id`: a UUID, a
    ///   number of six or more digits, a token of 16 or more letters and digits, a run of 32 or more
    ///   hex or base64 characters, a JSON Web Token, anything the value detectors find, and text
    ///   the free-text rule would change. The segment after one that names a secret is a value
    ///   too and becomes `:id` whatever it looks like (`/pin/4831`, `/token/…/info`). Parameters
    ///   after a `;` are read like query parameters.
    /// - With ``URLDetail/hostOnly`` only the scheme, host and port are written.
    ///
    /// The query and path rules above, apart from `?[redacted]` for a query servers could split
    /// differently, belong to ``Kinds/secretFields``. Without it the URL is read
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
        return redacted(components, nesting: .document)
    }

    /// A URL written in text, recorded as ``redact(url:)`` records it. `nesting` is the URL's own:
    /// its query values and path segments are read as text inside it.
    func redactedURL(_ text: String, nesting: Nesting) -> String {
        guard let components = URLComponents(string: text) else { return Self.unparsedURL }
        return redacted(components, nesting: nesting)
    }

    private func redacted(_ components: URLComponents, nesting: Nesting) -> String {
        guard let scheme = components.scheme, let host = components.percentEncodedHost else { return Self.unparsedURL }
        var result = scheme + "://" + host
        if let port = components.port { result += ":\(port)" }
        guard urlDetail == .full else { return result }
        let hidesByName = kinds.contains(.secretFields)
        let path = components.percentEncodedPath
        result += hidesByName ? redacted(path: path, nesting: nesting) : scanned(path: path, nesting: nesting)
        if let query = components.percentEncodedQuery, !Self.isStrictForm(query) { return result + "?" + Self.replacement }
        if let items = components.percentEncodedQueryItems {
            let parameters = items.map { item in
                hidesByName
                    ? redacted(parameter: item.name, value: item.value, nesting: nesting)
                    : scanned(parameter: item.name, value: item.value, nesting: nesting)
            }
            result += "?" + parameters.joined(separator: "&")
        }
        return result
    }

    // MARK: Without secret fields

    /// The path when only the value detectors run: a segment in which they find something, or that
    /// does not decode, becomes `:id`.
    private func scanned(path: String, nesting: Nesting) -> String {
        path.split(separator: "/", omittingEmptySubsequences: false)
            .map { holdsSecret(String($0), nesting: nesting) ? Self.identifierPlaceholder : String($0) }
            .joined(separator: "/")
    }

    /// A query parameter when only the value detectors run.
    private func scanned(parameter rawName: String, value rawValue: String?, nesting: Nesting) -> String {
        let name = scanned(rawName, nesting: nesting)
        return rawValue.map { name + "=" + scanned($0, nesting: nesting) } ?? name
    }

    /// A percent-encoded query name or value with what the value detectors find in it replaced;
    /// `[redacted]` when it does not decode.
    private func scanned(_ raw: String, nesting: Nesting) -> String {
        guard let decoded = Self.formDecoded(raw) else { return Self.replacement }
        let redacted = redact(decoded, nesting: nesting)
        return redacted == decoded ? raw : Self.formEncoded(redacted)
    }

    /// The path segment by segment. A segment after one that names a secret or cannot be read
    /// (`/pin/4831`, `/password-reset/…`, `/token/…/info`) is a value, so it becomes `:id`
    /// whatever it looks like. A segment that comes again is not read again.
    private func redacted(path: String, nesting: Nesting) -> String {
        let classifier = SensitiveDataRedactor(self, kinds: .all)
        var readings: [Substring: PathSegmentReading] = [:]
        var segments: [String] = []
        var followsLabel = false
        for segment in path.split(separator: "/", omittingEmptySubsequences: false) {
            guard !segment.isEmpty else {
                segments.append("")
                continue
            }
            let parts = segment.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            let base = parts[0]
            let reading = readings[base] ?? classifier.read(pathSegment: base, nesting: nesting)
            readings[base] = reading
            if followsLabel {
                segments.append(Self.identifierPlaceholder)
            } else {
                let shownBase = reading.hides ? Self.identifierPlaceholder : String(base)
                segments.append(parts.count == 2 ? shownBase + ";" + redacted(pathParameters: parts[1], nesting: nesting) : shownBase)
            }
            followsLabel = reading.isLabel
        }
        return segments.joined(separator: "/")
    }

    /// What a path segment is, from one reading of it.
    private struct PathSegmentReading {
        /// It looks like an identifier or holds a secret, so it becomes `:id`.
        let hides: Bool
        /// It has a word that names a secret or cannot be read, so the segment after it is a value.
        let isLabel: Bool
    }

    /// Reads a path segment, without its parameters, once: it is decoded and scanned a single
    /// time, and the free-text rule, every value detector and the word reading all run on that
    /// scan. A segment that does not decode is both.
    private func read(pathSegment segment: Substring, nesting: Nesting) -> PathSegmentReading {
        guard let decoded = segment.removingPercentEncoding else { return PathSegmentReading(hides: true, isLabel: true) }
        let scalars = Array(decoded.unicodeScalars)
        guard !scalars.isEmpty else { return PathSegmentReading(hides: false, isLabel: false) }
        let isIdentifier = UUID(uuidString: decoded) != nil || Self.isIdentifierShaped(scalars)
        guard !Self.isQuietWord(scalars) else { return PathSegmentReading(hides: isIdentifier, isLabel: false) }
        let compatibility = CompatibilityText()
        let text = NormalizedText(scalars, compatibility: compatibility)
        let holdsSecret = !textSpans(in: scalars, text: text, compatibility: compatibility, nesting: nesting, detectsInRegions: true).isEmpty
        let isLabel = FreeTextScanner.mentionsSecret(scalars, text: text, compatibility: compatibility)
        return PathSegmentReading(hides: isIdentifier || holdsSecret, isLabel: isLabel)
    }

    /// Parameters after a `;` in a path segment (`cart;jsessionid=…`), read like query parameters.
    private func redacted(pathParameters: Substring, nesting: Nesting) -> String {
        pathParameters.split(separator: ";", omittingEmptySubsequences: false).map { parameter in
            let pair = parameter.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return redacted(parameter: String(pair[0]), value: pair.count == 2 ? String(pair[1]) : nil, nesting: nesting)
        }.joined(separator: ";")
    }

    /// Whether the decoded segment holds something the free-text rule hides, or does not decode.
    private func holdsSecret(_ segment: String, nesting: Nesting) -> Bool {
        guard let decoded = segment.removingPercentEncoding else { return true }
        return redact(decoded, nesting: nesting) != decoded
    }

    /// `name=value` from a query or path parameter, both percent-encoded.
    private func redacted(parameter rawName: String, value rawValue: String?, nesting: Nesting) -> String {
        let name = Self.formDecoded(rawName)
        let shownName = name.map { PlainName($0.unicodeScalars) != nil && redactedName($0, nesting: nesting) == $0 } == true ? rawName : Self.replacement
        let allowed = name.flatMap { FieldName.allowableFold($0.unicodeScalars) }.map(allowedQueryParameters.contains) ?? false
        guard let rawValue else { return allowed ? shownName : Self.replacement }
        guard !rawValue.isEmpty else { return shownName + "=" }
        guard allowed, let value = Self.formDecoded(rawValue) else { return shownName + "=" + Self.replacement }
        let redactedValue = redact(value, nesting: nesting)
        return shownName + "=" + (redactedValue == value ? rawValue : Self.formEncoded(redactedValue))
    }

    /// Path segments of letters and digits at least this long are treated as tokens.
    static let mixedTokenLength = 16

    /// Whether a decoded path segment is a number of six or more digits or a token of 16 or more
    /// letters, digits, `-` and `_` with both letters and digits.
    private static func isIdentifierShaped(_ scalars: [Unicode.Scalar]) -> Bool {
        guard scalars.allSatisfy(\.isASCII) else { return false }
        let bytes = scalars.map { UInt8($0.value) }
        if bytes.count >= 6, bytes.allSatisfy(ASCII.isDigit) { return true }
        let isToken = bytes.allSatisfy { ASCII.isAlphanumeric($0) || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_") }
        return isToken && bytes.count >= mixedTokenLength && bytes.contains(where: ASCII.isLetter) && bytes.contains(where: ASCII.isDigit)
    }

    // MARK: Form encoding

    /// Whether common servers all split a form body or URL query into the same fields with the
    /// same names. Every character is printable ASCII other than `;`, every `%` starts an escape of
    /// two hex digits, and no two fields spell one name differently. Each rule closes a split that
    /// some server makes differently: Rack, Python before 3.9.2 and Go before 1.17 also split at
    /// `;`; Rack drops spaces after a separator; servers keep, drop or reject a bare `%`; and PHP
    /// reads `a.b`, `a b` and `a_b` as one name, which decoding (`pass%77ord`) and case can
    /// also make one.
    static func isStrictForm(_ text: String) -> Bool {
        let scalars = Array(text.unicodeScalars)
        for (i, scalar) in scalars.enumerated() {
            guard (0x21...0x7E).contains(scalar.value), scalar != ";" else { return false }
            guard scalar == "%" else { continue }
            guard i + 2 < scalars.count, scalars[(i + 1)...(i + 2)].allSatisfy(\.properties.isASCIIHexDigit) else { return false }
        }
        var spellings: [String: Substring] = [:]
        for field in text.unicodeScalars.split(separator: "&") {
            let rawName = Substring(field.prefix { $0 != "=" })
            guard let name = formDecoded(rawName) else { return false }
            let folded: [Unicode.Scalar] = name.unicodeScalars.drop { $0 == " " }.map { $0 == " " || $0 == "." ? "_" : $0 }
            let serverName = String(String.UnicodeScalarView(folded)).lowercased()
            if let earlier = spellings.updateValue(rawName, forKey: serverName), earlier != rawName { return false }
        }
        return true
    }

    /// `+` as a space, then percent-decoding as UTF-8; nil for a bad `%` escape or bytes that are
    /// not UTF-8. `+` is replaced scalar by scalar: `replacingOccurrences` compares characters and
    /// leaves a `+` that a combining mark follows.
    static func formDecoded(_ text: some StringProtocol) -> String? {
        let spaced = text.unicodeScalars.map { $0 == "+" ? " " : $0 }
        return String(String.UnicodeScalarView(spaced)).removingPercentEncoding
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
