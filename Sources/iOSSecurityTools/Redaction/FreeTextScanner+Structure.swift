/// JSON and URLs written into free text, read with their parsers.
extension FreeTextScanner {
    // MARK: JSON

    /// Whether the byte at `i` opens JSON: `{` before `"` or `}`, or `[` before `{`, `[`, `"` or
    /// `]`, with optional white space between. `[INFO]`, `[1/3]` and `{x}` are not JSON.
    func startsJSON(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        let allowed: Set<UInt8>
        if byte == UInt8(ascii: "{") {
            allowed = Self.objectStarts
        } else if byte == UInt8(ascii: "[") {
            allowed = Self.arrayStarts
        } else {
            return false
        }
        var k = i + 1
        while k < text.count, Self.jsonWhitespace.contains(text.bytes[k]) { k += 1 }
        return k < text.count && allowed.contains(text.bytes[k])
    }

    private static let objectStarts: Set<UInt8> = Set("\"}".utf8)
    private static let arrayStarts: Set<UInt8> = Set("{[\"]".utf8)
    private static let jsonWhitespace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D]

    /// JSON in a line, parsed and redacted by the key rule for structured input. JSON that does
    /// not parse cannot be read with certainty and is hidden.
    mutating func embeddedJSON(lineEnd: Int) {
        let start = text.offsets[position]
        guard let document = JSONDocument(source, at: start) else {
            hideUnparsedJSON(from: position, lineEnd: lineEnd)
            return
        }
        let region = start..<document.root.range.upperBound
        record(spans: document.secretSpans(using: redactor, compatibility: compatibility), region: region)
        position = text.byteIndex(atOrAfter: region.upperBound)
    }

    /// Hides JSON that does not parse: to the end of its line, and on over the lines below until
    /// its brackets close, outside strings, or to the end of the text.
    mutating func hideUnparsedJSON(from start: Int, lineEnd: Int) {
        let end = max(bracketsClose(from: start), lineEnd)
        let stopsOnLine = end == lineEnd
        hide(text.offset(at: start)..<text.offset(at: end))
        position = stopsOnLine ? lineEnd : end
        guard stopsOnLine else { return }
        carry = carryAfterHiding(from: start, valueStart: start, lineEnd: lineEnd, indent: lineIndent)
    }

    /// The byte after the bracket that closes the one at `start`, counting brackets outside
    /// double-quoted strings; a string ends at its closing quote or its line.
    private func bracketsClose(from start: Int) -> Int {
        var depth = 0
        var inString = false
        var k = start
        while k < text.count {
            let byte = text.bytes[k]
            if inString {
                if byte == UInt8(ascii: "\"") && !isEscaped(k) || text.isLineTerminator(k) { inString = false }
            } else if byte == UInt8(ascii: "\"") {
                inString = true
            } else if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") {
                depth += 1
            } else if byte == UInt8(ascii: "}") || byte == UInt8(ascii: "]") {
                depth -= 1
                if depth == 0 { return k + 1 }
            }
            k += 1
        }
        return text.count
    }

    // MARK: URLs

    /// The end of a URL with a scheme and `//` that starts at `i` (`https://…`, `redis://…`): up to
    /// white space, a quote or an angle bracket, without punctuation that ends a sentence.
    func urlEnd(from i: Int, lineEnd: Int) -> Int? {
        guard ASCII.isLetter(text.bytes[i]), i == 0 || !Self.isSchemeCharacter(text.bytes[i - 1]) else { return nil }
        var k = i + 1
        while k < lineEnd, k - i <= Self.maximumSchemeLength, Self.isSchemeCharacter(text.bytes[k]) { k += 1 }
        guard k + 2 < lineEnd, text.bytes[k] == UInt8(ascii: ":"), text.bytes[k + 1] == UInt8(ascii: "/"), text.bytes[k + 2] == UInt8(ascii: "/") else {
            return nil
        }
        var end = k + 3
        while end < lineEnd, !text.isSpace(end), !Self.urlEnds.contains(text.bytes[end]) { end += 1 }
        while end > k + 3, Self.trailingPunctuation.contains(text.bytes[end - 1]) { end -= 1 }
        return end
    }

    private static let maximumSchemeLength = 32
    private static let urlEnds: Set<UInt8> = Set("\"'<>`".utf8)
    private static let trailingPunctuation: Set<UInt8> = Set(".,;:!?)]}".utf8)

    private static func isSchemeCharacter(_ byte: UInt8) -> Bool {
        ASCII.isAlphanumeric(byte) || byte == UInt8(ascii: "+") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
    }

    /// A URL, recorded as ``SensitiveDataRedactor/redact(url:)`` records it.
    mutating func url(to end: Int) {
        let region = text.original(position..<end)
        let written = String(String.UnicodeScalarView(source[region]))
        let redacted = redactor.redactedURL(written)
        let span = SensitiveDataRedactor.Span(start: region.lowerBound, end: region.upperBound, kind: .secretFields, replacement: redacted)
        record(spans: redacted == written ? [] : [span], region: region)
        position = end
    }
}
