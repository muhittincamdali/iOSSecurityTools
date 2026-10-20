/// JSON and URLs written into free text, read with their parsers.
extension FreeTextScanner {
    // MARK: JSON

    /// Whether the byte at `i` opens JSON: `{` before `"` or `}`, or `[` before `{`, `[`, `"` or
    /// `]`, with optional white space between. `[INFO]`, `[1/3]` and `{x}` are not JSON.
    func startsJSON(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        let allowed: ByteSet
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

    private static let objectStarts = ByteSet("\"}")
    private static let arrayStarts = ByteSet("{[\"]")
    private static let jsonWhitespace = ByteSet(" \t\n\r")

    /// JSON in the text, parsed and redacted by the key rule for structured input, whose members
    /// follow the rule for keys in text: the text is cut at the value of the first member whose
    /// name is not on ``SensitiveDataRedactor/allowedTextKeys``, or at the first value that the key
    /// rule hides, whichever comes first (`{"status":200,"user":"bob"}` keeps `"status":200`).
    /// JSON that holds a word naming a secret or one that cannot be read (`["password"]=> "…"`)
    /// cuts the text at its end. JSON that does not parse cannot be read with certainty: the text
    /// is cut at its first bracket. In a text inside a document, JSON one level too many, deeper
    /// than the depth left or longer than the reading budget leaves (see ``ReadingBudget``) hides
    /// the whole text.
    mutating func embeddedJSON() {
        let start = text.offsets[position]
        guard let inner = nesting.enteringDocument() else {
            hideWholeText()
            return
        }
        let document: JSONDocument
        do {
            document = try JSONDocument(source, at: start, nesting: inner, lengthLimit: inner.lengthLeft)
        } catch .tooDeep where nesting.isEmbedded {
            hideWholeText()
            return
        } catch .overBudget where nesting.isEmbedded {
            hideWholeText()
            return
        } catch {
            cut(atByte: position)
            return
        }
        let region = start..<document.root.range.upperBound
        // The reader stopped within what the budget leaves, so this always fits.
        _ = inner.reads(region.count)
        let found = document.secretSpans(using: redactor, compatibility: compatibility)
        let end = text.byteIndex(atOrAfter: region.upperBound)
        let hidden = found.lazy.filter { $0.kind.contains(.secretFields) }.map(\.start).min()
        let unallowed = role == .text ? document.firstValue(underMemberWhere: { !redactor.allowsTextKey($0) }) : nil
        if let first = [hidden, unallowed].compactMap({ $0 }).min() {
            // What the key rule found before the cut stays: the masks of the value detectors.
            record(spans: found.filter { $0.start < first }, region: region)
            cut(atOffset: first)
        } else {
            record(spans: found, region: region)
            if mentionsSecret(in: position..<end) { cut(atByte: valueStart(after: end)) }
        }
        position = end
    }

    // MARK: URLs

    /// The end of a URL with a scheme and `//` that starts at `i` (`https://…`, `redis://…`): up to
    /// white space, a line break, a quote or an angle bracket, without punctuation that ends a
    /// sentence.
    func urlEnd(from i: Int) -> Int? {
        let limit = text.count
        guard ASCII.isLetter(text.bytes[i]), i == 0 || !Self.isSchemeCharacter(text.bytes[i - 1]) else { return nil }
        var k = i + 1
        while k < limit, k - i <= Self.maximumSchemeLength, Self.isSchemeCharacter(text.bytes[k]) { k += 1 }
        guard k + 2 < limit, text.bytes[k] == UInt8(ascii: ":"), text.bytes[k + 1] == UInt8(ascii: "/"), text.bytes[k + 2] == UInt8(ascii: "/") else {
            return nil
        }
        var end = k + 3
        while end < limit, !text.isSpace(end), !text.isLineTerminator(end), !Self.urlEnds.contains(text.bytes[end]) { end += 1 }
        while end > k + 3, Self.trailingPunctuation.contains(text.bytes[end - 1]) { end -= 1 }
        return end
    }

    private static let maximumSchemeLength = 32
    private static let urlEnds = ByteSet("\"'<>`")
    private static let trailingPunctuation = ByteSet(".,;:!?)]}")

    private static func isSchemeCharacter(_ byte: UInt8) -> Bool {
        ASCII.isAlphanumeric(byte) || byte == UInt8(ascii: "+") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
    }

    /// A URL, recorded as ``SensitiveDataRedactor/redact(url:)`` records it. A URL one level too
    /// many, or longer than the reading budget leaves, hides the whole text it is in; in a line
    /// that is not inside a document, only the URL is hidden then.
    mutating func url(to end: Int) {
        let region = text.original(position..<end)
        guard let inner = nesting.enteringDocument(), inner.reads(region.count) else {
            if nesting.isEmbedded {
                hideWholeText()
            } else {
                record(spans: [SensitiveDataRedactor.Span(start: region.lowerBound, end: region.upperBound, kind: .secretFields, replacement: SensitiveDataRedactor.replacement)], region: region)
                position = end
            }
            return
        }
        let written = String(String.UnicodeScalarView(source[region]))
        let redacted = redactor.redactedURL(written, nesting: inner)
        let span = SensitiveDataRedactor.Span(start: region.lowerBound, end: region.upperBound, kind: .secretFields, replacement: redacted)
        record(spans: redacted == written ? [] : [span], region: region)
        position = end
    }
}
