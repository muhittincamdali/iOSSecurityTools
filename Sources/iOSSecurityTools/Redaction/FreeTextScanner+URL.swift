/// URLs written into free text, read with `URLComponents`.
extension FreeTextScanner {
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

    /// A URL, recorded as ``SensitiveDataRedactor/redact(url:)`` records it, up to where it cuts
    /// the text (see ``SensitiveDataRedactor/cutInWrittenURL(_:)``): a URL is never a safe place to
    /// read on from, unless all of it is written and nothing in it is left for the text after it to
    /// complete. A URL one level too many, or longer than the reading budget leaves, hides the
    /// whole text it is in; in a line that is not inside a document, the text is cut at the URL.
    mutating func url(to end: Int) {
        let region = text.original(position..<end)
        guard let inner = nesting.enteringDocument(), inner.reads(region.count) else {
            if nesting.isEmbedded { hideWholeText() } else { cut(atByte: position) }
            return
        }
        let scalars = Array(source[region])
        let urlCut = redactor.cutInWrittenURL(scalars)
        let shown = urlCut?.written ?? scalars.count
        if shown > 0 {
            let written = String(String.UnicodeScalarView(scalars[..<shown]))
            let redacted = redactor.redactedURL(written, nesting: inner)
            let range = region.lowerBound..<(region.lowerBound + shown)
            let span = SensitiveDataRedactor.Span(start: range.lowerBound, end: range.upperBound, kind: .secretFields, replacement: redacted)
            record(spans: redacted == written ? [] : [span], region: range)
        }
        position = end
        guard let urlCut else { return }
        // A cut after the URL starts where a value after it would: past the quotes, brackets,
        // separators and spaces that follow it (`/password: hunter2`).
        cut(atByte: urlCut.cut == scalars.count ? valueStart(after: end) : text.byteIndex(atOrAfter: region.lowerBound + urlCut.cut))
    }
}
