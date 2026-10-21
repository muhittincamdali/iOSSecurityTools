/// URLs written into free text.
///
/// A URL in free text is not read on its own terms: it is shown only when it is clean (see
/// ``isCleanURL(to:)``), and any other URL cuts the text where it starts. Earlier designs read
/// the query, fragment and path parameters of a URL in text and kept the text after it when they
/// looked complete; reviews got values past every version of that reading, one ending at a time.
extension FreeTextScanner {
    /// The end of a URL with a scheme and `//` that starts at `i` (`https://…`, `redis://…`): up to
    /// white space, a line break, a quote, an angle bracket, a backtick or ``scanEnd``, without
    /// the punctuation that ends a sentence. A URL never runs past ``scanEnd``, so the character
    /// that cuts the text there is never inside it.
    func urlEnd(from i: Int) -> Int? {
        let limit = scanEnd
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

    /// The URL from ``position`` to byte `end`. A clean URL is recorded as
    /// ``SensitiveDataRedactor/redact(url:)`` records it, so a path segment that looks like an
    /// identifier becomes `:id`, and the text after it is read on. Any other URL cuts the text
    /// where it starts. A clean URL one level too many, or longer than the reading budget leaves,
    /// hides the whole text it is in when the text is inside a document, and cuts it at the URL
    /// otherwise.
    mutating func url(to end: Int) {
        guard isCleanURL(to: end) else {
            cut(atByte: position)
            return
        }
        let region = text.original(position..<end)
        guard let inner = nesting.enteringDocument(), inner.reads(region.count) else {
            if nesting.isEmbedded { hideWholeText() } else { cut(atByte: position) }
            return
        }
        let written = String(String.UnicodeScalarView(source[region]))
        let redacted = redactor.redactedURL(written, nesting: inner)
        let span = SensitiveDataRedactor.Span(start: region.lowerBound, end: region.upperBound, kind: .secretFields, replacement: redacted)
        record(spans: redacted == written ? [] : [span], region: region)
        position = end
    }

    /// Whether the URL from ``position`` to byte `end` is clean, so that it is shown:
    ///
    /// - it is `scheme://host` with an optional path, at most ``longestWord`` characters long;
    /// - after the scheme it holds only the ASCII letters, digits, `.`, `_`, `-` and `/`, so no
    ///   `?`, `#`, `;`, `%`, `=`, `:`, `@`, `\` and no letter, mark or digit outside ASCII;
    /// - the host is a name of ASCII labels or an IPv4 address in which the value detectors find
    ///   nothing (see ``SensitiveDataRedactor/showsHost(_:)``);
    /// - neither the host nor any path segment names a secret by the key rule
    ///   (``FieldName/hidesValue(_:)``), which also hides a segment without a letter or digit;
    /// - it ends cleanly (see ``endsCleanly(at:)``), and not at the character outside the safe
    ///   alphabet where the scan ends.
    private func isCleanURL(to end: Int) -> Bool {
        if end == scanEnd, scanEnd < text.count { return false }
        guard endsCleanly(at: end) else { return false }
        let range = position..<end
        guard !isOpaque(range) else { return false }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(range.count)
        for scalar in source[text.original(range)] {
            guard scalar.isASCII else { return false }
            bytes.append(UInt8(scalar.value))
        }
        guard let colon = bytes.firstIndex(of: UInt8(ascii: ":")), bytes[..<colon].allSatisfy(Self.isSchemeCharacter),
              bytes[colon...].starts(with: "://".utf8)
        else { return false }
        let rest = bytes[(colon + 3)...]
        guard rest.allSatisfy(Self.isCleanURLCharacter) else { return false }
        let host = rest.prefix { $0 != UInt8(ascii: "/") }
        guard !host.isEmpty, redactor.showsHost(String(decoding: host, as: UTF8.self)), !Self.namesSecret(host) else { return false }
        return !rest[host.endIndex...].split(separator: UInt8(ascii: "/")).contains(where: Self.namesSecret)
    }

    /// Whether a URL that ends at byte `end` ends cleanly: the end of the text, white space or a
    /// line break follows it, or one of ``sentenceEnds`` and then the end of the text, white space
    /// or a line break (`see https://x.example/a. Next`, `(https://x.example/a) ok`). Any other
    /// character after a URL — a quote, a backtick, `>`, `]`, `}`, two marks (`).`), or a `?`, `#`,
    /// `;` or `:`, which start a query, a fragment, path parameters or a port — leaves open where
    /// the URL ends: a URL parser reads `https://x.example/a'#token` and
    /// `https://x.example/a>?token` on past it, and `…/a? token` has an empty query. Such a URL is
    /// not clean, so the text is cut where it starts.
    func endsCleanly(at end: Int) -> Bool {
        guard end < text.count, !isBlank(end) else { return true }
        guard Self.sentenceEnds.contains(text.bytes[end]) else { return false }
        return end + 1 == text.count || isBlank(end + 1)
    }

    /// The one mark that may end a sentence right after a clean URL: `.`, `,`, `!` or `)`. None of
    /// them starts a part of a URL.
    static let sentenceEnds = ByteSet(".,!)")

    private func isBlank(_ i: Int) -> Bool {
        text.isSpace(i) || text.isLineTerminator(i)
    }

    /// The characters of a clean URL after its scheme: ASCII letters, digits, `.`, `_`, `-`, `/`.
    private static func isCleanURLCharacter(_ byte: UInt8) -> Bool {
        ASCII.isAlphanumeric(byte) || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "/")
    }

    /// Whether a host or path segment of ASCII bytes hides a value by the key rule: it names a
    /// secret, or it has no letter or digit.
    private static func namesSecret(_ bytes: some Collection<UInt8>) -> Bool {
        FieldName.hidesValue(bytes.lazy.map { Unicode.Scalar($0) })
    }
}
