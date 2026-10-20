/// Reads free text for keys, values and structured pieces, by the allowlist rule that
/// ``SensitiveDataRedactor/redact(_:)`` describes.
///
/// The scan runs on the scanning copy (``NormalizedText``), left to right and line by line, and
/// never moves backwards; the findings are spans of the original scalars. JSON and URLs found in
/// the text are recorded as regions, which the value detectors do not read again.
struct FreeTextScanner {
    /// What a line leaves open for the lines after it.
    enum Carry {
        case none
        /// A hidden key ended its line; the value is on the next line with text.
        case valueOnNextLine(indent: Int)
        /// A value was hidden to the end of its line; lines indented more than `indent`, and the
        /// line after a trailing `\`, belong to it.
        case continuation(indent: Int, backslash: Bool)
        /// A hidden value in quotes (`"`, `'` or a backtick) did not close on its line; it goes on
        /// to the line where it closes, which is hidden whole.
        case openQuote(quote: UInt8, escaped: Bool, indent: Int)
        /// A secret name was written in an element that is still open: the lines below that hold
        /// markup or are indented more than `indent` are hidden up to the element's end (see
        /// ``MarkupReader``). Other lines go on as `fallback`, what the name would leave open
        /// outside markup.
        indirect case markup(MarkupReader, indent: Int, fallback: Carry)
    }

    /// What kind of text is read.
    enum Role {
        /// A log line, a message, a string value: every rule applies.
        case text
        /// A key that is written out, such as a JSON name or a form field name: it is read for
        /// pairs, JSON, URLs and values, but its words are not read as labels, so a name such as
        /// `pass word` or one in mixed scripts stays as it is (its value is hidden by the key rule).
        case name
    }

    let source: [Unicode.Scalar]
    let text: NormalizedText
    let redactor: SensitiveDataRedactor
    let compatibility: CompatibilityText
    let role: Role
    /// The documents the text is in and the JSON objects and arrays around it.
    let nesting: Nesting

    private(set) var spans: [SensitiveDataRedactor.Span] = []
    private(set) var regions: [Range<Int>] = []
    /// Whether JSON or a URL in the text went past a limit of ``nesting`` while the text is inside
    /// a document, so the text is hidden whole.
    private(set) var hidesWholeText = false

    var position = 0
    var carry = Carry.none
    var lineIndent = 0
    /// The first byte of the line being read.
    var lineStartOfText = 0
    /// The bytes of the key that the next separator belongs to, when only spaces or tabs follow it.
    var pendingKey: Range<Int>?
    /// The closing quotes of quoted text being read, which do not open a new quote.
    var pairedQuotes: Set<Int> = []
    /// Whether the line before ended right after a word at a break other than LF and CRLF, so a
    /// separator at the start of this line may belong to that word.
    var lineFollowsBrokenWord = false
    /// The byte of the last end tag of each element name, found the first time a secret name is
    /// written in an element that goes on below its line (see ``MarkupReader``).
    var lastEndTags: [[UInt8]: Int]?

    init(
        source: [Unicode.Scalar], text: NormalizedText, redactor: SensitiveDataRedactor, compatibility: CompatibilityText, role: Role = .text,
        nesting: Nesting
    ) {
        self.source = source
        self.text = text
        self.redactor = redactor
        self.compatibility = compatibility
        self.role = role
        self.nesting = nesting
    }

    mutating func run() {
        var lineStart = 0
        while position < text.count {
            let end = lineEnd(from: position)
            lineStartOfText = lineStart
            if position == lineStart {
                lineIndent = indentation(from: lineStart, to: end)
                pendingKey = nil
                pairedQuotes = []
                if continueCarry(lineStart: lineStart, lineEnd: end) { scan(to: end) }
            } else {
                scan(to: end)
            }
            // A line separator other than LF may sit inside a key: a separator that starts the
            // next line may belong to the word before it.
            let isBlank = firstNonSpace(from: lineStartOfText, to: end) >= end
            lineFollowsBrokenWord = position <= end && (breaksWord(at: end, orAtCR: true) || (isBlank && lineFollowsBrokenWord))
            if position <= end {
                position = afterTerminator(end)
                lineStart = position
            } else {
                // JSON that went on over the lines below ended in the middle of a line.
                lineStart = self.lineStart(before: position)
                lineIndent = indentation(from: lineStart, to: lineEnd(from: lineStart))
                pendingKey = nil
                pairedQuotes = []
            }
        }
    }

    // MARK: Scanning a line

    private mutating func scan(to lineEnd: Int) {
        while position < lineEnd {
            let byte = text.bytes[position]
            if text.isSpace(position) {
                position += 1
            } else if isSeparator(position) {
                separator(lineEnd: lineEnd)
            } else if byte == UInt8(ascii: "\"") {
                quote(lineEnd: lineEnd)
            } else if startsJSON(position) {
                pendingKey = nil
                embeddedJSON(lineEnd: lineEnd)
            } else if Self.boundaries.contains(byte), referenceLength(at: position) == nil {
                pendingKey = nil
                position += 1
            } else if let end = urlEnd(from: position, lineEnd: lineEnd) {
                pendingKey = nil
                url(to: end)
            } else {
                word(lineEnd: lineEnd)
            }
        }
    }

    /// Characters that end a key and a word without being part of either.
    static let boundaries = ByteSet(",;&?|([{<")

    /// `=` and `:`; a `:` between two digits is part of a time (`12:30`).
    func isSeparator(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        if byte == UInt8(ascii: "=") { return true }
        guard byte == UInt8(ascii: ":") else { return false }
        return !(i > 0 && i + 1 < text.count && text.isDigit(i - 1) && text.isDigit(i + 1))
    }

    // MARK: Keys

    /// A `"` that opens a quoted key, quoted text or nothing that closes on the line.
    private mutating func quote(lineEnd: Int) {
        let open = position
        if pairedQuotes.remove(open) != nil {
            position += 1
            return
        }
        let escaped = isEscaped(open)
        guard let close = closingQuote(after: open, quote: UInt8(ascii: "\""), escaped: escaped, lineEnd: lineEnd) else {
            // A quote that does not close: where its text ends cannot be told.
            pendingKey = nil
            hide(fromByte: open, toLineEnd: lineEnd)
            carry = .openQuote(quote: UInt8(ascii: "\""), escaped: escaped, indent: lineIndent)
            return
        }
        let next = firstNonSpace(from: close + 1, to: lineEnd)
        if next < lineEnd, isSeparator(next) {
            // In escaped JSON (`\"key\":`) the backslash before the closing quote is not the key's.
            pendingKey = (open + 1)..<(escaped ? close - 1 : close)
            position = close + 1
            return
        }
        pendingKey = nil
        pairedQuotes.insert(close)
        position = open + 1
    }

    /// Whether the value after a key is kept: the key, without the brackets and single quotes
    /// around it, is plain ASCII, does not name a secret and is on the allowlist. A backslash is
    /// part of the key (`status\=…` escapes the `=` in some formats), so such a key is not plain.
    func allowsValue(ofKey key: Range<Int>?) -> Bool {
        guard let name = keyName(key), let fold = FieldName.allowableFold(name) else { return false }
        return redactor.allowedTextKeys.contains(fold)
    }

    /// The key as written, invisible characters before it included, without the brackets and
    /// single quotes around it; nil when there is none.
    func keyName(_ key: Range<Int>?) -> [Unicode.Scalar]? {
        guard let key, !key.isEmpty else { return nil }
        var name = source[text.originalWithInvisiblesBefore(key)]
        while let first = name.first, "([{<'".unicodeScalars.contains(first) { name = name.dropFirst() }
        while let last = name.last, last == "'" { name = name.dropLast() }
        return Array(name)
    }

    // MARK: Lines

    func lineEnd(from i: Int) -> Int {
        var end = i
        while end < text.count, !text.isLineTerminator(end) { end += 1 }
        return end
    }

    func afterTerminator(_ lineEnd: Int) -> Int {
        guard lineEnd < text.count else { return lineEnd }
        let isCRLF = text.bytes[lineEnd] == 0x0D && lineEnd + 1 < text.count && text.bytes[lineEnd + 1] == 0x0A
        return lineEnd + (isCRLF ? 2 : 1)
    }

    private func lineStart(before i: Int) -> Int {
        var start = i
        while start > 0, !text.isLineTerminator(start - 1) { start -= 1 }
        return start
    }

    func firstNonSpace(from i: Int, to lineEnd: Int) -> Int {
        var k = i
        while k < lineEnd, text.isSpace(k) { k += 1 }
        return k
    }

    private func indentation(from lineStart: Int, to lineEnd: Int) -> Int {
        firstNonSpace(from: lineStart, to: lineEnd) - lineStart
    }

    // MARK: Spans

    /// Hides from byte `start` to the end of its line, line terminator excluded.
    mutating func hide(fromByte start: Int, toLineEnd lineEnd: Int) {
        hide(text.offset(at: start)..<text.offset(at: lineEnd))
        position = max(position, lineEnd)
    }

    mutating func hide(_ range: Range<Int>) {
        guard !range.isEmpty else { return }
        spans.append(SensitiveDataRedactor.Span(start: range.lowerBound, end: range.upperBound, kind: .secretFields, replacement: SensitiveDataRedactor.replacement))
    }

    /// Ends the scan with the whole text hidden: JSON or a URL in it went past a limit of the
    /// nesting budget, so what the text holds cannot be read.
    mutating func hideWholeText() {
        hidesWholeText = true
        carry = .none
        position = text.count
    }

    mutating func record(_ span: SensitiveDataRedactor.Span) { spans.append(span) }

    mutating func record(spans found: [SensitiveDataRedactor.Span], region: Range<Int>) {
        spans += found
        regions.append(region)
    }
}
