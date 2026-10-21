/// Reads free text by the one rule that ``SensitiveDataRedactor/redact(_:)`` describes: the first
/// trigger hides everything after it, to the end of the text.
///
/// The text is read only as far as it is written in the safe alphabet (see
/// ``firstUnsafeOffset(in:)``): the first character outside it is the last possible cut. Up to
/// there the scan runs once over the scanning copy (``NormalizedText``), left to right, and stops
/// at the first trigger, which becomes the cut: the offset in the original scalars from which the
/// text is hidden. A trigger is a key that is not on ``SensitiveDataRedactor/allowedTextKeys``, in
/// `key=value`, in quotes (`"key": value`, cut at its opening quote), as a JSON member and as the
/// first string of a two-element JSON array; markup, which is never parsed (see
/// ``startsMarkup(at:)``); a secret name written without a separator (see ``LooseReading``); a
/// name written as a value that names a secret or is not plain ASCII; an escape (see
/// ``isEscape(at:)``); a word that cannot be read or is longer than ``longestWord``; JSON that does
/// not parse; a URL that is not clean; and a quote or bracket that is still open at the end of the
/// text. Nothing is carried from one line to the
/// next: the cut covers every line after it. JSON and clean URLs before the cut are redacted by their own rules and recorded
/// as regions, which the value detectors do not read again; a URL that is not clean is a trigger
/// where it starts (see ``url(to:)``).
///
/// Besides the findings of the JSON and URLs it reads, the scan keeps a few positions: the cut,
/// the key before the next separator, the quote that is open and the outermost open bracket; no
/// tag is open while it reads. Each JSON it reads is parsed and its tree released before the next one is
/// read (see ``JSONDocument``), so its extra memory grows with what it finds, not with the number
/// of JSON texts or the length of the text.
struct FreeTextScanner {
    /// What kind of text is read.
    enum Role {
        /// A log line, a message, a string value: every trigger counts.
        case text
        /// A key that is written out, such as a JSON name or a form field name. Its value is hidden
        /// by the key rule, so its own words are not triggers (`password_hint` and `pass word`
        /// stay as they are): only a key written inside it that is not allowed (`password=…`,
        /// `a=b`), a character outside the safe alphabet, an escape, a word longer than
        /// ``longestWord`` and JSON are.
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
    /// The offset in the original scalars from which the text is hidden to its end; nil when no
    /// trigger was found.
    private(set) var cut: Int?

    var position = 0
    /// The byte before which the scan stops: the end of the text, or the first byte of the first
    /// character outside the safe alphabet. No word is read past it.
    private(set) var scanEnd = 0
    /// The bytes of the key that the next separator belongs to, when only white space follows it.
    var pendingKey: Range<Int>?
    /// The quote that is open (`"`, `'` or a backtick) and its byte.
    private var openQuote: (byte: UInt8, at: Int)?
    /// The brackets open outside quotes, and the byte of the outermost one.
    private var bracketDepth = 0
    private var outermostBracket = 0

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
        scanEnd = text.count
    }

    mutating func run() {
        // Nothing past the first character outside the safe alphabet is read: the text is cut
        // there at the latest.
        let unsafe = text.firstUnsafeOffset
        scanEnd = unsafe.map(text.byteIndex(atOrAfter:)) ?? text.count
        while position < scanEnd, cut == nil, !hidesWholeText { step() }
        let foundTrigger = cut != nil
        // The earlier of the two cuts holds, whatever the scan recorded before it.
        if let unsafe { cut(atOffset: unsafe) }
        guard !foundTrigger, !hidesWholeText, role == .text else { return }
        // A quote or bracket that does not close before the text ends, or before the character
        // that cuts it, leaves the end of what it holds unknown.
        let open = [openQuote?.at, bracketDepth > 0 ? outermostBracket : nil].compactMap { $0 }.min()
        if let open { cut(atByte: open + 1) }
    }

    // MARK: Reading

    private mutating func step() {
        let byte = text.bytes[position]
        if text.isSpace(position) || text.isLineTerminator(position) {
            position += 1
            return
        }
        if isEscape(at: position) {
            cut(atByte: wordStart(before: position))
        } else if isSeparator(position) {
            separator()
        } else if byte == UInt8(ascii: "\"") {
            quote()
        } else if startsJSON(position) {
            pendingKey = nil
            embeddedJSON()
        } else if role == .text, startsMarkup(at: position) {
            cut(atByte: position)
        } else if Self.boundaries.contains(byte) {
            pendingKey = nil
            note(position)
            position += 1
        } else if let end = urlEnd(from: position) {
            pendingKey = nil
            url(to: end)
        } else {
            word()
        }
    }

    /// Characters that end a key and a word without being part of either.
    static let boundaries = ByteSet(",;&?|([{<")

    /// Moves to byte `end`, noting the quotes and brackets on the way.
    mutating func advance(to end: Int) {
        if role == .text {
            for k in position..<end { note(k) }
        }
        position = end
    }

    /// Notes a quote or bracket at byte `k`. A `'` opens a quote only at the start of a word, so
    /// the apostrophe of `don't` opens nothing; brackets inside quotes do not count.
    private mutating func note(_ k: Int) {
        let byte = text.bytes[k]
        if let open = openQuote {
            if byte == open.byte { openQuote = nil }
            return
        }
        switch byte {
        case UInt8(ascii: "\""), UInt8(ascii: "`"):
            openQuote = (byte, k)
        case UInt8(ascii: "'"):
            if k == 0 || !text.isAnyAlphanumeric(k - 1) { openQuote = (byte, k) }
        case UInt8(ascii: "("), UInt8(ascii: "["), UInt8(ascii: "{"):
            if bracketDepth == 0 { outermostBracket = k }
            bracketDepth += 1
        case UInt8(ascii: ")"), UInt8(ascii: "]"), UInt8(ascii: "}"):
            if bracketDepth > 0 { bracketDepth -= 1 }
        default:
            break
        }
    }

    // MARK: Keys

    /// A run of `=`, `:` and `>` (`:=`, `==`, `=>`) after a key. The value is read on only after a
    /// key on the allowlist (see
    /// ``allowsValue(ofKey:)``); in text, after a key on it that holds a name (`id=`, `type=`), the
    /// name is read too (see ``heldName(after:key:)``). After any other key, and after a separator
    /// with no key, the text is cut. Separators outside ASCII are never read: the safe alphabet
    /// ends before them.
    private mutating func separator() {
        var end = position + 1
        while end < text.count, isSeparator(end) || text.bytes[end] == UInt8(ascii: ">") { end += 1 }
        let key = pendingKey
        pendingKey = nil
        // A key on the line before its separator is a key, but never an allowed one.
        let isBroken = key.map { (($0.upperBound)..<position).contains(where: text.isLineTerminator) } ?? false
        position = end
        guard !isBroken, allowsValue(ofKey: key) else {
            cut(atByte: nextNonSpace(from: end))
            return
        }
        if role == .text, let name = keyName(key), WrittenName.holdsNameInText(name) { heldName(after: end, key: name) }
    }

    /// Whether the value after a key is read on: the key, without the brackets and single quotes
    /// around it, is plain ASCII, does not name a secret and is on the allowlist. A backslash is
    /// part of the key (`status\=…` escapes the `=` in some formats), so such a key is not plain.
    func allowsValue(ofKey key: Range<Int>?) -> Bool {
        guard let name = keyName(key) else { return false }
        return redactor.allowsTextKey(name)
    }

    /// A `"` that opens a quoted key (`"user": …`, `"user"=…`) or quoted text. A quoted key follows
    /// the key rule: unless it is on the allowlist (see ``allowsQuotedKey(_:)``), the text is cut
    /// at its opening quote, so nothing written in the quotes shows (`"session Qz9W…": …`,
    /// `"password hint": 1`). Text in quotes that no separator follows is read like any other,
    /// for the keys and names written in it.
    private mutating func quote() {
        let open = position
        let escaped = isEscaped(open)
        if let close = closingQuote(after: open, quote: UInt8(ascii: "\""), escaped: escaped) {
            let next = nextNonBlank(from: close + 1)
            if next < text.count, isSeparator(next) {
                // In escaped JSON (`\"key\":`) the backslash before the closing quote is not the key's.
                let key = (open + 1)..<(escaped ? close - 1 : close)
                guard allowsQuotedKey(key) else {
                    cut(atByte: escaped ? backslashesStart(before: open) : open)
                    return
                }
                pendingKey = key
                position = close + 1
                return
            }
        }
        pendingKey = nil
        note(open)
        position = open + 1
    }

    /// Whether the quoted key in the bytes `key` is on the allowlist (see
    /// ``SensitiveDataRedactor/allowsTextKey(_:)``), compared where it is in the text: the key as
    /// written, the invisible characters before it included, and nothing taken off it. A key
    /// longer than ``PlainName/maximumKeyLength`` is turned down before any of it is read, so no
    /// key is copied whatever its length.
    func allowsQuotedKey(_ key: Range<Int>) -> Bool {
        let region = text.originalWithInvisiblesBefore(key)
        guard !region.isEmpty, region.count <= PlainName.maximumKeyLength else { return false }
        return redactor.allowsTextKey(source[region])
    }

    /// The first of the backslashes right before byte `i`.
    private func backslashesStart(before i: Int) -> Int {
        var k = i
        while k > 0, text.bytes[k - 1] == UInt8(ascii: "\\") { k -= 1 }
        return k
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

    // MARK: Quotes and white space

    /// Whether the byte at `i` comes after an odd number of backslashes.
    func isEscaped(_ i: Int) -> Bool {
        var count = 0
        var k = i
        while k > 0, text.bytes[k - 1] == UInt8(ascii: "\\") {
            count += 1
            k -= 1
        }
        return count % 2 == 1
    }

    /// The next `quote` after `open` on its line, escaped like the opening one (`\"…\"` in escaped
    /// JSON) or not escaped, within `limit` bytes.
    func closingQuote(after open: Int, quote: UInt8, escaped: Bool, limit: Int = .max) -> Int? {
        var k = open + 1
        while k < text.count, k - open <= limit, !text.isLineTerminator(k) {
            if text.bytes[k] == quote, isEscaped(k) == escaped { return k }
            k += 1
        }
        return nil
    }

    /// The first byte at or after `i` that is not a space or a tab.
    func nextNonSpace(from i: Int) -> Int {
        var k = i
        while k < text.count, text.isSpace(k) { k += 1 }
        return k
    }

    /// The first byte at or after `i` that is not white space or a line break: a key may be
    /// written on the line before its separator.
    func nextNonBlank(from i: Int) -> Int {
        var k = i
        while k < text.count, text.isSpace(k) || text.isLineTerminator(k) { k += 1 }
        return k
    }

    /// Where the value after a secret name starts: after the quotes and brackets that close
    /// around the name (`<password>`, `"token"`), the separators and the spaces after it.
    func valueStart(after i: Int) -> Int {
        var k = i
        while k < text.count, Self.closingMarks.contains(text.bytes[k]) || text.isSpace(k) || isSeparator(k) { k += 1 }
        return k
    }

    private static let closingMarks = ByteSet("\"'`)]}>")

    // MARK: Findings

    /// Hides the text from byte `byte` to its end, with the invisible characters right before
    /// that byte, and ends the scan.
    mutating func cut(atByte byte: Int) {
        cut(atOffset: cutOffset(byte))
    }

    /// Hides the text from the original scalar `offset` to its end and ends the scan.
    mutating func cut(atOffset offset: Int) {
        cut = min(cut ?? offset, offset)
    }

    /// The first scalar hidden from byte `i` on: right after the scalar of the byte before, so the
    /// invisible characters before byte `i` go too, or the scalar of byte `i` when the byte
    /// before came from the same scalar (`ﬁ` is read as `fi`).
    private func cutOffset(_ i: Int) -> Int {
        guard i > 0 else { return 0 }
        if i < text.count, text.offsets[i] == text.offsets[i - 1] { return text.offsets[i] }
        return text.offsets[i - 1] + 1
    }

    /// Ends the scan with the whole text hidden: JSON or a URL in it went past a limit of the
    /// nesting budget, so what the text holds cannot be read.
    mutating func hideWholeText() {
        hidesWholeText = true
        position = text.count
    }

    mutating func record(spans found: [SensitiveDataRedactor.Span], region: Range<Int>) {
        spans += found
        regions.append(region)
    }
}
