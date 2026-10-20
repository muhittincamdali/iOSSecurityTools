/// Names written as values in free text: after an allowed key that holds a name, and in the text
/// of an element whose tag holds one.
extension FreeTextScanner {
    /// The value after an allowed key that holds a name (`id=`, `type=`, … but not `path=`, the
    /// route of a request), read as a name by the rule of ``WrittenName``: a secret name, one that
    /// is not plain ASCII (`type="Пароль"`, `id=ⓟⓘⓝ`) and JSON there (`id=["pin"]`) cut the text,
    /// after the closing quote of a quoted name and at the start of any other. A name that is
    /// plain and not secret (`type=status`) is read on as text.
    mutating func heldName(after separatorEnd: Int, key: [Unicode.Scalar]) {
        let start = nextNonSpace(from: separatorEnd)
        guard start < text.count, !text.isLineTerminator(start) else { return }
        let byte = text.bytes[start]
        if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") {
            cut(atByte: start)
        } else if Self.quotes.contains(byte) {
            // A quoted name longer than any name is no name that can be read.
            guard let close = closingQuote(after: start, quote: byte, escaped: false, limit: Self.longestName) else {
                cut(atByte: start + 1)
                return
            }
            if heldNameNamesSecret((start + 1)..<close, after: key) { cut(atByte: valueStart(after: close + 1)) }
        } else {
            // Where an unquoted name ends cannot be told, so it is hidden with what follows it.
            var end = wordEnd(from: start, to: text.count)
            if let close = text.bytes[start..<end].firstIndex(of: UInt8(ascii: ">")) { end = close }
            if heldNameNamesSecret(start..<end, after: key) { cut(atByte: start) }
        }
    }

    /// Whether a held name names a secret by the rule of ``WrittenName`` and holds no word that
    /// the word reading cuts at: a secret word in it (`type=pin1234`) is cut right after, as in
    /// any other word, when the scan reads it next.
    private func heldNameNamesSecret(_ range: Range<Int>, after key: [Unicode.Scalar]) -> Bool {
        let scalars = range.isEmpty ? [] : Array(source[text.originalWithInvisiblesBefore(range)])
        guard WrittenName.namesSecret(scalars, in: .quoted(after: key), compatibility: compatibility) else { return false }
        return !Self.mentionsSecret(Array(source[text.original(range)]), compatibility: compatibility)
    }

    /// A `<` before a letter starts a tag (see ``isInStartTag``). An element whose tag holds a name
    /// (`<key>`, `<name>`), with no attributes, holds a name written as a value in its text up to
    /// the next `<` (`<key>Şifre</key>`), read as after `key=`; when it names a secret, the text is
    /// cut at the name. An element text longer than any name is not read as one; its words are
    /// read as text.
    mutating func startTag() {
        guard position + 1 < text.count, ASCII.isLetter(text.bytes[position + 1]) else { return }
        isInStartTag = true
        startTagValues = nil
        var k = position + 1
        while k < text.count, k - position <= Self.longestTag, Self.isTagNameByte(text.bytes[k]) { k += 1 }
        guard k < text.count, text.bytes[k] == UInt8(ascii: ">") else { return }
        let tag = Array(source[text.original((position + 1)..<k)])
        guard WrittenName.holdsNameInText(tag) else { return }
        let contentStart = k + 1
        var end = contentStart
        while end < text.count, text.bytes[end] != UInt8(ascii: "<") {
            guard end - contentStart < Self.longestName else { return }
            end += 1
        }
        if heldNameNamesSecret(contentStart..<end, after: tag) { cut(atByte: contentStart) }
    }

    private static func isTagNameByte(_ byte: UInt8) -> Bool {
        ASCII.isAlphanumeric(byte) || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: ":") || byte == UInt8(ascii: ".")
    }

    private static let longestTag = 32

    /// The most bytes a name written as a value is read for: more than the longest plain key.
    private static let longestName = 4 * PlainName.maximumKeyLength

    static let quotes = ByteSet("\"'`")
}
