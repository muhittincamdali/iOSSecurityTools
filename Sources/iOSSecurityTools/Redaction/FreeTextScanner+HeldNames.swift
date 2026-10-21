/// Names written as values in free text, after an allowed key that holds a name. Markup is not
/// read for names: the first tag cuts the text (see ``startsMarkup(at:)``).
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
            let end = wordEnd(from: start, to: text.count)
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

    /// The most bytes a name written as a value is read for: more than the longest plain key.
    private static let longestName = 4 * PlainName.maximumKeyLength

    static let quotes = ByteSet("\"'`")
}
