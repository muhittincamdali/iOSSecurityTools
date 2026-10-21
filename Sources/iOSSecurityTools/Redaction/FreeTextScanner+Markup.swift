/// Markup, quotes and brackets in free text, read by their positions alone.
///
/// The scan keeps no tag, quote or bracket open while it reads. Earlier designs read a tag as a
/// key and tracked the quote and the start tag that were open: a quote opened before a tag kept
/// the tag from ever ending, and markup between a tag and its text ended the cut the tag had set
/// up. Markup is now never parsed (see ``startsMarkup(at:)``), and one pass of its own, over the
/// bytes of the scanning copy, finds the two positions where quotes and brackets cut the text
/// (see ``openMarks()``).
extension FreeTextScanner {
    /// Whether markup starts at byte `i`: a `<` that is not a comparison. The rule names what a
    /// comparison is, not what a tag can start with: a `<` is a comparison only before an ASCII
    /// space, tab, line feed or carriage return, an ASCII digit, `=` or the end of the text
    /// (`a < b`, `1<2`, `<3`, `<=`, `x <`). Before any other character — a letter of any script,
    /// `_`, `:`, `/`, `!`, `?`, any other punctuation, a digit or a symbol outside ASCII — it starts
    /// markup (`<user>`, `<_id>`, `</a>`, `<!--`, `<?xml`, `<०>`, `<-x>`, `x << 1`). Free text
    /// never parses markup: the first such `<` cuts the text, whatever follows it, so what an
    /// element, a comment or a CDATA section holds never shows. The character after the `<` is
    /// read in the original text, so a digit or a space outside ASCII (`<١>`, `<\u{00A0}`) is not
    /// read as its ASCII form.
    func startsMarkup(at i: Int) -> Bool {
        guard text.bytes[i] == UInt8(ascii: "<") else { return false }
        let next = text.offsets[i] + 1
        guard next < source.count else { return false }
        let scalar = source[next]
        return !(scalar.isASCII && Self.comparisonFollowers.contains(UInt8(scalar.value)))
    }

    /// What may follow a `<` that is a comparison.
    private static let comparisonFollowers = ByteSet(" \t\n\r0123456789=")

    /// Where the quotes and brackets that do not close cut the text.
    struct OpenMarks: Equatable {
        /// The first quote that does not close on its line before the scan ends: the byte of the
        /// quote, or of the backslashes before it when it is escaped (`\"`). The text is cut
        /// there.
        var unclosedQuote: Int?
        /// The outermost bracket outside quotes that is still open where the scan ends. The text
        /// is cut after it when nothing else cut it.
        var openBracket: Int?
    }

    /// Reads the quotes and brackets of the text, in one pass that keeps two positions:
    ///
    /// - A `"` or a backtick opens a quote anywhere, a `'` only at the start of a word, so the
    ///   apostrophe of `don't` and of `it\'s` opens nothing.
    /// - A quote closes at the next of its own character written the same way, escaped as in
    ///   escaped JSON (`\"…\"`) or not; nothing else inside it counts, brackets included.
    /// - A quote still open at a line break does not close on its line, and neither does one
    ///   still open where the scan ends (``scanEnd``): at the end of the text or at the first
    ///   character outside the safe alphabet, which cuts the text inside it. What it holds, a key
    ///   and its value over lines among them (`"note\nQx31": 1`), cannot be told, so the pass
    ///   ends there.
    /// - A bracket outside quotes (`(`, `[`, `{`) opens, and its closing one closes it.
    ///
    /// Nothing past ``scanEnd`` is read, as by the scan.
    func openMarks() -> OpenMarks {
        var marks = OpenMarks()
        var quote: (byte: UInt8, escaped: Bool, at: Int)?
        var depth = 0
        var k = 0
        while k < scanEnd {
            let byte = text.bytes[k]
            if let open = quote {
                if text.isLineTerminator(k) {
                    marks.unclosedQuote = open.at
                    return marks
                }
                if byte == open.byte, isEscaped(k) == open.escaped { quote = nil }
            } else if Self.quotes.contains(byte), opensQuote(at: k) {
                let escaped = isEscaped(k)
                quote = (byte, escaped, escaped ? backslashesStart(before: k) : k)
            } else if Self.openingBrackets.contains(byte) {
                if depth == 0 { marks.openBracket = k }
                depth += 1
            } else if Self.closingBrackets.contains(byte), depth > 0 {
                depth -= 1
                if depth == 0 { marks.openBracket = nil }
            }
            k += 1
        }
        if let open = quote { marks.unclosedQuote = open.at }
        return marks
    }

    /// Whether the quote character at byte `k` can open a quote: a `'` only where no letter or
    /// digit comes before it and its backslashes.
    private func opensQuote(at k: Int) -> Bool {
        guard text.bytes[k] == UInt8(ascii: "'") else { return true }
        let start = backslashesStart(before: k)
        return start == 0 || !text.isAnyAlphanumeric(start - 1)
    }

    private static let openingBrackets = ByteSet("([{")
    private static let closingBrackets = ByteSet(")]}")
}
