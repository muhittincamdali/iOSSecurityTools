/// Markup in free text, which is never parsed.
///
/// The scan keeps no tag open while it reads. An earlier design read a tag as a key and tracked
/// the start tag that was open: a quote opened before a tag kept the tag from ever ending, and
/// markup between a tag and its text ended the cut the tag had set up. The first markup tag cuts
/// the text instead (see ``startsMarkup(at:)``).
extension FreeTextScanner {
    /// Whether markup starts at byte `i`: a `<` before a letter of any script, `/`, `!` or `?`
    /// (`<user>`, `</a>`, `<!--`, `<![CDATA[`, `<?xml`). Free text never parses markup, whatever
    /// the tag: the first such `<` cuts the text, so what an element, a comment or a CDATA
    /// section holds never shows. A `<` before white space, a digit, `=` or anything else is
    /// read as a comparison (`a < b`, `<=`, `<3`).
    func startsMarkup(at i: Int) -> Bool {
        guard text.bytes[i] == UInt8(ascii: "<"), i + 1 < text.count else { return false }
        return text.isAnyLetter(i + 1) || Self.markupMarks.contains(text.bytes[i + 1])
    }

    private static let markupMarks = ByteSet("/!?")
}
