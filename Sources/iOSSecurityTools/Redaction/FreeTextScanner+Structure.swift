/// JSON written into free text, read with its parser.
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

    /// The longest JSON in free text that is parsed, in scalars: 64 Ki.
    static let longestJSON = 65_536

    private static let objectStarts = ByteSet("\"}")
    private static let arrayStarts = ByteSet("{[\"]")
    private static let jsonWhitespace = ByteSet(" \t\n\r")

    /// JSON in the text, parsed and redacted by the key rule for structured input, whose keys
    /// follow the rule for keys in text: the text is cut at the value of the first member whose
    /// name is not on ``SensitiveDataRedactor/allowedTextKeys``, or at the second element of the
    /// first two-element array whose first is a string not on it (`["user","bob"]`), or at the
    /// first value that the key rule hides, whichever comes first (`{"status":200,"user":"bob"}`
    /// keeps `"status":200`).
    /// JSON that holds a word naming a secret or one that cannot be read (`["password"]=> "…"`)
    /// cuts the text at its end. JSON that does not parse cannot be read with certainty: the text
    /// is cut at its first bracket, and so is JSON longer than ``longestJSON``, whose tree would
    /// take memory in proportion to it. In a text inside a document, JSON one level too many,
    /// deeper than the depth left or longer than the reading budget leaves (see ``ReadingBudget``)
    /// hides the whole text.
    mutating func embeddedJSON() {
        let start = text.offsets[position]
        guard let inner = nesting.enteringDocument() else {
            hideWholeText()
            return
        }
        let budget = inner.lengthLeft
        let document: JSONDocument
        do {
            document = try JSONDocument(source, at: start, nesting: inner, lengthLimit: min(budget, Self.longestJSON))
        } catch .tooDeep where nesting.isEmbedded {
            hideWholeText()
            return
        } catch .overBudget where nesting.isEmbedded && budget <= Self.longestJSON {
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
        let unallowed = role == .text ? document.firstValue(underKeyWhere: { !redactor.allowsTextKey($0) }) : nil
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
}
