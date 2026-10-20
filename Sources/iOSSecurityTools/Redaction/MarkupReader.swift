/// Reads the XML or HTML tags of free text far enough to tell which element holds a secret name
/// and where that element ends.
///
/// A secret name is often written as a value: `<string name="api_key">…</string>`,
/// `<entry key="db.password">…</entry>`, `<input name="password" value="…">`,
/// `<key>password</key><string>…</string>`. What follows it in its element is then the secret.
/// ``FreeTextScanner`` hides the rest of the line after such a name; this reader finds the rest of
/// the element: the values of the attributes before the name in its start tag, and where the
/// element ends on a later line. A name in the text of an element (`<key>password</key>`,
/// `<td>password</td>`) names the element after it, as a property list writes a key and its value,
/// so that element, or the text after the end tag, is followed too.
///
/// Only tags are read: `<name …>`, `</name>`, `/>` and quoted attribute values. Comments
/// (`<!-- … -->`), declarations and processing instructions (`<!…>`, `<?…>`) are skipped. HTML
/// elements that never close (`<input>`, `<br>`, `<img>`, …) end with their start tag. The reader
/// only ever makes the scanner hide more; text it does not read as markup is left to the
/// free-text rule.
struct MarkupReader {
    private enum Place {
        case text
        case startTag
        case endTag(start: Int)
        /// A comment, with the number of `-` just read.
        case comment(dashes: Int)
        case declaration
    }

    private var place = Place.text
    /// The quote of the attribute value being read in a start tag.
    private var quote: UInt8?
    /// The lowercased name of the start tag being read, up to ``maximumTagName`` bytes.
    private var tagName: [UInt8] = []
    private var readsTagName = false
    private var lastNonSpace: UInt8 = 0
    /// Elements open. Before a name: those opened since the line started. After it: the element
    /// that holds the name counts as 1 once its start tag has ended.
    private var depth = 0
    /// Whether an element that holds the name is followed: the reader then reports where it ends.
    private var follows = false
    /// Whether the element after the one that holds the name is followed too, and whether the
    /// reader waits for it or reads the text that stands for it.
    private var takesSibling = false
    private var awaitsSibling = false
    private var readsSiblingText = false
    /// Whether the last line read held a tag, a comment or a declaration.
    private(set) var sawTag = false
    /// Whether the element followed last holds text or an element, once its start tag has ended.
    private var heldContent = false
    /// The names of the elements opened since the line started, before a name, innermost last.
    private var openNames: [[UInt8]] = []
    /// The name of the element that holds the name, or of the element after it once that opens.
    private(set) var holdingName: [UInt8]?
    /// The byte ranges of the attribute values of the start tag being read, before a name.
    private(set) var attributeValues: [Range<Int>] = []
    private var valueStart: Int?
    private var expectsValue = false

    /// Longer tag names are compared by their first 16 bytes.
    static let maximumTagName = 16
    private static let maximumOpenNames = 32
    private static let voidElements: Set<[UInt8]> = Set(
        ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"].map { Array($0.utf8) }
    )

    /// Reads a line from its start up to a secret name at byte `nameStart`.
    init(_ text: NormalizedText, line: Range<Int>, nameStart: Int) {
        _ = read(text, line.lowerBound..<nameStart)
    }

    /// Whether the name starts the tag name of a start tag (`<key>…`, `<td>…`): the name word then
    /// runs on into the element's text, which may name the element after it.
    var isAtTagName: Bool {
        if case .startTag = place { return readsTagName }
        return false
    }

    /// The reader to follow the element that holds the name, or nil when no element does: the
    /// name is in a start tag (an attribute value or the tag's own name), or in the text of an
    /// element opened earlier on its line, which names the element after it.
    func followingElement() -> MarkupReader? {
        var reader = self
        switch place {
        case .startTag:
            reader.depth = 0
        case .text where depth > 0:
            reader.depth = 1
            reader.holdingName = openNames.last
            reader.takesSibling = true
        case .text, .endTag, .comment, .declaration:
            return nil
        }
        reader.follows = true
        reader.attributeValues = []
        reader.openNames = []
        return reader
    }

    /// Follows the element after the one that holds the name too.
    mutating func followSibling() {
        takesSibling = true
    }

    /// Whether the element followed last ended without holding text or an element:
    /// `<string></string>`, also over lines. Like an element that closes itself, it holds no
    /// value, so the value may come after it.
    var heldNothing: Bool { !heldContent }

    /// Reads bytes `range` of a line. When followed, returns where what belongs to the name ends:
    /// the `<` of an end tag, the byte after a start tag that closes itself, or, for text that
    /// stands for the element after the name, the next tag or the end of the line.
    mutating func read(_ text: NormalizedText, _ range: Range<Int>) -> Int? {
        sawTag = false
        var k = range.lowerBound
        while k < range.upperBound {
            let byte = text.bytes[k]
            switch place {
            case .text:
                if follows, depth > 0, byte != UInt8(ascii: "<") || isStartTag(at: k, in: text), !text.isSpace(k) { heldContent = true }
                if let end = readText(byte, at: k, in: text) { return end }
            case .startTag:
                if let end = readStartTag(byte, at: k) { return end }
            case .endTag(let start):
                if byte == UInt8(ascii: ">"), let end = endEndTag(startingAt: start) { return end }
            case .comment(let dashes):
                let ends = byte == UInt8(ascii: ">") && dashes >= 2
                place = ends ? .text : .comment(dashes: byte == UInt8(ascii: "-") ? dashes + 1 : 0)
            case .declaration:
                if byte == UInt8(ascii: ">") { place = .text }
            }
            k += 1
        }
        return readsSiblingText ? range.upperBound : nil
    }

    private mutating func endEndTag(startingAt start: Int) -> Int? {
        place = .text
        depth -= 1
        if !follows { _ = openNames.popLast() }
        guard follows, depth <= 0 else {
            depth = max(depth, 0)
            return nil
        }
        // The element that holds the name ended; the one after it is the value.
        if takesSibling, !awaitsSibling, depth == 0 {
            awaitsSibling = true
            return nil
        }
        return start
    }

    /// Whether a start tag (`<` and a letter) begins at byte `k`.
    private func isStartTag(at k: Int, in text: NormalizedText) -> Bool {
        text.bytes[k] == UInt8(ascii: "<") && k + 1 < text.count && ASCII.isLetter(text.bytes[k + 1])
    }

    private mutating func readText(_ byte: UInt8, at k: Int, in text: NormalizedText) -> Int? {
        if follows, awaitsSibling, depth == 0 {
            if byte == UInt8(ascii: "<"), readsSiblingText { return k }
            // A letter or digit there is the value, written without an element (`<td>pin</td> 1234`).
            if ASCII.isAlphanumeric(byte) || byte == CompatibilityText.unreadable { readsSiblingText = true }
        }
        guard byte == UInt8(ascii: "<"), k + 1 < text.count else { return nil }
        let next = text.bytes[k + 1]
        sawTag = sawTag || next == UInt8(ascii: "/") || next == UInt8(ascii: "!") || next == UInt8(ascii: "?") || ASCII.isLetter(next)
        if next == UInt8(ascii: "/") {
            place = .endTag(start: k)
        } else if next == UInt8(ascii: "!") || next == UInt8(ascii: "?") {
            let opensComment = k + 3 < text.count && text.bytes[k + 2] == UInt8(ascii: "-") && text.bytes[k + 3] == UInt8(ascii: "-")
            place = opensComment ? .comment(dashes: 0) : .declaration
        } else if ASCII.isLetter(next) {
            place = .startTag
            tagName = []
            readsTagName = true
            lastNonSpace = byte
            quote = nil
            expectsValue = false
            valueStart = nil
            if !follows { attributeValues = [] }
        }
        return nil
    }

    /// One byte of a start tag; returns the byte after the tag when it closes the element that is
    /// followed.
    private mutating func readStartTag(_ byte: UInt8, at k: Int) -> Int? {
        if let open = quote {
            if byte == open {
                quote = nil
                record(valueEnd: k)
            }
            return nil
        }
        if readsTagName {
            if ASCII.isAlphanumeric(byte) || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: ":") {
                if tagName.count < Self.maximumTagName { tagName.append(ASCII.lowercased(byte)) }
                lastNonSpace = byte
                return nil
            }
            readsTagName = false
        }
        let isSpace = byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")
        if valueStart != nil, !expectsValue, isSpace || byte == UInt8(ascii: ">") {
            record(valueEnd: k)
        }
        if expectsValue, !isSpace {
            expectsValue = false
            if byte == UInt8(ascii: "\"") || byte == UInt8(ascii: "'") {
                quote = byte
                valueStart = k + 1
                return nil
            }
            valueStart = byte == UInt8(ascii: ">") ? nil : k
        }
        if byte == UInt8(ascii: "=") {
            expectsValue = true
        } else if byte == UInt8(ascii: ">") {
            return endStartTag(at: k)
        }
        if !isSpace { lastNonSpace = byte }
        return nil
    }

    private mutating func endStartTag(at k: Int) -> Int? {
        place = .text
        let closesItself = lastNonSpace == UInt8(ascii: "/") || Self.voidElements.contains(tagName)
        guard closesItself else {
            depth += 1
            if follows, depth == 1 {
                holdingName = tagName
                heldContent = false
            } else if !follows {
                if openNames.count == Self.maximumOpenNames { openNames.removeFirst() }
                openNames.append(tagName)
            }
            return nil
        }
        guard follows, depth == 0 else { return nil }
        if takesSibling, !awaitsSibling {
            awaitsSibling = true
            return nil
        }
        return k + 1
    }

    private mutating func record(valueEnd: Int) {
        if let start = valueStart, !follows, valueEnd > start { attributeValues.append(start..<valueEnd) }
        valueStart = nil
    }
}
