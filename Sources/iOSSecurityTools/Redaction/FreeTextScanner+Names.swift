/// A secret name in free text, also when it is written as a value: what follows it is hidden.
extension FreeTextScanner {
    /// Hides what follows a secret name, or a word that cannot be read, that starts at byte
    /// `nameStart`: the rest of the line from byte `start`, and what the name leaves open below it
    /// (see ``carryAfterHiding(from:valueStart:lineEnd:indent:)``). In markup (see
    /// ``MarkupReader``) the values of the other attributes of the start tag that holds the name go
    /// too, and the lines below that hold markup or are indented more, up to the end of the element
    /// that holds the name or of the element after it.
    mutating func hideAfterName(at nameStart: Int, from start: Int, valueStart: Int, lineEnd: Int) {
        if start < lineEnd { hide(fromByte: start, toLineEnd: lineEnd) }
        position = max(position, lineEnd)
        let fallback = carryAfterHiding(from: start, valueStart: valueStart, lineEnd: lineEnd, indent: lineIndent)
        let markup = MarkupReader(text, line: lineStartOfText..<lineEnd, nameStart: nameStart)
        guard var element = markup.followingElement() else {
            carry = fallback
            return
        }
        for value in markup.attributeValues { hide(text.original(value)) }
        // `<key>password</key>`: the name is in the text after the tag name, and names the next element.
        if markup.isAtTagName, namesSecret(in: elementText(after: nameStart, lineEnd: lineEnd), after: tagName(at: nameStart, lineEnd: lineEnd)) {
            element.followSibling()
        }
        // An element that ends on the line was hidden with the rest of it.
        carry = element.read(text, nameStart..<lineEnd) == nil ? .markup(element, indent: lineIndent, fallback: fallback) : .none
    }

    /// The text of an element on its line: from after the `>` of the start tag that `tagName`
    /// begins to the next `<`.
    private func elementText(after tagName: Int, lineEnd: Int) -> Range<Int> {
        var start = tagName
        var quote: UInt8?
        while start < lineEnd {
            let byte = text.bytes[start]
            start += 1
            if let open = quote {
                if byte == open { quote = nil }
            } else if byte == UInt8(ascii: "\"") || byte == UInt8(ascii: "'") {
                quote = byte
            } else if byte == UInt8(ascii: ">") {
                break
            }
        }
        var end = start
        while end < lineEnd, text.bytes[end] != UInt8(ascii: "<") { end += 1 }
        return start..<end
    }

    /// The name of the tag that starts at byte `i`.
    private func tagName(at i: Int, lineEnd: Int) -> [Unicode.Scalar] {
        var end = i
        while end < lineEnd, ASCII.isAlphanumeric(text.bytes[end]) || "-_:".utf8.contains(text.bytes[end]) { end += 1 }
        return Array(source[text.original(i..<end)])
    }

    /// Whether quoted text after the key or tag `key` names a secret or cannot be read, by the rule
    /// of ``WrittenName``: `"password"`, `'db.password'`, `"API Key"`, `"pаssword"` with a
    /// Cyrillic `а`, and after a key that holds a name (`name=`, `key=`, `label=`, …) any name that
    /// is not plain ASCII (`label="Пароль"`, `name="ⓟⓘⓝ"`). Such text is a name written as a
    /// value, as in `name="password"` or `<string name="api_key">`, and what follows it is its
    /// value.
    func namesSecret(in range: Range<Int>, after key: [Unicode.Scalar]? = nil) -> Bool {
        let scalars = range.isEmpty ? [] : Array(source[text.originalWithInvisiblesBefore(range)])
        return WrittenName.namesSecret(scalars, in: .quoted(after: key), compatibility: compatibility)
    }

    /// A line below a secret name written in an element. The element's lines are hidden up to
    /// its end, after which the line is read again. When no end tag of the element comes later, a
    /// line that neither holds markup nor is indented more than the name's line may be text after
    /// an element that is never closed (`usage: login <password>`), and goes on as `fallback`.
    /// Returns whether the rest of the line is scanned.
    mutating func continueElement(_ element: MarkupReader, indent: Int, fallback: Carry, lineStart: Int, lineEnd: Int) -> Bool {
        var element = element
        let textStart = firstNonSpace(from: lineStart, to: lineEnd)
        if let end = element.read(text, lineStart..<lineEnd) {
            if textStart < end { hide(text.offset(at: textStart)..<text.offset(at: end)) }
            carry = .none
            position = end
            return true
        }
        guard textStart < lineEnd else {
            carry = .markup(element, indent: indent, fallback: fallback)
            return false
        }
        if element.sawTag || lineIndent > indent || endTagFollows(element, after: lineEnd) {
            hide(fromByte: textStart, toLineEnd: lineEnd)
            let next = carryAfterHiding(from: textStart, valueStart: textStart, lineEnd: lineEnd, indent: indent)
            carry = .markup(element, indent: indent, fallback: next)
            return false
        }
        carry = fallback
        let scansLine = continueCarry(lineStart: lineStart, lineEnd: lineEnd)
        // The line went on as the value: the element may go on below it too.
        if !scansLine { carry = .markup(element, indent: indent, fallback: carry) }
        return scansLine
    }

    /// Whether an end tag of the element that `element` follows comes after byte `i`. The end
    /// tags are found in one pass over the text, the first time they are needed.
    private mutating func endTagFollows(_ element: MarkupReader, after i: Int) -> Bool {
        guard let name = element.holdingName else { return false }
        if lastEndTags == nil { lastEndTags = Self.lastEndTags(in: text) }
        return (lastEndTags?[name] ?? -1) >= i
    }

    /// The byte of the last `</name` of each element name, read as ``MarkupReader`` reads names.
    private static func lastEndTags(in text: NormalizedText) -> [[UInt8]: Int] {
        var found: [[UInt8]: Int] = [:]
        var k = 0
        while k + 2 < text.count {
            guard text.bytes[k] == UInt8(ascii: "<"), text.bytes[k + 1] == UInt8(ascii: "/") else {
                k += 1
                continue
            }
            var name: [UInt8] = []
            var j = k + 2
            while j < text.count, ASCII.isAlphanumeric(text.bytes[j]) || "-_:".utf8.contains(text.bytes[j]) {
                if name.count < MarkupReader.maximumTagName { name.append(ASCII.lowercased(text.bytes[j])) }
                j += 1
            }
            if !name.isEmpty { found[name] = k }
            k = j
        }
        return found
    }
}
