/// Values in free text: what follows a separator, what earlier lines leave open, and JSON and
/// URLs written into a line.
extension FreeTextScanner {
    // MARK: Separators

    /// A run of `=`, `:` and `>` (`:=`, `==`, `=>`, `::=`) after a key. The value is kept when the
    /// key is allowed and hidden otherwise, also when no key comes before the separator.
    mutating func separator(lineEnd: Int) {
        var end = position + 1
        while end < lineEnd, isSeparator(end) || text.bytes[end] == UInt8(ascii: ">") { end += 1 }
        let key = pendingKey
        pendingKey = nil
        position = end
        let keyName = keyName(key)
        guard !allowsValue(ofKey: key) || allowedValueNamesSecret(after: end, key: keyName, lineEnd: lineEnd) else { return }
        hideValue(after: end, key: keyName, lineEnd: lineEnd)
    }

    /// Whether the value of an allowed key that holds a name (`type=…` with `type` allowed) names
    /// a secret, so it is hidden with what follows it after all (see ``WrittenName``).
    private func allowedValueNamesSecret(after separatorEnd: Int, key: [Unicode.Scalar]?, lineEnd: Int) -> Bool {
        guard let key, WrittenName.holdsNameInText(key) else { return false }
        let start = firstNonSpace(from: separatorEnd, to: lineEnd)
        guard start < lineEnd else { return false }
        let byte = text.bytes[start]
        if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") { return true }
        if byte == UInt8(ascii: "\"") || byte == UInt8(ascii: "'") || byte == UInt8(ascii: "`") {
            guard let close = closingQuote(after: start, quote: byte, escaped: false, lineEnd: lineEnd) else { return true }
            return namesSecret(in: (start + 1)..<close, after: key)
        }
        return namesSecret(in: start..<wordEnd(from: start, to: lineEnd), after: key)
    }

    /// Hides the value that starts after a separator ending at byte `separatorEnd`. `key`, when
    /// it holds a name, decides how a quoted name in the value is read, and a JSON value after
    /// it, which cannot be read as a name, hides the rest of the line too (`name=["pin"] …`).
    private mutating func hideValue(after separatorEnd: Int, key: [Unicode.Scalar]?, lineEnd: Int) {
        let start = firstNonSpace(from: separatorEnd, to: lineEnd)
        guard start < lineEnd else {
            carry = .valueOnNextLine(indent: lineIndent)
            position = lineEnd
            return
        }
        let byte = text.bytes[start]
        let escapedQuote = byte == UInt8(ascii: "\\") && start + 1 < lineEnd && text.bytes[start + 1] == UInt8(ascii: "\"")
        if byte == UInt8(ascii: "\"") || escapedQuote {
            hideQuoted(open: escapedQuote ? start + 1 : start, key: key, lineEnd: lineEnd)
        } else if byte == UInt8(ascii: "'") || byte == UInt8(ascii: "`") {
            hideSimplyQuoted(open: start, key: key, lineEnd: lineEnd)
        } else if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") {
            hideJSONValue(from: start, lineEnd: lineEnd)
            if let key, WrittenName.holdsNameInText(key), position < lineEnd, case .none = carry {
                hideAfterName(at: start, from: position, valueStart: position, lineEnd: lineEnd)
            }
        } else {
            // Where an unquoted value ends cannot be told: everything after the separator on the
            // line, from right after the separator so invisible characters before it go too.
            var from = text.offsets[separatorEnd - 1] + 1
            while from < source.count, Self.isBlank(source[from]) { from += 1 }
            hide(from..<text.offset(at: lineEnd))
            position = lineEnd
            // After a comment (`password: // rotate`), the value may be on the next line.
            let isComment = byte == UInt8(ascii: "#") || (byte == UInt8(ascii: "/") && start + 1 < lineEnd
                && (text.bytes[start + 1] == UInt8(ascii: "/") || text.bytes[start + 1] == UInt8(ascii: "*")))
            carry = isComment
                ? .valueOnNextLine(indent: lineIndent)
                : carryAfterHiding(from: start, valueStart: start, lineEnd: lineEnd, indent: lineIndent)
        }
    }

    /// A space of any kind that does not end a line.
    private static func isBlank(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .spaceSeparator: true
        default: scalar == "\t"
        }
    }

    /// A value in double quotes, also escaped as in `\"…\"`: hidden up to its closing quote, which
    /// may be on a later line.
    private mutating func hideQuoted(open: Int, key: [Unicode.Scalar]?, lineEnd: Int) {
        let escaped = isEscaped(open)
        let quote = UInt8(ascii: "\"")
        let contentStart = text.offsets[open] + 1
        guard let close = closingQuote(after: open, quote: quote, escaped: escaped, lineEnd: lineEnd) else {
            hide(contentStart..<text.offset(at: lineEnd))
            position = lineEnd
            carry = .openQuote(quote: quote, escaped: escaped, indent: lineIndent)
            return
        }
        hide(contentStart..<text.offsets[escaped ? close - 1 : close])
        guard !namesSecret(in: (open + 1)..<(escaped ? close - 1 : close), after: key) else {
            hideAfterQuotedName(open: open, close: close, lineEnd: lineEnd, quote: (quote, escaped))
            return
        }
        hideGluedText(after: close, lineEnd: lineEnd, quote: (quote, escaped))
    }

    /// A value in single quotes or backticks: hidden up to the closing one, which may be on a
    /// later line, as in a double-quoted value.
    private mutating func hideSimplyQuoted(open: Int, key: [Unicode.Scalar]?, lineEnd: Int) {
        let quote = text.bytes[open]
        guard let close = closingQuote(after: open, quote: quote, escaped: false, lineEnd: lineEnd) else {
            hide((text.offsets[open] + 1)..<text.offset(at: lineEnd))
            position = lineEnd
            carry = .openQuote(quote: quote, escaped: false, indent: lineIndent)
            return
        }
        hide((text.offsets[open] + 1)..<text.offsets[close])
        guard !namesSecret(in: (open + 1)..<close, after: key) else {
            hideAfterQuotedName(open: open, close: close, lineEnd: lineEnd, quote: (quote, false))
            return
        }
        hideGluedText(after: close, lineEnd: lineEnd, quote: (quote, false))
    }

    /// A quoted value that names a secret (`name="password" hunter2`, `<string name="api_key">`)
    /// names what follows it, which is hidden (see ``hideAfterName(at:from:valueStart:lineEnd:)``).
    /// Text glued to the closing quote means that quote may have opened another value, as after
    /// any other quoted value (see ``hideGluedText(after:lineEnd:quote:)``).
    private mutating func hideAfterQuotedName(open: Int, close: Int, lineEnd: Int, quote: (UInt8, Bool)) {
        hideAfterName(at: open + 1, from: close + 1, valueStart: close + 1, lineEnd: lineEnd)
        let next = close + 1
        guard next < lineEnd, !text.isSpace(next), !Self.valueEnds.contains(text.bytes[next]) else { return }
        if case .openQuote = carry { return }
        carry = .openQuote(quote: quote.0, escaped: quote.1, indent: lineIndent)
    }

    /// A JSON object or array is hidden whole; one that does not parse, or is deeper than the
    /// depth left, is hidden to the end of its line and on until its brackets close. Only the
    /// extent of the value is read, never what is in it.
    private mutating func hideJSONValue(from start: Int, lineEnd: Int) {
        if let document = try? JSONDocument(source, at: text.offsets[start], nesting: nesting) {
            hide(document.root.range)
            let end = text.byteIndex(atOrAfter: document.root.range.upperBound)
            if end <= lineEnd { hideGluedText(after: end - 1, lineEnd: lineEnd) } else { position = end }
        } else {
            hideUnparsedJSON(from: start, lineEnd: lineEnd)
        }
    }

    /// Text glued to the end of a hidden value (`"x"y`, as a shell joins them) continues it: the
    /// rest of the line is hidden. A space, a boundary or a closing bracket ends the value.
    ///
    /// After a quoted value, glued text also means the quote that seemed to close it may have
    /// opened another value (`"a="b` / `c"`), so the value goes on until a line with that quote.
    private mutating func hideGluedText(after close: Int, lineEnd: Int, quote: (UInt8, Bool)? = nil) {
        let next = close + 1
        guard next < lineEnd, !text.isSpace(next), !Self.valueEnds.contains(text.bytes[next]) else {
            position = next
            return
        }
        hide((text.offsets[close] + 1)..<text.offset(at: lineEnd))
        position = lineEnd
        let carried = carryAfterHiding(from: next, valueStart: next, lineEnd: lineEnd, indent: lineIndent)
        if case .openQuote = carried {
            carry = carried
        } else if let (quote, escaped) = quote {
            carry = .openQuote(quote: quote, escaped: escaped, indent: lineIndent)
        } else {
            carry = carried
        }
    }

    private static let valueEnds: Set<UInt8> = Set(",;&|)]}>".utf8)

    // MARK: Quotes

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

    /// The next `quote` after `open` on the line that closes it: escaped like the opening one
    /// (`\"…\"` in escaped JSON) or not escaped.
    func closingQuote(after open: Int, quote: UInt8, escaped: Bool, lineEnd: Int) -> Int? {
        var k = open + 1
        while k < lineEnd {
            if text.bytes[k] == quote, isEscaped(k) == escaped { return k }
            k += 1
        }
        return nil
    }
}
