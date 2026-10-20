/// Values that go on past the end of their line: what a line leaves open for the lines below it.
extension FreeTextScanner {
    /// Hides from byte `start` to the end of the line, and passes the value on to the lines below
    /// (see ``carryAfterHiding(from:valueStart:lineEnd:indent:)``). The trigger pass hides no
    /// value.
    mutating func hideRestOfLine(from start: Int, valueStart: Int, lineEnd: Int) {
        guard pass == .hiding else { return }
        if start < lineEnd { hide(fromByte: start, toLineEnd: lineEnd) }
        position = max(position, lineEnd)
        carry = carryAfterHiding(from: start, valueStart: valueStart, lineEnd: lineEnd, indent: lineIndent)
    }

    /// What a value hidden from byte `start` to the end of its line leaves open:
    ///
    /// - A quote opened in the hidden text that does not close on the line goes on to the line
    ///   where it closes (see ``Carry/openQuote(quote:escaped:indent:)``).
    /// - When no letter or digit follows `valueStart` on the line, the line ends open (with
    ///   punctuation other than a closing quote or bracket or a full stop: `<key>`, `(`, `:`, `=`),
    ///   or it ends at a line break other than LF and CRLF (a lone CR, a vertical tab, U+2028),
    ///   the value may start on the next line with text, which is hidden too.
    /// - Otherwise the lines indented more than `indent`, and the line after a trailing `\`,
    ///   belong to the value.
    func carryAfterHiding(from start: Int, valueStart: Int, lineEnd: Int, indent: Int) -> Carry {
        if let (quote, escaped) = unclosedQuote(in: start..<lineEnd) {
            return .openQuote(quote: quote, escaped: escaped, indent: indent)
        }
        let hasValue = valueStart < lineEnd && (valueStart..<lineEnd).contains { text.isAlphanumeric($0) }
        guard hasValue, !endsOpen(lineEnd), !endsAtUnusualBreak(lineEnd) else { return .valueOnNextLine(indent: indent) }
        return .continuation(indent: indent, backslash: endsWithBackslash(lineEnd))
    }

    /// Whether the line ends with punctuation that may lead to a value below it: anything but a
    /// letter, a digit, a closing quote or bracket, `.`, `!`, `?` and `;`.
    private func endsOpen(_ lineEnd: Int) -> Bool {
        var k = lineEnd
        while k > 0, text.isSpace(k - 1) { k -= 1 }
        guard k > 0, !text.isLineTerminator(k - 1) else { return false }
        return !text.isAlphanumeric(k - 1) && !Self.closings.contains(text.bytes[k - 1])
    }

    private static let closings = ByteSet("\"'`)]}.!?;")

    /// A quote (`"`, `'` or a backtick, plain or escaped as `\"`) that may open a value in bytes
    /// `range` without closing it there: one written an odd number of times, or whose last one is
    /// directly followed by text, as an opening quote is (`"a` in `x="a="b`). Which quote closes
    /// which cannot be told, so either way the value may go on below. An apostrophe counts too.
    func unclosedQuote(in range: Range<Int>) -> (UInt8, Bool)? {
        // Each kind of quote, plain and escaped, in the order they are tried: `"`, `'`, backtick.
        var counts = [0, 0, 0, 0, 0, 0]
        var last = [0, 0, 0, 0, 0, 0]
        for k in range {
            guard let quote = Self.quotes.firstIndex(of: text.bytes[k]) else { continue }
            let kind = quote * 2 + (isEscaped(k) ? 1 : 0)
            counts[kind] += 1
            last[kind] = k
        }
        for kind in counts.indices where counts[kind] > 0 {
            let k = last[kind]
            if counts[kind] % 2 == 1 || (k + 1 < range.upperBound && opensText(at: k + 1)) || endsWithQuoteRun(k, in: range) {
                return (Self.quotes[kind / 2], kind % 2 == 1)
            }
        }
        return nil
    }

    /// Whether the quote at `k` ends a run of two or more at the end of the range, as a triple
    /// quote (`"""`) that opens a block of lines does.
    private func endsWithQuoteRun(_ k: Int, in range: Range<Int>) -> Bool {
        guard k > range.lowerBound, text.bytes[k - 1] == text.bytes[k] else { return false }
        return firstNonSpace(from: k + 1, to: range.upperBound) == range.upperBound
    }

    private static let quotes: [UInt8] = [UInt8(ascii: "\""), UInt8(ascii: "'"), UInt8(ascii: "`")]

    /// A letter, a digit, a character outside ASCII or a backslash: text that a quote opens.
    private func opensText(at i: Int) -> Bool {
        text.isAlphanumeric(i) || text.bytes[i] == CompatibilityText.unreadable || text.bytes[i] == UInt8(ascii: "\\")
    }

    /// Applies what the line before left open. Returns whether the rest of the line is scanned.
    mutating func continueCarry(lineStart: Int, lineEnd: Int) -> Bool {
        let textStart = firstNonSpace(from: lineStart, to: lineEnd)
        let hasText = textStart < lineEnd
        switch carry {
        case .none:
            return true
        case .valueOnNextLine(let indent):
            guard hasText else { return false }
            if isSeparator(textStart) {
                // `password` / `:` / `"value"` on three lines: the separator line passes the value on.
                carry = .none
                position = textStart
                separator(lineEnd: lineEnd)
                return true
            }
            hide(fromByte: textStart, toLineEnd: lineEnd)
            // A line of punctuation only (`(`, `|`, `---`) passes the value on again.
            carry = carryAfterHiding(from: textStart, valueStart: textStart, lineEnd: lineEnd, indent: indent)
            return false
        case .continuation(let indent, let backslash):
            guard hasText else { return false }
            guard backslash || lineIndent > indent else {
                carry = .none
                return true
            }
            hide(fromByte: textStart, toLineEnd: lineEnd)
            carry = carryAfterHiding(from: textStart, valueStart: textStart, lineEnd: lineEnd, indent: indent)
            return false
        case .markup(let element, let indent, let fallback):
            return continueElement(element, indent: indent, fallback: fallback, lineStart: lineStart, lineEnd: lineEnd)
        case .brackets(let depth, let indent):
            return continueBrackets(depth: depth, indent: indent, lineStart: lineStart, lineEnd: lineEnd)
        case .part(let delimiter, let state):
            return continuePart(delimiter: delimiter, state: state, lineStart: lineStart, lineEnd: lineEnd)
        case .openQuote(let quote, let escaped, let indent):
            // The line where the value closes is hidden whole: what follows the closing quote
            // cannot be told from the rest of the value (`msg="a=` / `"b"…`).
            hide(fromByte: lineStart, toLineEnd: lineEnd)
            guard let close = closingQuote(after: lineStart - 1, quote: quote, escaped: escaped, lineEnd: lineEnd) else { return false }
            // Quotes after the closing one (`"""`) may open another value: which quote closes
            // which cannot be told, so the value goes on.
            if close + 1 < lineEnd, !text.isSpace(close + 1), unclosedQuote(in: (close + 1)..<lineEnd) == nil {
                // Text glued to the quote: it may have opened another value (`"a` / `b""`).
                carry = .openQuote(quote: quote, escaped: escaped, indent: indent)
            } else if firstNonSpace(from: close + 1, to: lineEnd) < lineEnd {
                // More after the value on its last line (`" =`, `" "b`) is read like a value.
                carry = carryAfterHiding(from: close + 1, valueStart: close + 1, lineEnd: lineEnd, indent: indent)
            } else {
                carry = .continuation(indent: indent, backslash: endsWithBackslash(lineEnd))
            }
            return false
        }
    }

    func endsWithBackslash(_ lineEnd: Int) -> Bool {
        var k = lineEnd
        while k > 0, text.isSpace(k - 1) { k -= 1 }
        return k > 0 && text.bytes[k - 1] == UInt8(ascii: "\\")
    }

    private func endsAtUnusualBreak(_ lineEnd: Int) -> Bool {
        guard lineEnd < text.count else { return false }
        let scalar = source[text.offsets[lineEnd]]
        if scalar == "\n" { return false }
        return !(scalar == "\r" && lineEnd + 1 < text.count && source[text.offsets[lineEnd + 1]] == "\n")
    }

    /// Whether the line ends at U+2028, U+2029, U+0085, a vertical tab or a form feed (and, with
    /// `orAtCR`, a CR without LF) after a word and spaces at most: a break that logs do not write
    /// between lines, and that can split a key from its separator.
    func breaksWord(at lineEnd: Int, orAtCR: Bool = false) -> Bool {
        var k = lineEnd
        while k > 0, text.isSpace(k - 1) { k -= 1 }
        guard k > 0, lineEnd < text.count, !text.isLineTerminator(k - 1) else { return false }
        let scalar = source[text.offsets[lineEnd]]
        if scalar == "\r" { return orAtCR && endsAtUnusualBreak(lineEnd) }
        return scalar != "\n"
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

    func lineStart(before i: Int) -> Int {
        var start = i
        while start > 0, !text.isLineTerminator(start - 1) { start -= 1 }
        return start
    }

    func firstNonSpace(from i: Int, to lineEnd: Int) -> Int {
        var k = i
        while k < lineEnd, text.isSpace(k) { k += 1 }
        return k
    }

    func indentation(from lineStart: Int, to lineEnd: Int) -> Int {
        firstNonSpace(from: lineStart, to: lineEnd) - lineStart
    }
}
