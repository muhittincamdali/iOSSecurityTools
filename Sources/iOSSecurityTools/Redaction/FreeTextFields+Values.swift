extension FreeTextFields {
    // MARK: Values

    /// The value after a separator that ends at `separatorEnd`. When nothing follows on the
    /// separator's line, the value is on the next line that has text. A separator with no name
    /// before it cannot be read as a field, so the rest of its line is hidden.
    func value(after separatorEnd: Int, hasName: Bool) -> Range<Int>? {
        var j = separatorEnd
        while j < upper, Self.isSpace(scalars[j]) { j += 1 }
        guard hasName else { return restOfLine(from: j) }
        if j < upper, Self.isLineBreak(scalars[j]) {
            while j < upper, scalars[j].properties.isWhitespace { j += 1 }
        }
        guard j < upper else { return nil }
        if let block = blockScalar(at: j) { return block }
        // Closing brackets glued between the separator and a value (`<password:>hunter2`) do
        // not end it.
        while j < upper, Self.isClosingBracket(scalars[j]), j + 1 < upper, !scalars[j + 1].properties.isWhitespace { j += 1 }
        let first = scalars[j]
        if first == "\\", j + 1 < upper, Self.isQuote(scalars[j + 1]) { return escapedQuotedValue(from: j + 2, quote: scalars[j + 1]) }
        if Self.isQuote(first) { return quotedValue(at: j) }
        if Self.isOpeningBracket(first) { return bracketedValue(from: j) }
        return wordValue(from: j)
    }

    /// The rest of the line from `start`. When the line holds nothing more, the next line with
    /// text is hidden instead; when it ends with a separator, the next line is hidden with it.
    private func restOfLine(from start: Int) -> Range<Int>? {
        let end = lineEnd(from: start)
        var last = end
        while last > start, Self.isSpace(scalars[last - 1]) { last -= 1 }
        guard last == start || isSeparatorCharacter(scalars[last - 1]) else { return start..<end }
        var next = end
        while next < upper, scalars[next].properties.isWhitespace { next += 1 }
        guard next < upper else { return last > start ? start..<end : nil }
        return (last == start ? next : start)..<lineEnd(from: next)
    }

    private func lineEnd(from start: Int) -> Int {
        var end = start
        while end < upper, !Self.isLineBreak(scalars[end]) { end += 1 }
        return end
    }

    private func isSeparatorCharacter(_ scalar: Unicode.Scalar) -> Bool {
        scalar == "=" || scalar == ":" || isSeparatorScalar(scalar)
    }

    /// The text inside quotes, up to the closing quote or the end of the line. When the closing
    /// quote is followed by more than a delimiter (`"hun"x"ter2"`), that text is hidden too.
    private func quotedValue(at open: Int) -> Range<Int>? {
        let quote = scalars[open]
        let start = open + 1
        var end = start
        while end < upper, scalars[end] != quote, !Self.isLineBreak(scalars[end]) {
            end += scalars[end] == "\\" ? 2 : 1
        }
        end = min(end, upper)
        guard end < upper, scalars[end] == quote else { return end > start ? start..<end : nil }
        var after = end + 1
        guard after < upper, !isValueEnd(scalars[after]) else { return end > start ? start..<end : nil }
        while after < upper, !isValueEnd(scalars[after]) { after += 1 }
        return start..<after
    }

    /// A value quoted with `\"` in JSON escaped inside a string, up to the next `\"` that is not
    /// itself escaped in the inner JSON (`\\\"`), or the end of the line.
    private func escapedQuotedValue(from start: Int, quote: Unicode.Scalar) -> Range<Int>? {
        var end = start
        var innerEscape = false
        while end < upper, !Self.isLineBreak(scalars[end]) {
            guard scalars[end] == "\\", end + 1 < upper else {
                innerEscape = false
                end += 1
                continue
            }
            let next = scalars[end + 1]
            if next == quote, !innerEscape { break }
            innerEscape = next == "\\" ? !innerEscape : false
            end += 2
        }
        end = min(end, upper)
        return end > start ? start..<end : nil
    }

    /// A value in brackets, `[…]`, `{…}`, `(…)` or `<…>`, up to the bracket that closes it, across
    /// lines and over brackets inside quotes. A value that is never closed runs to the end of the
    /// text: what follows may still be part of it.
    private func bracketedValue(from start: Int) -> Range<Int> {
        var depth = 0
        var quote: Unicode.Scalar?
        var j = start
        while j < upper {
            let scalar = scalars[j]
            if scalar == "\\" {
                j += 2
                continue
            }
            if let open = quote {
                if scalar == open { quote = nil }
            } else if Self.isQuote(scalar) {
                quote = scalar
            } else if Self.isOpeningBracket(scalar) {
                depth += 1
            } else if Self.isClosingBracket(scalar) {
                depth -= 1
                if depth == 0 { return start..<(j + 1) }
            }
            j += 1
        }
        return start..<upper
    }

    /// A word up to whitespace or a delimiter; an HTML character reference (`&#100;`) inside it
    /// does not end it. After an authentication scheme (`Bearer`, `Basic`, …) or a YAML tag
    /// (`!!binary`) the word that follows belongs to the value.
    private func wordValue(from start: Int) -> Range<Int>? {
        let end = wordEnd(from: start)
        guard end > start else { return nil }
        let word = String(String.UnicodeScalarView(scalars[start..<end])).lowercased()
        guard Self.authenticationSchemes.contains(word) || word.hasPrefix("!") else { return start..<end }
        var next = end
        while next < upper, Self.isSpace(scalars[next]) { next += 1 }
        let nextEnd = wordEnd(from: next)
        return nextEnd > next ? start..<nextEnd : start..<end
    }

    private static let authenticationSchemes: Set<String> = ["bearer", "basic", "digest", "token", "negotiate", "ntlm"]

    /// A YAML block scalar: `|` or `>`, maybe with `-` or `+`, alone at the end of its line, and
    /// the indented lines below it, which hold the value. Nil when no indented line follows.
    private func blockScalar(at start: Int) -> Range<Int>? {
        guard scalars[start] == "|" || scalars[start] == ">" else { return nil }
        var indicatorEnd = start + 1
        if indicatorEnd < upper, scalars[indicatorEnd] == "-" || scalars[indicatorEnd] == "+" { indicatorEnd += 1 }
        var afterIndicator = indicatorEnd
        while afterIndicator < upper, Self.isSpace(scalars[afterIndicator]) { afterIndicator += 1 }
        guard afterIndicator == upper || Self.isLineBreak(scalars[afterIndicator]) else { return nil }
        var blockEnd = indicatorEnd
        var lineStart = afterIndicator + 1
        while lineStart < upper {
            let nextBreak = lineEnd(from: lineStart)
            let isBlank = scalars[lineStart..<nextBreak].allSatisfy(Self.isSpace)
            guard isBlank || Self.isSpace(scalars[lineStart]) else { break }
            if !isBlank { blockEnd = nextBreak }
            lineStart = nextBreak + 1
        }
        return blockEnd > indicatorEnd ? start..<blockEnd : nil
    }

    /// Where a word value ends: at whitespace or a delimiter. An HTML character reference
    /// (`&#100;`) does not end it and a quoted part glued to it (`x='hunter2'`) belongs to it. A
    /// `:` before whitespace ends it, so that in `pass:word: hunter2` that `:` is read again as a
    /// separator, one with no name before it.
    private func wordEnd(from start: Int) -> Int {
        var end = start
        while end < upper {
            let scalar = scalars[end]
            if scalar == "&", let entity = entityEnd(startingAt: end) {
                end = entity
                continue
            }
            if end > start, Self.isQuote(scalar), opensQuotedSection(at: end) {
                end = quotedSectionEnd(from: end)
                continue
            }
            if isColon(scalar), end + 1 == upper || scalars[end + 1].properties.isWhitespace { break }
            if isWordTerminator(scalar) { break }
            end += 1
        }
        return end
    }

    /// Whether a quote inside a word opens a quoted part, as after a separator (`x='…'`) or
    /// before more text (`x"…"`), rather than closing quotes around the whole field
    /// (`'Authorization: Bearer abc'`).
    private func opensQuotedSection(at quote: Int) -> Bool {
        if isSeparatorCharacter(scalars[quote - 1]) { return true }
        guard quote + 1 < upper else { return false }
        let next = scalars[quote + 1]
        return !isValueEnd(next) && !Self.isQuote(next)
    }

    /// The end of a quoted part that starts at `open`: after its closing quote, or at the end of
    /// the line.
    private func quotedSectionEnd(from open: Int) -> Int {
        let quote = scalars[open]
        var end = open + 1
        while end < upper, scalars[end] != quote, !Self.isLineBreak(scalars[end]) {
            end += scalars[end] == "\\" ? 2 : 1
        }
        guard end < upper else { return upper }
        return scalars[end] == quote ? end + 1 : end
    }

    private func isColon(_ scalar: Unicode.Scalar) -> Bool {
        scalar == ":" || (!scalar.isASCII && compatibility.ascii(scalar) == [UInt8(ascii: ":")])
    }

    private func isWordTerminator(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar {
        case ",", ";", "&", ")", "]", "}", "<", ">", "\"", "'": true
        default: scalar.properties.isWhitespace
        }
    }

    /// What may follow a closed quoted value: whitespace or a delimiter.
    private func isValueEnd(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar {
        case ",", ";", "&", ")", "]", "}", ">": true
        default: scalar.properties.isWhitespace
        }
    }

    static func isOpeningBracket(_ scalar: Unicode.Scalar) -> Bool { "[{(<".unicodeScalars.contains(scalar) }

    static func isClosingBracket(_ scalar: Unicode.Scalar) -> Bool { "]})>".unicodeScalars.contains(scalar) }
}
