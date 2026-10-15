/// Finds the values of secret fields in text that has no structure to parse, such as a log line
/// or an error message. This is the free-text rule; ``SensitiveDataRedactor`` documents it.
///
/// It reads Unicode scalars, not `Character`s: a combining mark after a quote or a separator
/// would join them into one `Character` and hide them from the scan.
struct FreeTextFields {
    let scalars: [Unicode.Scalar]
    let bounds: Range<Int>
    let compatibility: CompatibilityText

    /// A name that cannot be longer than this is all a name before another one needs to be read.
    private static let wordLookBehind = 64

    func spans() -> [SensitiveDataRedactor.Span] {
        fieldSpans() + elementSpans()
    }

    var upper: Int { bounds.upperBound }

    private func fieldSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = bounds.lowerBound
        // A name never reaches back past the previous separator or hidden value, so every
        // scalar is read a bounded number of times and the scan stays linear.
        var clamp = bounds.lowerBound
        while i < upper {
            let separatorEnd: Int
            let hidden: Bool
            let hasName: Bool
            if let end = separatorRunEnd(from: i) {
                let name = name(before: i, clamp: clamp)
                separatorEnd = end
                hasName = !name.range.isEmpty
                hidden = hides(name, clamp: clamp)
            } else if isLookAlikeSeparator(at: i, clamp: clamp) {
                // Where such a separator ends the name and where the value ends cannot be told
                // (`pass·word: hunter2`), so the rest of the line is hidden.
                separatorEnd = i + 1
                hasName = false
                hidden = true
            } else {
                i += 1
                continue
            }
            if hidden, let value = value(after: separatorEnd, hasName: hasName) {
                spans.append(SensitiveDataRedactor.Span(
                    start: value.lowerBound, end: value.upperBound, kind: .secretFields, replacement: SensitiveDataRedactor.replacement
                ))
                i = value.upperBound
            } else {
                i = separatorEnd
            }
            clamp = i
        }
        return spans
    }

    // MARK: Names

    struct Name {
        let range: Range<Int>
        let isQuoted: Bool
    }

    /// The name before a separator: the text in the quotes right before it, or the word right
    /// before it. Whitespace between the name and the separator, line breaks included, is skipped.
    private func name(before separator: Int, clamp: Int) -> Name {
        var end = separator
        while end > clamp, scalars[end - 1].properties.isWhitespace { end -= 1 }
        guard end > clamp else { return Name(range: end..<end, isQuoted: false) }
        if Self.isQuote(scalars[end - 1]) {
            // A quote that opens nowhere, or quotes glued to more of the name (`pass"word"`,
            // which a shell reads as `password`): everything back to the previous separator is
            // the name, and the quotes in it make it not plain.
            guard let content = quotedName(closingAt: end - 1, clamp: clamp) else { return Name(range: clamp..<end, isQuoted: false) }
            let opening = content.lowerBound - 1 - backslashCount(before: content.lowerBound - 1, clamp: clamp)
            guard opening == clamp || isNameDelimiter(scalars[opening - 1]) else { return Name(range: clamp..<end, isQuoted: false) }
            return Name(range: content, isQuoted: true)
        }
        // A name that ends in a bracket keeps its brackets (`user[password]`, `f(x)`), which make
        // it not plain.
        let keepsBrackets = scalars[end - 1] == "]" || scalars[end - 1] == ")"
        var start = wordStart(endingAt: end, limit: clamp, keepsBrackets: keepsBrackets)
        // In a closing tag, `</ns:password>`, the name is the namespace prefix without the `/`.
        if start < end, scalars[start] == "/", start > clamp, scalars[start - 1] == "<" { start += 1 }
        // A word glued to a closing quote (`"pass"word=`) is part of a longer name.
        if start > clamp, Self.isQuote(scalars[start - 1]) { return Name(range: clamp..<end, isQuoted: false) }
        return Name(range: start..<end, isQuoted: false)
    }

    /// The content of a quoted name whose closing quote is at `quote`: `"name"`, `'name'`, or
    /// `\"name\"` in JSON escaped inside a string; nil when no opening quote is on its line.
    private func quotedName(closingAt quote: Int, clamp: Int) -> Range<Int>? {
        let mark = scalars[quote]
        let backslashes = backslashCount(before: quote, clamp: clamp)
        // An odd number of backslashes makes `\"` the delimiter; an even number are escaped
        // backslashes at the end of the name.
        let isEscapedForm = backslashes % 2 == 1
        let contentEnd = isEscapedForm ? quote - backslashes : quote
        var k = contentEnd - 1
        while k >= clamp {
            let scalar = scalars[k]
            if Self.isLineBreak(scalar) { return nil }
            guard scalar == mark else {
                k -= 1
                continue
            }
            let run = backslashCount(before: k, clamp: clamp)
            if isEscapedForm ? run == backslashes : run % 2 == 0 { return (k + 1)..<contentEnd }
            if isEscapedForm, run < backslashes { return nil }
            k -= run + 1
        }
        return nil
    }

    /// Where the word that ends at `end` starts: back to whitespace or a name delimiter, with an
    /// HTML character reference (`&#97;`) inside the word, and with brackets inside it when
    /// `keepsBrackets`.
    private func wordStart(endingAt end: Int, limit: Int, keepsBrackets: Bool) -> Int {
        var start = end
        while start > limit {
            let scalar = scalars[start - 1]
            if scalar == ";", let entity = entityStart(endingAt: start - 1), entity >= limit {
                start = entity
                continue
            }
            let isBracket = keepsBrackets && (scalar == "[" || scalar == "]" || scalar == "(" || scalar == ")")
            guard isBracket || !isNameDelimiter(scalar) else { break }
            start -= 1
        }
        return start
    }

    private func backslashCount(before i: Int, clamp: Int) -> Int {
        var count = 0
        while i - count - 1 >= clamp, scalars[i - count - 1] == "\\" { count += 1 }
        return count
    }

    private func hides(_ name: Name, clamp: Int) -> Bool {
        guard !name.range.isEmpty else { return true }
        if name.isQuoted { return FieldName.hidesValue(scalars[name.range]) }
        guard let plain = PlainName(scalars[name.range]) else { return true }
        return plain.namesSecret || plain.continuesSecret(after: precedingWords(before: name.range.lowerBound, clamp: clamp))
    }

    /// The words before a name that only whitespace separates from it, nearest first.
    private func precedingWords(before nameStart: Int, clamp: Int) -> PrecedingWords {
        var words = PrecedingWords()
        var wordEnd = nameStart
        while !words.isFull {
            var end = wordEnd
            while end > clamp, scalars[end - 1].properties.isWhitespace { end -= 1 }
            guard end < wordEnd, end > clamp else { break }
            let limit = max(clamp, end - Self.wordLookBehind)
            let start = wordStart(endingAt: end, limit: limit, keepsBrackets: false)
            guard start < end else { break }
            let word = scalars[start..<end]
            guard word.allSatisfy(Self.isPlainWordCharacter) else {
                // Letters of other scripts, invisible characters, escapes and punctuation that
                // would make a name not plain can stand for anything.
                words.endsInUnreadableWord = true
                break
            }
            words.prepend(word.map { UInt8($0.value) })
            // Stop at a word that a delimiter or the look-behind limit cuts off.
            guard start > clamp, scalars[start - 1].properties.isWhitespace else { break }
            wordEnd = start
        }
        return words
    }

    /// A name that names a secret, once read through Unicode compatibility normalization and
    /// without invisible characters, followed by punctuation or a symbol outside ASCII that has
    /// no `=` or `:` form: `password꞉hunter2`, `𝐩𝐚𝐬𝐬𝐰𝐨𝐫𝐝 ꞉ hunter2`. No list of characters that
    /// look like `:` is complete, so after a secret name any of them counts as one.
    private func isLookAlikeSeparator(at i: Int, clamp: Int) -> Bool {
        let scalar = scalars[i]
        guard !scalar.isASCII, Self.isPunctuationOrSymbol(scalar),
              compatibility.ascii(scalar) == [CompatibilityText.unreadable]
        else { return false }
        var end = i
        while end > clamp, Self.isSpace(scalars[end - 1]) { end -= 1 }
        var start = end
        while start > clamp, !scalars[start - 1].properties.isWhitespace, !isNameDelimiter(scalars[start - 1]),
              !Self.isPunctuationOrSymbol(scalars[start - 1]) || scalars[start - 1].isASCII {
            start -= 1
        }
        var reading: [Unicode.Scalar] = []
        for scalar in scalars[start..<end] where !ScalarClass.isInvisible(scalar) {
            reading += compatibility.ascii(scalar).map { Unicode.Scalar($0) }
        }
        guard let plain = PlainName(reading) else { return false }
        return plain.namesSecret || plain.continuesSecret(after: precedingWords(before: start, clamp: clamp))
    }

    // MARK: Separators

    /// Where the run of separators that starts at `i` ends: `=`, `:=`, `==`, `= =`, `=>`, `?=`,
    /// `%3D`. Nil when no separator starts at `i`.
    private func separatorRunEnd(from i: Int) -> Int? {
        guard var end = separatorEnd(at: i, startsRun: true) else { return nil }
        while true {
            if end < upper, scalars[end] == ">", scalars[end - 1] == "=" { end += 1 }
            var next = end
            while next < upper, Self.isSpace(scalars[next]) { next += 1 }
            guard let after = separatorEnd(at: next, startsRun: false) else { return end }
            end = after
        }
    }

    private func separatorEnd(at i: Int, startsRun: Bool) -> Int? {
        guard i < upper else { return nil }
        let scalar = scalars[i]
        if scalar == "=" || scalar == ":" { return i + 1 }
        if startsRun, ["?", "!", "+", "<", ">"].contains(scalar), i + 1 < upper, scalars[i + 1] == "=" { return i + 2 }
        if scalar == "%" || scalar == "&" || scalar == "\\" {
            guard let escaped = EscapedSeparator(in: scalars, at: i, upper: upper) else { return nil }
            return escaped.end
        }
        return isSeparatorScalar(scalar) ? i + 1 : nil
    }

    /// `≔`, `∶` and characters whose compatibility form is made of `=` and `:` (`＝`, `：`, `︓`, `⩴`).
    func isSeparatorScalar(_ scalar: Unicode.Scalar) -> Bool {
        guard !scalar.isASCII else { return false }
        if scalar == "\u{2254}" || scalar == "\u{2236}" { return true }
        return compatibility.ascii(scalar).allSatisfy { $0 == UInt8(ascii: "=") || $0 == UInt8(ascii: ":") }
    }

    // MARK: Character classes

    /// Whitespace, quotes, brackets, `,`, `;`, `&`, `?` and separators end a name.
    func isNameDelimiter(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar {
        case "\"", "'", "`", "{", "}", "[", "]", "(", ")", "<", ">", ",", ";", "&", "?", "=", ":": return true
        default: break
        }
        if scalar.properties.isWhitespace { return true }
        return isSeparatorScalar(scalar)
    }

    static func isQuote(_ scalar: Unicode.Scalar) -> Bool { scalar == "\"" || scalar == "'" }

    /// ASCII letters and digits, and the `.`, `/`, `_` and `-` of versions, paths and plain
    /// names, which separate words.
    static func isPlainWordCharacter(_ scalar: Unicode.Scalar) -> Bool {
        scalar.isASCII && (ASCII.isAlphanumeric(UInt8(scalar.value)) || "./_-".unicodeScalars.contains(scalar))
    }

    /// `\n`, `\r`, vertical tab, form feed, next line and the line and paragraph separators.
    static func isLineBreak(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar {
        case "\n", "\r", "\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}": true
        default: false
        }
    }

    /// Whitespace that does not end a line.
    static func isSpace(_ scalar: Unicode.Scalar) -> Bool {
        scalar.properties.isWhitespace && !isLineBreak(scalar)
    }

    static func isPunctuationOrSymbol(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .dashPunctuation, .otherPunctuation, .mathSymbol, .currencySymbol, .modifierSymbol, .otherSymbol: true
        default: false
        }
    }
}
