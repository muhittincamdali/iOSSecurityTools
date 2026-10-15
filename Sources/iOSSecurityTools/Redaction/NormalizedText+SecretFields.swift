import Foundation

extension NormalizedText {
    // MARK: Secret fields

    func secretFieldSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i < count {
            guard isIdentifierCharacter(i), i == 0 || !isIdentifierCharacter(i - 1) else {
                i += 1
                continue
            }
            var end = i
            while end < count, isIdentifierCharacter(end) { end += 1 }
            guard namesSecret(i..<end), let value = valueRange(after: end) else {
                i = end
                continue
            }
            spans.append(span(value, .secretFields, SensitiveDataRedactor.replacement))
            i = value.upperBound
        }
        return spans
    }

    // MARK: Field names

    private func isSeparator(_ i: Int) -> Bool { bytes[i] == UInt8(ascii: "_") || bytes[i] == UInt8(ascii: "-") }

    private func isIdentifierCharacter(_ i: Int) -> Bool { isAlphanumeric(i) || isSeparator(i) }

    /// Whether a word of a field name starts at `i`: after `_` or `-`, between letters and digits,
    /// at a camel-case hump (`accessToken`) or at the last capital of an acronym (`AWSSecret`).
    private func startsWord(_ i: Int, in name: Range<Int>) -> Bool {
        guard i > name.lowerBound else { return true }
        guard i < name.upperBound, !isSeparator(i) else { return false }
        if isSeparator(i - 1) || isDigit(i - 1) != isDigit(i) { return true }
        guard isUppercase[i], isLetter(i - 1) else { return false }
        if !isUppercase[i - 1] { return true }
        return i + 1 < name.upperBound && isLetter(i + 1) && !isUppercase[i + 1]
    }

    private func endsWord(_ i: Int, in name: Range<Int>) -> Bool {
        i == name.upperBound || isSeparator(i) || startsWord(i, in: name)
    }

    /// Whether a field name such as `password`, `aws_secret_access_key` or `passwordConfirm` holds
    /// a secret: a word of it begins a secret word that ends with a word of the name and is not
    /// followed by a word that only describes the secret (`passwordHint`, `token_type`).
    private func namesSecret(_ name: Range<Int>) -> Bool {
        for start in name where isLetter(start) && startsWord(start, in: name) {
            for secret in SensitiveDataRedactor.secretFieldNames {
                guard let end = spelledEnd(of: secret, from: start, in: name), endsWord(end, in: name) else { continue }
                if !isDescribingWord(at: end, in: name) { return true }
            }
        }
        return false
    }

    /// Where `word` ends if it is spelled from `start`, ignoring `_` and `-` between its letters.
    private func spelledEnd(of word: [UInt8], from start: Int, in name: Range<Int>) -> Int? {
        var j = start
        for (k, byte) in word.enumerated() {
            if k > 0 { while j < name.upperBound, isSeparator(j) { j += 1 } }
            guard j < name.upperBound, lowercased(j) == byte else { return nil }
            j += 1
        }
        return j
    }

    private func isDescribingWord(at wordEnd: Int, in name: Range<Int>) -> Bool {
        var start = wordEnd
        while start < name.upperBound, isSeparator(start) { start += 1 }
        guard start < name.upperBound else { return false }
        var end = start + 1
        while !endsWord(end, in: name) { end += 1 }
        return SensitiveDataRedactor.describingWords.contains((start..<end).map(lowercased))
    }

    // MARK: Values

    /// The value after a field name: `name: value`, `name=value`, `"name": "value"`, and
    /// `\"name\":\"value\"` in JSON escaped inside another string.
    private func valueRange(after nameEnd: Int) -> Range<Int>? {
        var j = nameEnd
        if isEscapedQuote(j) {
            j += 2
        } else if j < count, isQuote(j) {
            j += 1
        }
        while j < count, isSpace(j) { j += 1 }
        guard j < count, bytes[j] == UInt8(ascii: ":") || bytes[j] == UInt8(ascii: "=") else { return nil }
        j += 1
        if j < count, bytes[j] == UInt8(ascii: ">") { j += 1 }
        while j < count, isSpace(j) { j += 1 }
        guard j < count else { return nil }

        if isEscapedQuote(j) { return escapedQuotedValue(from: j + 2, quote: bytes[j + 1]) }
        if isQuote(j) { return quotedValue(from: j + 1, quote: bytes[j]) }

        let start = j
        var end = start
        while end < count, !isValueTerminator(end) { end += 1 }
        guard end > start else { return nil }
        // "Authorization: Bearer <token>": the scheme is not the secret, the token after it is.
        let scheme = string(start..<end).lowercased()
        if ["bearer", "basic", "digest", "token"].contains(scheme) {
            var tokenStart = end
            while tokenStart < count, isSpace(tokenStart) { tokenStart += 1 }
            var tokenEnd = tokenStart
            while tokenEnd < count, !isValueTerminator(tokenEnd) { tokenEnd += 1 }
            if tokenEnd > tokenStart { return start..<tokenEnd }
        }
        return start..<end
    }

    private func isQuote(_ i: Int) -> Bool { bytes[i] == UInt8(ascii: "\"") || bytes[i] == UInt8(ascii: "'") }

    private func isEscapedQuote(_ i: Int) -> Bool {
        i + 1 < count && bytes[i] == UInt8(ascii: "\\") && isQuote(i + 1)
    }

    /// A quoted value up to the closing quote or the end of the line; `\` escapes the next character.
    private func quotedValue(from start: Int, quote: UInt8) -> Range<Int>? {
        var end = start
        while end < count, bytes[end] != quote, bytes[end] != UInt8(ascii: "\n") {
            end += bytes[end] == UInt8(ascii: "\\") ? 2 : 1
        }
        end = min(end, count)
        return end > start ? start..<end : nil
    }

    /// A value quoted with `\"`, up to the next `\"` that is not itself escaped in the inner JSON
    /// (`\\\"`), or the end of the line.
    private func escapedQuotedValue(from start: Int, quote: UInt8) -> Range<Int>? {
        var end = start
        var innerEscape = false
        while end < count, bytes[end] != UInt8(ascii: "\n") {
            guard bytes[end] == UInt8(ascii: "\\"), end + 1 < count else {
                innerEscape = false
                end += 1
                continue
            }
            let next = bytes[end + 1]
            if next == quote, !innerEscape { break }
            innerEscape = next == UInt8(ascii: "\\") ? !innerEscape : false
            end += 2
        }
        return end > start ? start..<end : nil
    }

    private func isValueTerminator(_ i: Int) -> Bool {
        isSpace(i) || [
            UInt8(ascii: "\n"), UInt8(ascii: "\r"), UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "&"),
            UInt8(ascii: "}"), UInt8(ascii: "]"), UInt8(ascii: ")"), UInt8(ascii: "\""), UInt8(ascii: "'"),
            UInt8(ascii: "<"), UInt8(ascii: ">"),
        ].contains(bytes[i])
    }
}
