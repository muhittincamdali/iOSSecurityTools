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
            // In `user%5Bpassword%5D` the name starts after the `5B` of the encoded `[`.
            let start = i > 0 && bracketLength(at: i - 1, closing: false) == 3 ? i + 2 : i
            let name = start..<end
            guard !name.isEmpty, namesSecret(name) || joinedName(endingWith: name).map(spellsSecret) == true else {
                i = end
                continue
            }
            let afterBrackets = indexAfterBrackets(of: name)
            guard let value = valueRange(from: afterBrackets) ?? elementContent(after: name) else {
                // A name inside the brackets that follow has no value either: its brackets end at
                // the same place. Going on from there keeps `[password][password]…` linear.
                i = max(end, afterBrackets)
                continue
            }
            spans.append(span(value, .secretFields, SensitiveDataRedactor.replacement))
            i = value.upperBound
        }
        return spans
    }

    // MARK: Field names

    /// `_`, `-` and `.` between the words of a name, and the spaces of a name joined across them
    /// (see ``joinedName(endingWith:)``).
    private func isSeparator(_ i: Int) -> Bool {
        [UInt8(ascii: "_"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: " "), UInt8(ascii: "\t")].contains(bytes[i])
    }

    private func isIdentifierCharacter(_ i: Int) -> Bool {
        isAlphanumeric(i) || (isSeparator(i) && !isSpace(i)) || bytes[i] == LatinFolding.unreadableLetter
    }

    /// The longest secret word, in letters.
    private static let longestSecretWord = SensitiveDataRedactor.secretFieldNames.map(\.count).max() ?? 0

    /// The name together with the words before it when they are only spaces apart, as long as
    /// the words before it are short enough to hold part of a secret word: `pass word` and
    /// `api key` in `pass word=hunter2` and `API key: abc`. Nil when no word comes before it.
    private func joinedName(endingWith name: Range<Int>) -> Range<Int>? {
        var start = name.lowerBound
        var letters = 0
        while true {
            var gapStart = start
            while gapStart > 0, start - gapStart < 3, isSpace(gapStart - 1) { gapStart -= 1 }
            guard gapStart < start, gapStart > 0, isIdentifierCharacter(gapStart - 1) else { break }
            var wordStart = gapStart
            while wordStart > 0, isIdentifierCharacter(wordStart - 1), letters + gapStart - wordStart < Self.longestSecretWord {
                wordStart -= 1
            }
            // A word longer than any secret word cannot hold the start of one.
            guard wordStart == 0 || !isIdentifierCharacter(wordStart - 1) else { break }
            letters += gapStart - wordStart
            start = wordStart
        }
        return start < name.lowerBound ? start..<name.upperBound : nil
    }

    /// Whether a word of a field name starts at `i`: after `_`, `-` or `.`, between letters and digits,
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
        mixesScripts(name) || spellsSecret(name)
    }

    /// Whether a secret word is spelled in the name and reaches its last part, after the last `.`
    /// or space: `pass.word`, `api.key` and `client.secret` hold a secret, while `token.type` and
    /// `token.example.com` name something else, as `type` and `com` did before `.` joined them.
    private func spellsSecret(_ name: Range<Int>) -> Bool {
        let lastPart = (name.last { bytes[$0] == UInt8(ascii: ".") || isSpace($0) }).map { $0 + 1 } ?? name.lowerBound
        if SensitiveDataRedactor.wholeSecretFieldNames.contains((lastPart..<name.upperBound).map(lowercased)) { return true }
        for start in name where isLetter(start) && startsWord(start, in: name) {
            for secret in SensitiveDataRedactor.secretFieldNames {
                guard let end = spelledEnd(of: secret, from: start, in: name), end > lastPart, endsWord(end, in: name) else { continue }
                if !isDescribingWord(at: end, in: name) { return true }
            }
        }
        return false
    }

    /// Whether a name mixes Latin letters with letters of another script or Latin letters that
    /// have no ASCII reading (`passwдrd`). Such a name is written to look like another one, or
    /// cannot be read, so its value is hidden: the redactor fails closed.
    private func mixesScripts(_ name: Range<Int>) -> Bool {
        var hasLatin = false
        var hasForeign = false
        for i in name {
            if isForeignLetter[i] {
                hasForeign = true
            } else if isLetter(i) {
                hasLatin = true
            }
            if hasLatin, hasForeign { return true }
        }
        return false
    }

    /// Where `word` ends if it is spelled from `start`, ignoring separators between its letters.
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

    /// The value after a field name: `name: value`, `name=value`, `name := value`,
    /// `name == value`, `"name": "value"`, `\"name\":\"value\"` in JSON escaped inside another
    /// string, form fields such as `password[]=value`, `user[password]=value` and
    /// `user%5Bpassword%5D=value`, and `name%3Dvalue` with the `=` or `:` percent-encoded.
    /// `afterName` is where the text continues after the name and its brackets.
    private func valueRange(from afterName: Int) -> Range<Int>? {
        var j = afterName
        if isEscapedQuote(j) {
            j += 2
        } else if j < count, isQuote(j) {
            j += 1
        }
        j = indexAfterSpaces(from: j)
        // `?=` in a Makefile and `!=`: the first character belongs to the separator. The `+` of
        // `+=` was already passed over with the spaces.
        if j + 1 < count, [UInt8(ascii: "?"), UInt8(ascii: "!")].contains(bytes[j]), bytes[j + 1] == UInt8(ascii: "=") {
            j += 1
        }
        guard let afterSeparator = indexAfterSeparator(at: j) else { return nil }
        j = afterSeparator
        // `=>`: the `>` belongs to the separator.
        if j < count, bytes[j] == UInt8(ascii: ">") { j += 1 }
        // `:=` in Make, Go and Pascal, `==` and `===` in code, `::=` and `= =`: every `=` or `:`
        // that follows, with or without spaces between, belongs to the separator too.
        j = indexAfterSpaces(from: j)
        while let next = indexAfterSeparator(at: j) { j = indexAfterSpaces(from: next) }
        guard j < count else { return nil }

        if isEscapedQuote(j) { return escapedQuotedValue(from: j + 2, quote: bytes[j + 1]) }
        if isQuote(j) { return quotedValue(from: j + 1, quote: bytes[j]) }
        // `password: <hunter2>`: the value inside angle brackets, or after a `<` that is not closed.
        if bytes[j] == UInt8(ascii: "<") {
            if let value = angleBracketedValue(from: j + 1) { return value }
            j += 1
        }

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

    /// Where the text continues after the `]` that closes `user[password` and after brackets that
    /// follow a name, as in `password[]` and `password[0]`. Brackets can be percent-encoded, as
    /// form bodies send them: `user%5Bpassword%5D`.
    private func indexAfterBrackets(of name: Range<Int>) -> Int {
        var j = name.upperBound
        let isInBrackets = bracketLength(at: name.lowerBound - 1, closing: false) == 1
            || bracketLength(at: name.lowerBound - 3, closing: false) == 3
        if isInBrackets { j += bracketLength(at: j, closing: true) }
        while case let open = bracketLength(at: j, closing: false), open > 0 {
            var close = j + open
            while close < count, isIdentifierCharacter(close) { close += 1 }
            let closeLength = bracketLength(at: close, closing: true)
            guard closeLength > 0 else { break }
            j = close + closeLength
        }
        return j
    }

    /// The length of the `[`, or of the `]` when `closing`, at `i`: 1, or 3 when it is
    /// percent-encoded as `%5B` or `%5D`; 0 when there is none.
    private func bracketLength(at i: Int, closing: Bool) -> Int {
        guard i >= 0, i < count else { return 0 }
        if bytes[i] == (closing ? UInt8(ascii: "]") : UInt8(ascii: "[")) { return 1 }
        let isEncoded = i + 2 < count && bytes[i] == UInt8(ascii: "%") && bytes[i + 1] == UInt8(ascii: "5")
            && lowercased(i + 2) == (closing ? UInt8(ascii: "d") : UInt8(ascii: "b"))
        return isEncoded ? 3 : 0
    }

    /// Where the text continues after spaces at `i`, also written as form bodies encode them:
    /// `+` and `%20`.
    private func indexAfterSpaces(from i: Int) -> Int {
        var j = i
        while j < count {
            if isSpace(j) || bytes[j] == UInt8(ascii: "+") {
                j += 1
            } else if j + 2 < count, bytes[j] == UInt8(ascii: "%"), bytes[j + 1] == UInt8(ascii: "2"), bytes[j + 2] == UInt8(ascii: "0") {
                j += 3
            } else {
                break
            }
        }
        return j
    }

    /// Where the value starts after a `:` or `=` at `i`. Written as `%3A`, `%3D` or another
    /// escape, it is already decoded.
    private func indexAfterSeparator(at i: Int) -> Int? {
        guard i < count, bytes[i] == UInt8(ascii: ":") || bytes[i] == UInt8(ascii: "=") else { return nil }
        return i + 1
    }

    /// The content of an XML element named like a secret, `<password>value</password>`, also with
    /// attributes or a namespace prefix (`<wsse:Password Type="…">`): up to the next `<`, or to
    /// the end of the line when no `<` follows.
    private func elementContent(after name: Range<Int>) -> Range<Int>? {
        guard isElementName(name), let start = indexAfterStartTag(from: name.upperBound) else { return nil }
        var end = start
        var lineEnd: Int?
        while end < count, bytes[end] != UInt8(ascii: "<") {
            if lineEnd == nil, bytes[end] == UInt8(ascii: "\n") { lineEnd = end }
            end += 1
        }
        if end == count, let lineEnd { end = lineEnd }
        return end > start ? start..<end : nil
    }

    /// Whether `name` is the name in a start tag: right after `<`, or after a prefix such as `<ns:`.
    private func isElementName(_ name: Range<Int>) -> Bool {
        let i = name.lowerBound
        guard i > 0 else { return false }
        if bytes[i - 1] == UInt8(ascii: "<") { return true }
        guard bytes[i - 1] == UInt8(ascii: ":") else { return false }
        var prefixStart = i - 1
        while prefixStart > 0, isIdentifierCharacter(prefixStart - 1) { prefixStart -= 1 }
        return prefixStart < i - 1 && prefixStart > 0 && bytes[prefixStart - 1] == UInt8(ascii: "<")
    }

    /// Where the content starts after the rest of a start tag at `i`: a `>` right away, or space,
    /// attributes and then `>`. Nil for an empty tag (`<password/>`) and for a tag that a `<` or
    /// the end of the text cuts short; a `>` inside a quoted attribute value does not end the tag.
    private func indexAfterStartTag(from i: Int) -> Int? {
        guard i < count else { return nil }
        if bytes[i] == UInt8(ascii: ">") { return i + 1 }
        guard isSpace(i) || bytes[i] == UInt8(ascii: "\n") || bytes[i] == UInt8(ascii: "\r") else { return nil }
        var quote: UInt8?
        for j in i..<count {
            if bytes[j] == UInt8(ascii: "<") { return nil }
            if let open = quote {
                if bytes[j] == open { quote = nil }
            } else if isQuote(j) {
                quote = bytes[j]
            } else if bytes[j] == UInt8(ascii: ">") {
                return bytes[j - 1] == UInt8(ascii: "/") ? nil : j + 1
            }
        }
        return nil
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

    /// A value up to the `>` that closes it on the same line; nil when a `<` or the end of the line
    /// comes first. Stopping at the next `<` keeps the scans of `password:<…` repeated apart.
    private func angleBracketedValue(from start: Int) -> Range<Int>? {
        var end = start
        while end < count, ![UInt8(ascii: ">"), UInt8(ascii: "<"), UInt8(ascii: "\n"), UInt8(ascii: "\r")].contains(bytes[end]) {
            end += 1
        }
        guard end < count, bytes[end] == UInt8(ascii: ">"), end > start else { return nil }
        return start..<end
    }

    private func isValueTerminator(_ i: Int) -> Bool {
        isSpace(i) || [
            UInt8(ascii: "\n"), UInt8(ascii: "\r"), UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "&"),
            UInt8(ascii: "}"), UInt8(ascii: "]"), UInt8(ascii: ")"), UInt8(ascii: "\""), UInt8(ascii: "'"),
            UInt8(ascii: "<"), UInt8(ascii: ">"),
        ].contains(bytes[i])
    }
}
