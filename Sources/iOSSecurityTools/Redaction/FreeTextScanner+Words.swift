/// Words in free text: keys before a separator, and words that name a secret or cannot be read.
extension FreeTextScanner {
    /// What a word that no separator follows says about the text after it.
    enum WordReading: Equatable {
        case plain
        /// The word mixes scripts or holds a character that only hides text: it cannot be read
        /// with certainty.
        case ambiguous
        /// The word holds a secret name or an escaped `=` or `:`; a value starts at this byte:
        /// right after the secret word or at the escape, or at the end of the word.
        case valueStart(Int)
    }

    /// A run of characters up to white space, a separator, a quote or a boundary: a key when a
    /// separator follows, otherwise a word that hides the rest of the line when it names a secret
    /// (`password hunter2`, `PIN 1234`, also split by a space: `pass word`) or cannot be read. A
    /// key or word with a separator of its own in it, look-alike or escaped, holds its value too:
    /// it is hidden from there on. In every case the value may go on to the lines below (see
    /// ``carryAfterHiding(from:valueStart:lineEnd:indent:)``).
    mutating func word(lineEnd: Int) {
        let start = position
        let end = wordEnd(from: start, to: lineEnd)
        position = end
        if let embedded = embeddedSeparator(in: start..<end, lineEnd: lineEnd) {
            pendingKey = nil
            // The whole word may be a disguised name (`pass‧word`) whose value is below it.
            hideAfterName(at: start, from: embedded, valueStart: end, lineEnd: lineEnd)
            return
        }
        let next = firstNonSpace(from: end, to: lineEnd)
        if next < lineEnd, isSeparator(next) {
            pendingKey = start..<end
            return
        }
        pendingKey = nil
        guard role == .text, !isEndTag(start..<end) else { return }
        if isSeparatorWord(start..<end, lineEnd: lineEnd) {
            hideRestOfLine(from: next, valueStart: next, lineEnd: lineEnd)
            return
        }
        switch read(start..<end) {
        case .plain:
            guard let (secretEnd, nextWord) = secretEndAcrossSpace(after: start..<end, lineEnd: lineEnd) else { return }
            // `verification code: 1234`: the next word is a key whose value the scan hides.
            let afterNextWord = firstNonSpace(from: nextWord.upperBound, to: lineEnd)
            if secretEnd == nextWord.upperBound, afterNextWord < lineEnd, isSeparator(afterNextWord), !allowsValue(ofKey: nextWord) {
                return
            }
            let from = firstNonSpace(from: secretEnd, to: lineEnd)
            hideAfterName(at: start, from: from, valueStart: from, lineEnd: lineEnd)
        case .ambiguous:
            hideAfterName(at: start, from: start, valueStart: end, lineEnd: lineEnd)
        case .valueStart(let valueStart):
            let from = valueAfterName(from: valueStart, wordEnd: end, lineEnd: lineEnd)
            hideAfterName(at: start, from: from, valueStart: from, lineEnd: lineEnd)
        }
    }

    /// A secret word split by white space or by one of `|`, `,`, `;`, `&` and `?` (`pass word`,
    /// `to ken`, `p|wd`): the byte after it, when it starts in this word and ends in the next one
    /// on the line, and that next word.
    private func secretEndAcrossSpace(after word: Range<Int>, lineEnd: Int) -> (Int, Range<Int>)? {
        var nextStart = firstNonSpace(from: word.upperBound, to: lineEnd)
        if nextStart < lineEnd, Self.splittingBoundaries.contains(text.bytes[nextStart]) {
            nextStart = firstNonSpace(from: nextStart + 1, to: lineEnd)
        }
        guard nextStart > word.upperBound, nextStart < lineEnd, !endsWord(nextStart) else { return nil }
        let next = nextStart..<wordEnd(from: nextStart, to: lineEnd)
        guard let reading = LooseReading(text, [word, next], source: source) else { return nil }
        let split = reading.letterCount(before: nextStart)
        return reading.secretEnd { $0.lowerBound < split && $0.upperBound > split }.map { ($0, next) }
    }

    private static let splittingBoundaries = ByteSet("|,;&?")

    /// Whether the word is the name of an end tag (`</key>`): it closes an element and names no
    /// value, so `<key>user</key>` names nothing on the lines below it.
    private func isEndTag(_ word: Range<Int>) -> Bool {
        guard word.count >= 2, word.lowerBound > 0, text.bytes[word.lowerBound - 1] == UInt8(ascii: "<"),
              text.bytes[word.lowerBound] == UInt8(ascii: "/") else { return false }
        var k = word.lowerBound + 1
        while k < word.upperBound, ASCII.isAlphanumeric(text.bytes[k]) || "-_:.".utf8.contains(text.bytes[k]) { k += 1 }
        let endsName = k == word.upperBound || (text.bytes[k] == UInt8(ascii: ">") && k + 1 == word.upperBound)
        return k > word.lowerBound + 1 && endsName
    }

    /// Punctuation, a math symbol or a modifier letter or symbol outside ASCII, such as `꞉`, `∶`,
    /// `≔`, `→` or `·`, may be meant as a separator. Glued between other characters of a word
    /// (`user꞉bob`, `e%79≔…`, `token·"…"`), and written as `%3D`, `&#61;` or `\u003A`, it
    /// separates a key from its value, so the value starts there. Glued, a connector without an
    /// ASCII form separates too (`user‿bob`); between words of prose it does not. A dash of any
    /// kind is read as `-` (see ``CompatibilityText``), which joins words. Quotation marks,
    /// brackets, currency signs, emoji and the punctuation of East Asian scripts are not read this
    /// way.
    private func embeddedSeparator(in range: Range<Int>, lineEnd: Int) -> Int? {
        let first = text.offsets[range.lowerBound]
        // At the start of a word, such a character separates the text before it on the line
        // (`a ≔b`, `a;꞉b`), or the word that ended the line before at a break other than LF.
        let followsText = firstNonSpace(from: lineStartOfText, to: lineEnd) < range.lowerBound || lineFollowsBrokenWord
        let glued = range.first { k in
            guard text.offsets[k] > first || followsText, isSeparatorLike(k, glued: true) else { return false }
            let after = scalarEnd(k)
            return after < range.upperBound || (range.upperBound < lineEnd && !text.isSpace(range.upperBound))
        }
        return [glued, escapedValueStart(in: range)].compactMap { $0 }.min()
    }

    /// The byte after the bytes that the scalar of byte `i` became.
    private func scalarEnd(_ i: Int) -> Int {
        var k = i + 1
        while k < text.count, text.offsets[k] == text.offsets[i] { k += 1 }
        return k
    }

    /// Whether the word is only such characters, between another word and more text on its line
    /// (`user ꞉ bob`).
    private func isSeparatorWord(_ range: Range<Int>, lineEnd: Int) -> Bool {
        guard range.allSatisfy({ isSeparatorLike($0) }) else { return false }
        let followsWord = firstNonSpace(from: lineStartOfText, to: lineEnd) < range.lowerBound || lineFollowsBrokenWord
        return followsWord && firstNonSpace(from: range.upperBound, to: lineEnd) < lineEnd
    }

    /// A character without an ASCII reading that may be a separator; one that has an ASCII
    /// reading (`．`, `‥`, `－`) is read as that. With `glued`, for a character between other
    /// characters of a word, connectors count too.
    private func isSeparatorLike(_ i: Int, glued: Bool = false) -> Bool {
        guard text.bytes[i] == CompatibilityText.unreadable else { return false }
        let scalar = source[text.offsets[i]]
        switch scalar.properties.generalCategory {
        case .otherPunctuation, .mathSymbol, .modifierLetter, .modifierSymbol: break
        case .connectorPunctuation:
            guard glued else { return false }
        default: return false
        }
        // `、`, `。`, `ー` and `・` belong to the East Asian text around them, but not to ASCII.
        return !Self.isEastAsian(scalar) || (i > 0 && text.bytes[i - 1] != CompatibilityText.unreadable && !text.isSpace(i - 1))
    }

    /// CJK symbols and punctuation, kana and the full-width and half-width forms (the full-width
    /// `＝` and `：` are read as separators already).
    private static func isEastAsian(_ scalar: Unicode.Scalar) -> Bool {
        (0x3000...0x30FF).contains(scalar.value) || (0xFF00...0xFFEF).contains(scalar.value)
    }

    /// Where the value after a secret name starts: after the quotes and brackets that close
    /// around the name (`<password>`, `"token"`), and after the spaces when the name ends the word.
    private mutating func valueAfterName(from cut: Int, wordEnd: Int, lineEnd: Int) -> Int {
        var k = cut
        while k < lineEnd, pairedQuotes.contains(k) || Self.closingMarks.contains(text.bytes[k]) {
            pairedQuotes.remove(k)
            k += 1
        }
        return k >= wordEnd ? firstNonSpace(from: max(k, wordEnd), to: lineEnd) : k
    }

    private static let closingMarks = ByteSet(")]}>")

    /// The end of the word that starts at `start`. An HTML character reference (`&#97;`) and a
    /// `\u{…}` escape are part of a word, though `&`, `;` and `{` end words elsewhere.
    func wordEnd(from start: Int, to lineEnd: Int) -> Int {
        var end = start
        while end < lineEnd {
            if let length = referenceLength(at: end) ?? bracedEscapeLength(at: end) {
                end += length
            } else if end > start, endsWord(end) {
                break
            } else {
                end += 1
            }
        }
        return min(end, lineEnd)
    }

    func endsWord(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        return text.isSpace(i) || text.isLineTerminator(i) || isSeparator(i) || byte == UInt8(ascii: "\"") || Self.boundaries.contains(byte)
    }

    /// The length of `&#NN;` or `&#xHH;` at `i`, also without the `;` (`&#61`) and behind `&amp;`
    /// (`&amp;#97;`), or of `&amp;` alone, or nil.
    func referenceLength(at i: Int) -> Int? {
        guard text.bytes[i] == UInt8(ascii: "&") else { return nil }
        var k = i + 1
        if k + 4 <= text.count, text.bytes[k..<(k + 4)].elementsEqual("amp;".utf8) {
            k += 4
            guard k < text.count, text.bytes[k] == UInt8(ascii: "#") else { return k - i }
        }
        guard k + 1 < text.count, text.bytes[k] == UInt8(ascii: "#") else { return nil }
        let isHex = text.bytes[k + 1] | 0x20 == UInt8(ascii: "x")
        k += isHex ? 2 : 1
        let digitsStart = k
        while k < text.count, k - digitsStart < EscapeDecoder.maximumReferenceDigits,
              isHex ? Self.isHexDigit(text.bytes[k]) : ASCII.isDigit(text.bytes[k]) {
            k += 1
        }
        guard k > digitsStart else { return nil }
        return (k < text.count && text.bytes[k] == UInt8(ascii: ";") ? k + 1 : k) - i
    }

    /// The length of `\u{…}` at `i`, or nil.
    private func bracedEscapeLength(at i: Int) -> Int? {
        guard text.bytes[i] == UInt8(ascii: "\\"), i + 3 < text.count, text.bytes[i + 1] == UInt8(ascii: "u"), text.bytes[i + 2] == UInt8(ascii: "{")
        else { return nil }
        var k = i + 3
        while k < text.count, k - i < 12, Self.isHexDigit(text.bytes[k]) { k += 1 }
        guard k > i + 3, k < text.count, text.bytes[k] == UInt8(ascii: "}") else { return nil }
        return k + 1 - i
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        ASCII.isDigit(byte) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte | 0x20)
    }
}
