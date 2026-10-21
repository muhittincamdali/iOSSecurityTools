/// Words in free text: keys before a separator, and words that name a secret or cannot be read.
extension FreeTextScanner {
    /// What a word that no separator follows says about the text after it.
    enum WordReading: Equatable {
        case plain
        /// The word mixes scripts, holds a character that only hides text or is longer than
        /// ``longestWord``: it cannot be read with certainty.
        case ambiguous
        /// The word holds a secret name; a value starts at this byte, right after the secret word.
        case valueStart(Int)
    }

    /// A run of characters up to white space, a separator, a quote or a boundary: a key when a
    /// separator follows (see ``separator()``), otherwise a word. A word that holds a secret name
    /// (`password hunter2`, `PIN 1234`, also split by a space: `pass word`) hides what follows
    /// the name; one that cannot be read hides itself and what follows. A key or word longer than
    /// ``longestWord``, or with an escape in it, is not read: it hides itself and what follows.
    mutating func word() {
        let start = position
        let end = wordEnd(from: start, to: scanEnd)
        if isOpaque(start..<end) || holdsEscape(start..<end) {
            cut(atByte: start)
            return
        }
        let next = nextNonBlank(from: end)
        if next < text.count, isSeparator(next) {
            pendingKey = start..<end
            position = end
            return
        }
        pendingKey = nil
        guard role == .text else {
            position = end
            return
        }
        switch read(start..<end) {
        case .ambiguous:
            cut(atByte: start)
        case .valueStart(let valueStart):
            cut(atByte: self.valueStart(after: valueStart))
        case .plain:
            if let secretEnd = secretEndAcrossSpace(after: start..<end) {
                cut(atByte: valueStart(after: secretEnd))
            } else {
                position = end
            }
        }
    }

    /// A secret word split by white space or by one of `|`, `,`, `;`, `&` and `?` (`pass word`,
    /// `to ken`, `p|wd`): the byte after it, when it starts in this word and ends in the next one
    /// on the line. A next word longer than ``longestWord`` is not read with it.
    func secretEndAcrossSpace(after word: Range<Int>) -> Int? {
        var nextStart = nextNonSpace(from: word.upperBound)
        if nextStart < text.count, Self.splittingBoundaries.contains(text.bytes[nextStart]) {
            nextStart = nextNonSpace(from: nextStart + 1)
        }
        guard nextStart > word.upperBound, nextStart < scanEnd, !endsWord(nextStart) else { return nil }
        let next = nextStart..<wordEnd(from: nextStart, to: scanEnd)
        guard !isOpaque(next), let reading = LooseReading(text, [word, next], source: source) else { return nil }
        let split = reading.letterCount(before: nextStart)
        return reading.secretEnd { $0.lowerBound < split && $0.upperBound > split }
    }

    private static let splittingBoundaries = ByteSet("|,;&?")

    /// The end of the word that starts at `start`. An HTML character reference (`&#97;`) is part
    /// of a word, though `&` and `;` end words elsewhere. A backslash escape needs no such rule:
    /// the word it is in cuts the text or cannot be read, whatever the form of the escape and
    /// wherever the word ends after the backslash (see ``backslashEscapes(at:)``).
    func wordEnd(from start: Int, to lineEnd: Int) -> Int {
        var end = start
        while end < lineEnd {
            if let length = referenceLength(at: end) {
                end += length
            } else if end > start, endsWord(end) {
                break
            } else {
                end += 1
            }
        }
        return min(end, lineEnd)
    }

    /// Whether an escape starts in the bytes `range` (see ``isEscape(at:)``).
    private func holdsEscape(_ range: Range<Int>) -> Bool {
        var k = range.lowerBound
        while k < range.upperBound {
            if isEscape(at: k) { return true }
            k += 1
        }
        return false
    }

    /// Where the word that byte `i` is glued to starts: an escape at a boundary (`alice&commat;…`,
    /// `user&colon;…`) belongs to the word before it, which the value detectors cannot read
    /// through the escape (`alice%40example.com`), so the word is hidden with it.
    func wordStart(before i: Int) -> Int {
        var k = i
        while k > 0, !endsWord(k - 1) { k -= 1 }
        return k
    }

    /// Whether byte `i` ends a word: white space, a separator, a quote or a boundary.
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

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        ASCII.isDigit(byte) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte | 0x20)
    }
}
