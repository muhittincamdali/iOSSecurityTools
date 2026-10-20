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
            advance(to: end)
            return
        }
        pendingKey = nil
        guard role == .text else {
            advance(to: end)
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
                advance(to: end)
            }
        }
    }

    /// A secret word split by white space or by one of `|`, `,`, `;`, `&` and `?` (`pass word`,
    /// `to ken`, `p|wd`): the byte after it, when it starts in this word and ends in the next one
    /// on the line. A next word longer than ``longestWord`` is not read with it.
    private func secretEndAcrossSpace(after word: Range<Int>) -> Int? {
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

    /// Reads the quoted key in the bytes `key` (`"…": value`) as the name of a JSON member is
    /// read, in the ``Role/name`` role: its own words are not triggers, but a URL that is not
    /// clean, a key written in it (`"user=bob":`), an escape, a word longer than ``longestWord``
    /// and JSON cut the text where they start, as they would outside the quotes. A key of ASCII
    /// letters, digits, `_`, `-`, `.` and spaces holds none of them and is not read again.
    mutating func readQuotedKey(_ key: Range<Int>) {
        let region = text.original(key)
        let scalars = source[region]
        if scalars.count <= Self.longestWord, scalars.allSatisfy({ $0.isASCII && ASCII.isNameCharacter(UInt8($0.value)) }) { return }
        let keyScalars = Array(scalars)
        var scanner = FreeTextScanner(
            source: keyScalars, text: NormalizedText(keyScalars, compatibility: compatibility), redactor: redactor, compatibility: compatibility,
            role: .name, nesting: nesting
        )
        scanner.run()
        guard !scanner.hidesWholeText else {
            hideWholeText()
            return
        }
        let shift = region.lowerBound
        let spans = scanner.spans.map { SensitiveDataRedactor.Span(start: $0.start + shift, end: $0.end + shift, kind: $0.kind, replacement: $0.replacement) }
        for (index, inner) in scanner.regions.enumerated() {
            record(spans: index == 0 ? spans : [], region: (inner.lowerBound + shift)..<(inner.upperBound + shift))
        }
        if let inner = scanner.cut { cut(atOffset: shift + inner) }
    }

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

    /// Whether an escape starts in the bytes `range`.
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

    /// Whether byte `i` ends a word: white space, a separator, a quote, a boundary, and in a start
    /// tag the `>` that ends it.
    func endsWord(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        return text.isSpace(i) || text.isLineTerminator(i) || isSeparator(i) || byte == UInt8(ascii: "\"") || Self.boundaries.contains(byte)
            || (byte == UInt8(ascii: ">") && isInStartTag)
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
