/// Words read after their escapes are decoded, and the secret words in them.
extension FreeTextScanner {
    /// Reads a word that no separator follows, after its escapes are decoded (see
    /// ``EscapeDecoder``): whether it can be read with certainty, and where the first secret word
    /// in it ends.
    func read(_ range: Range<Int>) -> WordReading {
        let scalars = source[text.originalWithInvisiblesBefore(range)]
        guard scalars.contains(where: EscapeDecoder.startsEscape) else {
            if Self.isAmbiguous(scalars) { return .ambiguous }
            return LooseReading(text, [range], source: source)?.secretEnd { _ in true }.map { .valueStart($0) } ?? .plain
        }
        let decoded = DecodedWord(range, in: self)
        if Self.isAmbiguous(scalars) || Self.isAmbiguous(decoded.scalars) { return .ambiguous }
        let reading = LooseReading(decoded.text, [0..<decoded.text.count], source: decoded.scalars)
        return decoded.byteIndex(of: reading?.secretEnd { _ in true }).map { .valueStart($0) } ?? .plain
    }

    /// Whether a word cannot be read with certainty: it holds a character that only hides text
    /// (see ``ScalarClass/isHiding(_:)``) or mixes scripts (see ``ScriptMix``).
    static func isAmbiguous(_ scalars: some Collection<Unicode.Scalar>) -> Bool {
        // Printable ASCII hides nothing and is all one script; most words are read here.
        if scalars.allSatisfy({ $0.isASCII && !ASCII.isHidingControl(UInt8($0.value)) }) { return false }
        return scalars.contains(where: ScalarClass.isHiding) || ScriptMix.mixesScripts(scalars)
    }

    /// Where a value written into a word with escapes starts: at an escaped `=` or `:`
    /// (`password%3D…`, `a&#61;b`), or where a value detector finds something once the word is
    /// decoded (`a\u0040b.com`, `eyJ…%2EeyJ…`).
    func escapedValueStart(in range: Range<Int>) -> Int? {
        guard source[text.original(range)].contains(where: EscapeDecoder.startsEscape) else { return nil }
        let decoded = DecodedWord(range, in: self)
        let separator = decoded.text.bytes.firstIndex { $0 == UInt8(ascii: "=") || $0 == UInt8(ascii: ":") }
        let finding = redactor.detectorSpans(in: decoded.text).map(\.start).min().map { decoded.text.byteIndex(atOrAfter: $0) }
        return decoded.byteIndex(of: [separator, finding].compactMap { $0 }.min())
    }

    /// Whether a text, read in words as the free-text rule reads them, has a word that holds a
    /// secret name or cannot be read: in an array such as `["password","…"]`, the elements after
    /// it are hidden, as such a word hides the rest of a line, and in a URL path the segment after
    /// such a segment is hidden.
    static func mentionsSecret(_ scalars: [Unicode.Scalar], compatibility: CompatibilityText) -> Bool {
        guard !SensitiveDataRedactor.isQuietWord(scalars) else { return false }
        return mentionsSecret(scalars, text: NormalizedText(scalars, compatibility: compatibility), compatibility: compatibility)
    }

    /// Whether a name written as a value (a quoted value, a JSON string) names a secret or cannot
    /// be read: a word of it does (see ``mentionsSecret(_:compatibility:)``), its words mix scripts
    /// (`рԝ d`, as a word that mixes them cannot be read), or its words, with their escapes
    /// decoded, read as one name, as the words of a key are (`pass word`, `id_tok e n`,
    /// `c v%2576`).
    static func nameNamesSecret(_ scalars: [Unicode.Scalar], compatibility: CompatibilityText) -> Bool {
        // One short plain word holds no secret word, alone or read with others.
        guard !SensitiveDataRedactor.isQuietWord(scalars) else { return false }
        let plainText = NormalizedText(scalars, compatibility: compatibility)
        if mentionsSecret(scalars, text: plainText, compatibility: compatibility) { return true }
        let hasEscapes = scalars.contains(where: EscapeDecoder.startsEscape)
        let decoded = hasEscapes ? EscapeDecoder.decode(scalars).scalars : scalars
        if ScriptMix.mixesScripts(decoded) { return true }
        let text = hasEscapes ? NormalizedText(decoded, compatibility: compatibility) : plainText
        var words: [Range<Int>] = []
        var k = 0
        while k < text.count {
            guard !text.isSpace(k), !text.isLineTerminator(k) else {
                k += 1
                continue
            }
            let start = k
            while k < text.count, !text.isSpace(k), !text.isLineTerminator(k) { k += 1 }
            words.append(start..<k)
        }
        return LooseReading(text, words, source: decoded)?.secretEnd { _ in true } != nil
    }

    /// ``mentionsSecret(_:compatibility:)`` on a scanning copy that is already made.
    static func mentionsSecret(_ scalars: [Unicode.Scalar], text: NormalizedText, compatibility: CompatibilityText) -> Bool {
        // Only words are read here, never JSON or URLs, so no nesting is entered.
        let scanner = FreeTextScanner(source: scalars, text: text, redactor: .standard, compatibility: compatibility, nesting: .text(length: 0))
        return scanner.mentionsSecret(in: 0..<text.count) || scalars.contains(where: ScalarClass.isHiding)
    }

    /// Whether a word in the bytes `range` of the text holds a secret name or cannot be read.
    func mentionsSecret(in range: Range<Int>) -> Bool {
        var start = range.lowerBound
        while start < range.upperBound {
            guard !endsWord(start) || referenceLength(at: start) != nil else {
                start += 1
                continue
            }
            let end = wordEnd(from: start, to: range.upperBound)
            if read(start..<end) != .plain { return true }
            start = end
        }
        return false
    }
}

/// Words of the scanned text read loosely for the secret words in them (see
/// ``PlainName/init(looseBytes:wildcards:)``): punctuation between letters is read as a
/// separator, and a letter without an ASCII form as any letter, so `pass~word`, `t*okens`,
/// `Authorizɑtion` and, read with the next word, `pass word` hold a secret word.
struct LooseReading {
    private let name: PlainName
    /// The bytes read, with the byte of the scanned text each came from and those read as any
    /// letter. Where a letter came from is looked up only when a secret word is found.
    private let bytes: [UInt8]
    private let origins: [Int]
    /// Whether each byte is read as any letter.
    private let wildcards: [Bool]

    /// Reads the bytes of `ranges` of `text`, in order, as one word with a separator between the
    /// ranges. `source` is the text `text` was made from.
    init?(_ text: NormalizedText, _ ranges: [Range<Int>], source: [Unicode.Scalar]) {
        var bytes: [UInt8] = []
        var origins: [Int] = []
        var wildcards: [Bool] = []
        let count = ranges.reduce(ranges.count) { $0 + $1.count }
        bytes.reserveCapacity(count)
        origins.reserveCapacity(count)
        wildcards.reserveCapacity(count)
        for range in ranges {
            if !bytes.isEmpty {
                bytes.append(UInt8(ascii: " "))
                origins.append(range.lowerBound)
                wildcards.append(false)
            }
            for k in range {
                bytes.append(text.bytes[k])
                origins.append(k)
                wildcards.append(text.bytes[k] == CompatibilityText.unreadable && ScalarClass.isLetter(source[text.offsets[k]]))
            }
        }
        guard let name = PlainName(looseBytes: bytes, wildcards: wildcards) else { return nil }
        self.name = name
        self.bytes = bytes
        self.origins = origins
        self.wildcards = wildcards
    }

    private func isLetter(at k: Int) -> Bool { ASCII.isAlphanumeric(bytes[k]) || wildcards[k] }

    /// The number of letters that come from bytes before `byte`.
    func letterCount(before byte: Int) -> Int {
        var letters = 0
        for k in bytes.indices where isLetter(at: k) {
            if origins[k] >= byte { break }
            letters += 1
        }
        return letters
    }

    /// The byte after the last letter of the first secret word that `accepts` takes.
    func secretEnd(where accepts: (Range<Int>) -> Bool) -> Int? {
        guard let secret = name.firstSecret(where: accepts) else { return nil }
        var letters = 0
        for k in bytes.indices where isLetter(at: k) {
            if letters == secret.upperBound - 1 { return origins[k] + 1 }
            letters += 1
        }
        return nil
    }
}

/// A word of free text with its escapes decoded, and the way back to the bytes it came from.
struct DecodedWord {
    let scalars: [Unicode.Scalar]
    let text: NormalizedText
    private let origins: [Int]
    private let original: Range<Int>
    private let wordEnd: Int
    private let scannedText: NormalizedText

    init(_ range: Range<Int>, in scanner: FreeTextScanner) {
        original = scanner.text.original(range)
        (scalars, origins) = EscapeDecoder.decode(Array(scanner.source[original]))
        text = NormalizedText(scalars, compatibility: scanner.compatibility)
        wordEnd = range.upperBound
        scannedText = scanner.text
    }

    /// The byte of the scanned text that a byte of the decoded word came from; the end of the
    /// word for the end of the decoded word.
    func byteIndex(of decodedByte: Int?) -> Int? {
        guard let decodedByte else { return nil }
        let scalar = text.offset(at: decodedByte)
        guard scalar < scalars.count else { return wordEnd }
        return scannedText.byteIndex(atOrAfter: original.lowerBound + origins[scalar])
    }
}
