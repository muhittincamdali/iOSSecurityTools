/// Words read as written and with their escapes decoded, and the secret words in them.
extension FreeTextScanner {
    /// Reads a word that no separator follows: whether it can be read with certainty, and where
    /// the first secret word in it ends. Free text never reaches the decoding: an escape cuts it
    /// first (see ``isEscape(at:)``). The words of a name written as a value, of an array element,
    /// of a URL path segment and of JSON written into a line can hold percent escapes and
    /// character references (see ``mentionsSecret(_:compatibility:)``). A word is read as written
    /// and, where `&#x` or `%u` is in it or right before it, with the letter that starts the hex
    /// escape read as punctuation; a word with `%` or `&` is also read with its escapes decoded
    /// (see ``EscapeDecoder``). The reading that hides most counts: one that cannot be read, then
    /// the secret word that ends first. Decoding alone takes the first letters of a name for
    /// digits of an escape (`%card` decodes to U+FFFD and `rd`, `&#xcvv` to U+000C and `vv`), and
    /// the written word alone glues the `x` of `&#x` to the name (`&#xpass`, in free text too), so
    /// each reads less than all of them. A backslash escape is not decoded in any form: a word
    /// with one cannot be read, as it cuts free text (see ``backslashEscapes(at:)``). Nor is a word
    /// longer than ``longestWord`` read.
    func read(_ range: Range<Int>) -> WordReading {
        if isOpaque(range) || holdsBackslashEscape(range) { return .ambiguous }
        let scalars = source[text.originalWithInvisiblesBefore(range)]
        if Self.isAmbiguous(scalars) { return .ambiguous }
        let written = LooseReading(text, [range], source: source)?.secretEnd { _ in true }
        let unescaped = LooseReading.holdsEscapeStart(text, in: range)
            ? LooseReading(text, [range], source: source, readsEscapeStartsAsPunctuation: true)?.secretEnd { _ in true } : nil
        let writtenEnd = Self.earliest(written, unescaped)
        guard scalars.contains(where: EscapeDecoder.startsEscape) else { return writtenEnd.map { .valueStart($0) } ?? .plain }
        let decoded = DecodedWord(range, in: self)
        if Self.isAmbiguous(decoded.scalars) { return .ambiguous }
        let reading = LooseReading(decoded.text, [0..<decoded.text.count], source: decoded.scalars)
        return Self.earliest(writtenEnd, decoded.byteIndex(of: reading?.secretEnd { _ in true })).map { .valueStart($0) } ?? .plain
    }

    private static func earliest(_ first: Int?, _ second: Int?) -> Int? {
        guard let first, let second else { return first ?? second }
        return min(first, second)
    }

    private func holdsBackslashEscape(_ range: Range<Int>) -> Bool {
        range.contains { text.bytes[$0] == UInt8(ascii: "\\") && backslashEscapes(at: $0) }
    }

    /// Whether a word cannot be read with certainty: it holds a character that only hides text
    /// (see ``ScalarClass/isHiding(_:)``) or mixes scripts (see ``ScriptMix``).
    static func isAmbiguous(_ scalars: some Collection<Unicode.Scalar>) -> Bool {
        // Printable ASCII hides nothing and is all one script; most words are read here.
        if scalars.allSatisfy({ $0.isASCII && !ASCII.isHidingControl(UInt8($0.value)) }) { return false }
        return scalars.contains(where: ScalarClass.isHiding) || ScriptMix.mixesScripts(scalars)
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
    /// (`рԝ d`, as a word that mixes them cannot be read), or its words read as one name, as the
    /// words of a key are (`pass word`, `id_tok e n`). A name with an escape is read the three ways
    /// a word is (see ``read(_:)``), and any of them that names a secret counts: as written
    /// (`%card`, `&#xcvv`, though decoding takes `ca` and `c` for hex digits), with the letter
    /// that starts a hex escape read as punctuation (`&#xpass`) and decoded (`c v%2576`).
    static func nameNamesSecret(_ scalars: [Unicode.Scalar], compatibility: CompatibilityText) -> Bool {
        // One short plain word holds no secret word, alone or read with others.
        guard !SensitiveDataRedactor.isQuietWord(scalars) else { return false }
        let writtenText = NormalizedText(scalars, compatibility: compatibility)
        if mentionsSecret(scalars, text: writtenText, compatibility: compatibility) { return true }
        if ScriptMix.mixesScripts(scalars) { return true }
        let writtenWords = words(of: writtenText)
        if LooseReading(writtenText, writtenWords, source: scalars)?.secretEnd(where: { _ in true }) != nil { return true }
        if LooseReading.holdsEscapeStart(writtenText, in: 0..<writtenText.count) {
            let unescaped = LooseReading(writtenText, writtenWords, source: scalars, readsEscapeStartsAsPunctuation: true)
            if unescaped?.secretEnd(where: { _ in true }) != nil { return true }
        }
        guard scalars.contains(where: EscapeDecoder.startsEscape) else { return false }
        let decoded = EscapeDecoder.decode(scalars).scalars
        if ScriptMix.mixesScripts(decoded) { return true }
        let decodedText = NormalizedText(decoded, compatibility: compatibility)
        return LooseReading(decodedText, words(of: decodedText), source: decoded)?.secretEnd { _ in true } != nil
    }

    /// The runs of `text` between white space and line breaks.
    private static func words(of text: NormalizedText) -> [Range<Int>] {
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
        return words
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

/// Words of the scanned text compared with the secret names by their ASCII skeleton: the one
/// rule that every path reading a word of text uses (free text, names written as values, array
/// elements, URL path segments, form, query and multipart values).
///
/// The scanning copy has already read each character as the ASCII it stands for under
/// compatibility normalization and left out marks and format characters (`pässword`, `ｐａｓｓ`
/// are `password`, `pass`). Every letter that is still without an ASCII form (`ꞏ`, `ı`, `ɑ`,
/// `ø`) is then left out, and what remains is compared, lowercased, with the secret names, a
/// plural `s` included (see ``PlainName/firstSecret(where:)``): `piꞏn`, `tokeın`, `tokenꞏs` and
/// `keyıs` read as `pin`, `token`, `tokens` and `keys`, however many letters are left out. A name
/// also counts with one of its letters missing where letters were left out, so a letter (L*) put
/// in place of one of its letters is found too (`pɑssword`, `user_pın`), and a word of another
/// language that reads as a name this way is read as that name (Turkish `yapın` as `pin`),
/// which hides more on purpose. Two or more letters put in place of letters of one name
/// (`pɑsswoʀd`) are not found: no list of look-alikes is kept. Nor is a name with a combining
/// mark (Mn) in place of one of its letters (`tͦken`): the mark is left out like any mark, so the
/// letter the name misses is not where a letter was left out. Both are deliberate disguise, a
/// documented limit of free text written without a separator. Punctuation between letters is
/// read as a separator (`pass~word`), and a word read with the next one (`pass word`) holds a
/// secret name across the space.
struct LooseReading {
    private let name: PlainName
    /// The bytes of the skeleton, with the byte of the scanned text each came from. Where a
    /// letter came from is looked up only when a secret word is found.
    private let bytes: [UInt8]
    private let origins: [Int]

    /// Reads the bytes of `ranges` of `text`, in order, as one word with a separator between the
    /// ranges. `source` is the text `text` was made from. With `readsEscapeStartsAsPunctuation`,
    /// the letter that starts a hex escape is read as punctuation (see ``isEscapeStart(_:after:)``).
    init?(_ text: NormalizedText, _ ranges: [Range<Int>], source: [Unicode.Scalar], readsEscapeStartsAsPunctuation: Bool = false) {
        var bytes: [UInt8] = []
        var origins: [Int] = []
        var leftOutBefore: [Bool] = []
        var isLeavingOut = false
        let count = ranges.reduce(ranges.count) { $0 + $1.count }
        bytes.reserveCapacity(count)
        origins.reserveCapacity(count)
        leftOutBefore.reserveCapacity(count)
        func append(_ byte: UInt8, from k: Int) {
            bytes.append(byte)
            origins.append(k)
            leftOutBefore.append(isLeavingOut)
            if ASCII.isAlphanumeric(byte) { isLeavingOut = false }
        }
        for range in ranges {
            if !bytes.isEmpty { append(UInt8(ascii: " "), from: range.lowerBound) }
            for k in range {
                let byte = text.bytes[k]
                if byte == CompatibilityText.unreadable, ScalarClass.isLetter(source[text.offsets[k]]) {
                    isLeavingOut = true
                } else if readsEscapeStartsAsPunctuation, k > 0, Self.isEscapeStart(byte, after: text.bytes[k - 1]) {
                    append(UInt8(ascii: "_"), from: k)
                } else {
                    append(byte, from: k)
                }
            }
        }
        guard let name = PlainName(skeleton: bytes, leftOutBefore: leftOutBefore, leftOutAtEnd: isLeavingOut) else { return nil }
        self.name = name
        self.bytes = bytes
        self.origins = origins
    }

    /// Whether `byte` is the letter that starts a hex escape, the `x` of `&#x` or the `u` of `%u`,
    /// and not a letter of a name: `&#xpass` is `&#x` and `pass`. The byte before a word counts,
    /// as `&` and `#` end a word where no reference follows them. No secret name holds an `x`, and
    /// the word is also read as written, for a `u`, so this reading only ever hides more.
    private static func isEscapeStart(_ byte: UInt8, after previous: UInt8) -> Bool {
        switch ASCII.lowercased(byte) {
        case UInt8(ascii: "x"): previous == UInt8(ascii: "#")
        case UInt8(ascii: "u"): previous == UInt8(ascii: "%")
        default: false
        }
    }

    /// Whether the bytes `range` of `text`, or the byte right before them, start a hex escape (see
    /// ``isEscapeStart(_:after:)``).
    static func holdsEscapeStart(_ text: NormalizedText, in range: Range<Int>) -> Bool {
        var k = max(range.lowerBound, 1)
        while k < range.upperBound {
            if isEscapeStart(text.bytes[k], after: text.bytes[k - 1]) { return true }
            k += 1
        }
        return false
    }

    /// The number of letters that come from bytes before `byte`.
    func letterCount(before byte: Int) -> Int {
        var letters = 0
        for k in bytes.indices where ASCII.isAlphanumeric(bytes[k]) {
            if origins[k] >= byte { break }
            letters += 1
        }
        return letters
    }

    /// The byte after the last letter of the first secret word that `accepts` takes.
    func secretEnd(where accepts: (Range<Int>) -> Bool) -> Int? {
        guard let secret = name.firstSecret(where: accepts) else { return nil }
        var letters = 0
        for k in bytes.indices where ASCII.isAlphanumeric(bytes[k]) {
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
