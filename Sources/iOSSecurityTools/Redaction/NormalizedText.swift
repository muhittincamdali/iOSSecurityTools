import Foundation

/// The scanning copy of a text: invisible scalars (format characters, marks, variation selectors,
/// default-ignorable code points and control characters, see ``ScalarClass/isInvisible(_:)``)
/// removed and every other scalar read as the ASCII it stands for under Unicode compatibility
/// normalization (see ``CompatibilityText``), with the offset each byte came from in the original
/// scalars. One scalar can become several bytes (`ﬁ` is read as `fi`).
///
/// The free-text rule and the value detectors read this copy; their findings are mapped back to
/// the original scalars. Keys are judged on the original scalars, never on this copy.
struct NormalizedText {
    let bytes: [UInt8]
    /// The offset in the original scalars of the scalar a byte came from.
    let offsets: ScalarOffsets
    /// The original scalars.
    let source: [Unicode.Scalar]
    /// The offset of the first original scalar outside the safe alphabet of free text, or nil
    /// (see ``FreeTextScanner/firstUnsafeOffset(in:)``). It is found while the copy is made, from
    /// the same reading of each scalar.
    let firstUnsafeOffset: Int?
    /// The number of original scalars.
    var sourceCount: Int { source.count }

    /// A byte of a masked range: like ``CompatibilityText/unreadable`` it matches no detector or
    /// separator, and unlike it, it never stands for a letter.
    static let masked: UInt8 = 0xFE

    init(_ scalars: [Unicode.Scalar], compatibility: CompatibilityText) {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(scalars.count)
        var alphabet = SafeAlphabetReader()
        // While every scalar becomes one byte, as in printable ASCII, each byte comes from the
        // scalar at its own index and no offsets are stored.
        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            let byte: UInt8
            if scalar.isASCII {
                byte = UInt8(scalar.value)
                alphabet.read(ascii: byte, at: index)
                guard !ASCII.isHidingControl(byte) else { break }
            } else {
                let reading = compatibility.reading(scalar)
                alphabet.read(reading.alphabet, at: index)
                guard !reading.isInvisible, reading.bytes.count == 1 else { break }
                byte = reading.bytes[0]
            }
            bytes.append(byte)
            index += 1
        }
        guard index < scalars.count else {
            self.init(bytes: bytes, offsets: ScalarOffsets(), source: scalars, firstUnsafeOffset: alphabet.firstUnsafe)
            return
        }
        // Up to the scalar the fast loop stopped at, each byte came from the scalar at its own
        // index: one run, which the builder starts with.
        var offsets = ScalarOffsets.Builder()
        // The scalar the fast loop stopped at is read again here, and the alphabet with it, which
        // reads it the same way.
        for offset in index..<scalars.count {
            let scalar = scalars[offset]
            if scalar.isASCII {
                let byte = UInt8(scalar.value)
                if offset > index { alphabet.read(ascii: byte, at: offset) }
                // Control characters other than tab and line terminators hide like format ones.
                guard !ASCII.isHidingControl(byte) else { continue }
                offsets.add(byte: bytes.count, from: offset)
                bytes.append(byte)
                continue
            }
            let reading = compatibility.reading(scalar)
            if offset > index { alphabet.read(reading.alphabet, at: offset) }
            guard !reading.isInvisible else { continue }
            for byte in reading.bytes {
                offsets.add(byte: bytes.count, from: offset)
                bytes.append(byte)
            }
        }
        self.init(bytes: bytes, offsets: offsets.offsets, source: scalars, firstUnsafeOffset: alphabet.firstUnsafe)
    }

    private init(bytes: [UInt8], offsets: ScalarOffsets, source: [Unicode.Scalar], firstUnsafeOffset: Int?) {
        self.bytes = bytes
        self.offsets = offsets
        self.source = source
        self.firstUnsafeOffset = firstUnsafeOffset
    }

    /// This copy with the bytes that come from scalars in `regions` read as ``masked``, so that no
    /// finding starts, ends or runs inside them. The offsets and the scalars are shared, so the
    /// masked copy takes only its bytes.
    func masking(_ regions: [Range<Int>]) -> NormalizedText {
        var masked = bytes
        // The offsets only grow from byte to byte, so the bytes of a region are the ones from the
        // first at or after its start to the first at or after its end.
        for region in regions {
            let start = byteIndex(atOrAfter: region.lowerBound)
            let end = max(start, byteIndex(atOrAfter: region.upperBound))
            for k in start..<end { masked[k] = Self.masked }
        }
        return NormalizedText(bytes: masked, offsets: offsets, source: source, firstUnsafeOffset: firstUnsafeOffset)
    }

    var count: Int { bytes.count }

    func span(_ range: Range<Int>, _ kind: SensitiveDataRedactor.Kinds, _ replacement: String) -> SensitiveDataRedactor.Span {
        SensitiveDataRedactor.Span(start: offsets[range.lowerBound], end: offsets[range.upperBound - 1] + 1, kind: kind, replacement: replacement)
    }

    func string(_ range: Range<Int>) -> String {
        String(decoding: bytes[range], as: UTF8.self)
    }

    /// The bytes of a range as text, with each byte that has no ASCII reading written as the
    /// scalar it came from: `ayşe.yılmaz` is `ayse.yılmaz`, and `例子.中国` stays as it is.
    func shown(_ range: Range<Int>) -> String {
        var scalars = String.UnicodeScalarView()
        for k in range {
            scalars.append(bytes[k] == CompatibilityText.unreadable ? source[offsets[k]] : Unicode.Scalar(bytes[k]))
        }
        return String(scalars)
    }

    /// The offset in the original scalars where byte `i` starts; the end of the text for
    /// `i == count`.
    func offset(at i: Int) -> Int {
        i < count ? offsets[i] : sourceCount
    }

    /// The original scalars of a range of bytes, with the invisible scalars up to the next byte.
    func original(_ range: Range<Int>) -> Range<Int> {
        offset(at: range.lowerBound)..<offset(at: range.upperBound)
    }

    /// ``original(_:)`` together with the invisible scalars right before the range, which belong
    /// to the key or word that starts there: `\u{200D}status` is not the key `status`.
    func originalWithInvisiblesBefore(_ range: Range<Int>) -> Range<Int> {
        let end = offset(at: range.upperBound)
        guard range.lowerBound > 0 else { return 0..<end }
        return min(offsets[range.lowerBound - 1] + 1, offset(at: range.lowerBound))..<end
    }

    /// The first byte at or after an offset in the original scalars.
    func byteIndex(atOrAfter offset: Int) -> Int {
        var low = 0
        var high = count
        while low < high {
            let middle = (low + high) / 2
            if offsets[middle] < offset { low = middle + 1 } else { high = middle }
        }
        return low
    }

    // MARK: Character classes

    func isDigit(_ i: Int) -> Bool { ASCII.isDigit(bytes[i]) }

    func isUppercase(_ i: Int) -> Bool { ASCII.isUppercase(bytes[i]) }

    func isLetter(_ i: Int) -> Bool { ASCII.isLetter(bytes[i]) }

    func isAlphanumeric(_ i: Int) -> Bool { isDigit(i) || isLetter(i) }

    /// A letter of any script: an ASCII letter, or one without an ASCII reading (`ı`, `ø`, `张`).
    func isAnyLetter(_ i: Int) -> Bool {
        isLetter(i) || (bytes[i] == CompatibilityText.unreadable && ScalarClass.isLetter(source[offsets[i]]))
    }

    /// A letter or digit of any script; marks are not in the scanning copy, so a letter with
    /// marks is one too.
    func isAnyAlphanumeric(_ i: Int) -> Bool {
        isAlphanumeric(i) || (bytes[i] == CompatibilityText.unreadable && ScalarClass.isLetterOrNumber(source[offsets[i]]))
    }

    func isBase64URL(_ i: Int) -> Bool { isAlphanumeric(i) || bytes[i] == UInt8(ascii: "-") || bytes[i] == UInt8(ascii: "_") }

    func isTokenCharacter(_ i: Int) -> Bool {
        isAlphanumeric(i) || [UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"), UInt8(ascii: "+"), UInt8(ascii: "/"), UInt8(ascii: "=")].contains(bytes[i])
    }

    func isSpace(_ i: Int) -> Bool { bytes[i] == UInt8(ascii: " ") || bytes[i] == UInt8(ascii: "\t") }

    /// LF (also read from U+2028, U+2029 and U+0085), CR, vertical tab and form feed.
    func isLineTerminator(_ i: Int) -> Bool {
        let byte = bytes[i]
        return byte == 0x0A || byte == 0x0D || byte == 0x0B || byte == 0x0C
    }

    /// Whether a word starts at `i`: after a character that does not glue to it (see
    /// ``gluesToWord(_:)``), or at a lowercase to uppercase change (`accessToken`).
    func isWordStart(_ i: Int) -> Bool {
        guard i > 0 else { return true }
        if !gluesToWord(i - 1) { return true }
        return isUppercase(i) && isLetter(i - 1) && !isUppercase(i - 1)
    }

    /// Whether byte `i` is a letter or digit written in ASCII, which makes the digits or the token
    /// next to it part of a word (`id4242…`, `xeyJ…`) that the value detectors leave alone. A letter
    /// read from another character (`é`, `𝐚`, `№`) does not: the detectors find a card number or a
    /// token after it, as 2.0.0 did.
    func gluesToWord(_ i: Int) -> Bool {
        isAlphanumeric(i) && source[offsets[i]].isASCII
    }

    func matches(_ word: [UInt8], at i: Int) -> Bool {
        guard i + word.count <= count else { return false }
        for (k, byte) in word.enumerated() where ASCII.lowercased(bytes[i + k]) != byte {
            return false
        }
        return true
    }
}

/// The offset in the original scalars of each byte of a scanning copy, kept as runs, not one for
/// each byte. In a run, each byte comes from the scalar after the one the byte before it came from,
/// so a run is stored as the byte it starts at and the offset of that byte's scalar, in 32 bits
/// each. A run starts where that stops: at the second byte of a scalar read as several (`ﬁ` is
/// read as `fi`) and at the byte after scalars that the copy leaves out. When each byte comes from
/// the scalar at its own index, as in printable ASCII, nothing is stored, and a megabyte of log
/// lines with one `ﬁ` each stores one run for each line: the eighteenth review measured 4 MB of
/// offsets, one for each byte, which pushed such text over 16 MB of memory. Free text of 2^28
/// scalars or more is hidden whole before a copy is made (see
/// ``SensitiveDataRedactor/maximumTextLength``).
struct ScalarOffsets {
    /// The byte each run starts at, in order; empty when each byte comes from the scalar at its
    /// own index.
    private let starts: [UInt32]
    /// The offset of the scalar that the first byte of each run came from.
    private let firstOffsets: [UInt32]

    init() {
        starts = []
        firstOffsets = []
    }

    fileprivate init(starts: [UInt32], firstOffsets: [UInt32]) {
        self.starts = starts
        self.firstOffsets = firstOffsets
    }

    /// The offset of the scalar byte `i` came from, found among the runs by binary search.
    subscript(i: Int) -> Int {
        guard !starts.isEmpty else { return i }
        var low = 0
        var high = starts.count
        while high - low > 1 {
            let middle = (low + high) / 2
            if Int(starts[middle]) <= i { low = middle } else { high = middle }
        }
        return Int(firstOffsets[low]) + (i - Int(starts[low]))
    }

    /// Collects the runs while the bytes of a copy are written in order, starting with a run at
    /// byte 0 from scalar 0.
    struct Builder {
        private var starts: [UInt32] = [0]
        private var firstOffsets: [UInt32] = [0]

        /// Records that byte `byte`, the next one written, comes from the scalar at `offset`.
        mutating func add(byte: Int, from offset: Int) {
            let last = starts.count - 1
            guard Int(firstOffsets[last]) + (byte - Int(starts[last])) != offset else { return }
            if Int(starts[last]) == byte {
                firstOffsets[last] = UInt32(clamping: offset)
            } else {
                starts.append(UInt32(clamping: byte))
                firstOffsets.append(UInt32(clamping: offset))
            }
        }

        var offsets: ScalarOffsets { ScalarOffsets(starts: starts, firstOffsets: firstOffsets) }
    }
}

/// Reads a scalar outside ASCII as the ASCII it stands for under Unicode compatibility
/// decomposition (NFKD) without its marks: `ａ` and `𝐚` are `a`, `é` is `e`, `＝` and `︓` are `=`
/// and `:`, `≠` is `=`, a digit of any script is its digit, a dash of any kind is `-`, every space
/// is ` ` and a line or paragraph separator is `\n`. A scalar whose decomposition is not ASCII is
/// read as ``unreadable``. This is Unicode's own mapping, not a list of look-alikes: a Cyrillic
/// `а` stays unreadable.
///
/// The readings are cached per scalar: logs repeat the same few non-ASCII characters, and the
/// normalization goes through Foundation.
final class CompatibilityText {
    /// A byte that no detector or separator matches.
    static let unreadable: UInt8 = 0xFF

    /// What a scalar outside ASCII is read as, worked out once: its ASCII reading, whether the
    /// scanning copy leaves it out (see ``ScalarClass/isInvisible(_:)``) and what the safe
    /// alphabet of free text makes of it.
    struct Reading {
        let bytes: [UInt8]
        let isInvisible: Bool
        let alphabet: SafeAlphabet.Class
    }

    private var cache: [UInt32: Reading] = [:]

    func ascii(_ scalar: Unicode.Scalar) -> [UInt8] {
        if scalar.isASCII { return [UInt8(scalar.value)] }
        return reading(scalar).bytes
    }

    /// The reading of a scalar outside ASCII.
    func reading(_ scalar: Unicode.Scalar) -> Reading {
        if let cached = cache[scalar.value] { return cached }
        let alphabet = SafeAlphabet.class(of: scalar)
        var bytes = Self.read(scalar)
        // A letter, mark or number is never read as punctuation or a space (`⑴` decomposes to
        // `(1)`, `🄁` to `0,`): a key or a word would be split where the text holds one character.
        // Free text is cut at such a scalar, as its class says (see ``SafeAlphabet/class(of:)``);
        // the value detectors, which read on where no cut is made, read it as one character.
        if ScalarClass.isLetterOrNumber(scalar), bytes.contains(where: { $0 < 0x80 && !ASCII.isAlphanumeric($0) }) { bytes = [Self.unreadable] }
        let reading = Reading(bytes: bytes, isInvisible: ScalarClass.isInvisible(scalar), alphabet: alphabet)
        cache[scalar.value] = reading
        return reading
    }

    private static func read(_ scalar: Unicode.Scalar) -> [UInt8] {
        if let digit = ScalarClass.decimalDigit(scalar) { return [UInt8(ascii: "0") + digit] }
        switch scalar.properties.generalCategory {
        case .lineSeparator, .paragraphSeparator: return [UInt8(ascii: "\n")]
        default: break
        }
        if scalar == "\u{85}" { return [UInt8(ascii: "\n")] }
        // The blank Braille pattern draws nothing, like a space.
        if scalar.properties.isWhitespace || scalar == "\u{2800}" { return [UInt8(ascii: " ")] }
        if scalar.properties.generalCategory == .dashPunctuation { return [UInt8(ascii: "-")] }
        var bytes: [UInt8] = []
        for part in String(scalar).decomposedStringWithCompatibilityMapping.unicodeScalars where !ScalarClass.isInvisible(part) {
            guard part.isASCII else { return [unreadable] }
            bytes.append(UInt8(part.value))
        }
        return bytes.isEmpty ? [unreadable] : bytes
    }
}
