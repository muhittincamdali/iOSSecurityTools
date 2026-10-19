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
    let offsets: [Int]
    let isUppercase: [Bool]
    /// The number of original scalars.
    let sourceCount: Int

    /// - Parameter masked: Ranges of original scalars to read as ``CompatibilityText/unreadable``,
    ///   so that no finding starts, ends or runs inside them.
    init(_ scalars: [Unicode.Scalar], compatibility: CompatibilityText, masked: [Range<Int>] = []) {
        var bytes: [UInt8] = []
        var offsets: [Int] = []
        bytes.reserveCapacity(scalars.count)
        offsets.reserveCapacity(scalars.count)
        var mask = masked.sorted { $0.lowerBound < $1.lowerBound }.makeIterator()
        var nextMask = mask.next()
        for (offset, scalar) in scalars.enumerated() {
            while let range = nextMask, range.upperBound <= offset { nextMask = mask.next() }
            if let range = nextMask, range.contains(offset) {
                bytes.append(CompatibilityText.unreadable)
                offsets.append(offset)
                continue
            }
            if scalar.isASCII {
                // Control characters other than tab and line terminators hide like format ones.
                guard !ASCII.isHidingControl(UInt8(scalar.value)) else { continue }
                bytes.append(UInt8(scalar.value))
                offsets.append(offset)
                continue
            }
            guard !ScalarClass.isInvisible(scalar) else { continue }
            for byte in compatibility.ascii(scalar) {
                bytes.append(byte)
                offsets.append(offset)
            }
        }
        self.bytes = bytes
        self.offsets = offsets
        self.isUppercase = bytes.map(ASCII.isUppercase)
        self.sourceCount = scalars.count
    }

    var count: Int { bytes.count }

    func span(_ range: Range<Int>, _ kind: SensitiveDataRedactor.Kinds, _ replacement: String) -> SensitiveDataRedactor.Span {
        SensitiveDataRedactor.Span(start: offsets[range.lowerBound], end: offsets[range.upperBound - 1] + 1, kind: kind, replacement: replacement)
    }

    func string(_ range: Range<Int>) -> String {
        String(decoding: bytes[range], as: UTF8.self)
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

    func isLetter(_ i: Int) -> Bool { ASCII.isLetter(bytes[i]) }

    func isAlphanumeric(_ i: Int) -> Bool { isDigit(i) || isLetter(i) }

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

    /// Whether a word starts at `i`: after a non-alphanumeric character, or at a lowercase to
    /// uppercase change (`accessToken`).
    func isWordStart(_ i: Int) -> Bool {
        guard i > 0 else { return true }
        if !isAlphanumeric(i - 1) { return true }
        return isUppercase[i] && isLetter(i - 1) && !isUppercase[i - 1]
    }

    func matches(_ word: [UInt8], at i: Int) -> Bool {
        guard i + word.count <= count else { return false }
        for (k, byte) in word.enumerated() where ASCII.lowercased(bytes[i + k]) != byte {
            return false
        }
        return true
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

    private var cache: [UInt32: [UInt8]] = [:]

    func ascii(_ scalar: Unicode.Scalar) -> [UInt8] {
        if scalar.isASCII { return [UInt8(scalar.value)] }
        if let cached = cache[scalar.value] { return cached }
        let reading = Self.read(scalar)
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
