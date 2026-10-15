import Foundation

/// The text the detectors read: invisible scalars removed, full-width ASCII and decimal digits of
/// every script mapped to ASCII, with the offset of each kept scalar in the original.
struct NormalizedText {
    let bytes: [UInt8]
    let offsets: [Int]
    let isUppercase: [Bool]
    let originalCount: Int

    init(_ scalars: [Unicode.Scalar]) {
        var bytes: [UInt8] = []
        var offsets: [Int] = []
        var isUppercase: [Bool] = []
        bytes.reserveCapacity(scalars.count)
        offsets.reserveCapacity(scalars.count)
        isUppercase.reserveCapacity(scalars.count)
        for (offset, scalar) in scalars.enumerated() where !ScalarClass.isInvisible(scalar) {
            let byte = Self.ascii(scalar)
            bytes.append(byte)
            offsets.append(offset)
            isUppercase.append((UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte))
        }
        self.bytes = bytes
        self.offsets = offsets
        self.isUppercase = isUppercase
        self.originalCount = scalars.count
    }

    /// Byte used for matching: ASCII as is, full-width forms and other digits as ASCII, spaces as
    /// a space, anything else as 0xFF (never matches).
    private static func ascii(_ scalar: Unicode.Scalar) -> UInt8 {
        let value = scalar.value
        if value < 0x80 { return UInt8(value) }
        if (0xFF01...0xFF5E).contains(value) { return UInt8(value - 0xFEE0) }
        if let digit = ScalarClass.decimalDigit(scalar) { return UInt8(ascii: "0") + digit }
        switch value {
        // Every space separator of Unicode (category Zs) except the ASCII space handled above.
        case 0x00A0, 0x1680, 0x2000...0x200A, 0x202F, 0x205F, 0x3000: return UInt8(ascii: " ")
        default: return 0xFF
        }
    }

    var count: Int { bytes.count }

    func span(_ range: Range<Int>, _ kind: SensitiveDataRedactor.Kinds, _ replacement: String) -> SensitiveDataRedactor.Span {
        SensitiveDataRedactor.Span(start: offsets[range.lowerBound], end: offsets[range.upperBound - 1] + 1, kind: kind, replacement: replacement)
    }

    func string(_ range: Range<Int>) -> String {
        String(decoding: bytes[range], as: UTF8.self)
    }

    // MARK: Character classes

    func isDigit(_ i: Int) -> Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[i]) }

    func isLetter(_ i: Int) -> Bool {
        let byte = bytes[i] | 0x20
        return (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
    }

    func isAlphanumeric(_ i: Int) -> Bool { isDigit(i) || isLetter(i) }

    func lowercased(_ i: Int) -> UInt8 { isLetter(i) ? bytes[i] | 0x20 : bytes[i] }

    func isBase64URL(_ i: Int) -> Bool { isAlphanumeric(i) || bytes[i] == UInt8(ascii: "-") || bytes[i] == UInt8(ascii: "_") }

    func isTokenCharacter(_ i: Int) -> Bool {
        isAlphanumeric(i) || [UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"), UInt8(ascii: "+"), UInt8(ascii: "/"), UInt8(ascii: "=")].contains(bytes[i])
    }

    func isSpace(_ i: Int) -> Bool { bytes[i] == UInt8(ascii: " ") || bytes[i] == UInt8(ascii: "\t") }

    /// Whether a word starts at `i`: after a non-alphanumeric character, or at a lowercase to
    /// uppercase change (`accessToken`).
    func isWordStart(_ i: Int) -> Bool {
        guard i > 0 else { return true }
        if !isAlphanumeric(i - 1) { return true }
        return isUppercase[i] && isLetter(i - 1) && !isUppercase[i - 1]
    }

    func matches(_ word: [UInt8], at i: Int) -> Bool {
        guard i + word.count <= count else { return false }
        for (k, byte) in word.enumerated() where lowercased(i + k) != byte {
            return false
        }
        return true
    }
}
