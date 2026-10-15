import Foundation

/// The text the detectors read: invisible scalars removed and everything else read as ASCII
/// where it stands for ASCII (see ``LatinFolding``), with the range each byte came from in the
/// original scalars. One scalar can become several bytes (`ß` is read as `ss`).
struct NormalizedText {
    let bytes: [UInt8]
    /// The offset in the original scalars where the scalar a byte came from starts.
    let offsets: [Int]
    /// The offset in the original scalars right after the scalar a byte came from.
    let ends: [Int]
    let isUppercase: [Bool]
    let originalCount: Int

    init(_ scalars: [Unicode.Scalar]) {
        var bytes: [UInt8] = []
        var offsets: [Int] = []
        var ends: [Int] = []
        bytes.reserveCapacity(scalars.count)
        offsets.reserveCapacity(scalars.count)
        ends.reserveCapacity(scalars.count)
        var folding = LatinFolding()
        for (offset, scalar) in scalars.enumerated() where !ScalarClass.isInvisible(scalar) {
            if scalar.isASCII {
                bytes.append(UInt8(scalar.value))
                offsets.append(offset)
                ends.append(offset + 1)
                continue
            }
            for byte in folding.bytes(for: scalar) {
                bytes.append(byte)
                offsets.append(offset)
                ends.append(offset + 1)
            }
        }
        self.bytes = bytes
        self.offsets = offsets
        self.ends = ends
        self.isUppercase = bytes.map { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0) }
        self.originalCount = scalars.count
    }

    var count: Int { bytes.count }

    func span(_ range: Range<Int>, _ kind: SensitiveDataRedactor.Kinds, _ replacement: String) -> SensitiveDataRedactor.Span {
        SensitiveDataRedactor.Span(start: offsets[range.lowerBound], end: ends[range.upperBound - 1], kind: kind, replacement: replacement)
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
