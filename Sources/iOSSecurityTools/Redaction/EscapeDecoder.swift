/// Decodes the escapes a word of free text may hide a secret name behind, so that `pass%77ord`,
/// `p&#97;ssword`, `\u0070assword` and `pass%2577ord` read as `password` when the free-text rule
/// looks for secret names.
///
/// Decoded are percent escapes (as UTF-8, and `%uXXXX`), HTML character references by number
/// (`&#97;`, `&#x61;`, also without the `;` and with leading zeros) and `&amp;`, and `\uXXXX`,
/// `\u{…}` and `\xXX` escapes, round after round up to ``maximumRounds`` times. Keys are never
/// decoded for an allowlist: a key with an escape is not plain ASCII, so its value is hidden.
enum EscapeDecoder {
    static let maximumRounds = 4

    /// The most digits read in a character reference, leading zeros included.
    static let maximumReferenceDigits = 16

    /// Whether a scalar can start an escape.
    static func startsEscape(_ scalar: Unicode.Scalar) -> Bool {
        scalar == "%" || scalar == "&" || scalar == "\\"
    }

    /// The scalars with their escapes decoded, and for each the offset in `scalars` it came from.
    static func decode(_ scalars: [Unicode.Scalar]) -> (scalars: [Unicode.Scalar], origins: [Int]) {
        var current = scalars
        var origins = Array(scalars.indices)
        for _ in 0..<maximumRounds where current.contains(where: startsEscape) {
            let (next, positions) = decodeOnce(current)
            guard next.count != current.count else { break }
            origins = positions.map { origins[$0] }
            current = next
        }
        return (current, origins)
    }

    private static func decodeOnce(_ scalars: [Unicode.Scalar]) -> ([Unicode.Scalar], [Int]) {
        var output: [Unicode.Scalar] = []
        var positions: [Int] = []
        var i = 0
        while i < scalars.count {
            if let (decoded, length) = percentRun(scalars, at: i) ?? percentU(scalars, at: i) ?? reference(scalars, at: i)
                ?? backslash(scalars, at: i) {
                output += decoded
                positions += Array(repeating: i, count: decoded.count)
                i += length
            } else {
                output.append(scalars[i])
                positions.append(i)
                i += 1
            }
        }
        return (output, positions)
    }

    /// A run of `%XX` escapes decoded as UTF-8; bytes that are not UTF-8 become U+FFFD.
    private static func percentRun(_ scalars: [Unicode.Scalar], at start: Int) -> ([Unicode.Scalar], Int)? {
        var bytes: [UInt8] = []
        var i = start
        while i + 2 < scalars.count, scalars[i] == "%", let high = hex(scalars[i + 1]), let low = hex(scalars[i + 2]) {
            bytes.append(UInt8(high << 4 | low))
            i += 3
        }
        guard !bytes.isEmpty else { return nil }
        return (Array(String(decoding: bytes, as: UTF8.self).unicodeScalars), i - start)
    }

    /// `%uXXXX`, as JavaScript's `escape` writes a character outside Latin-1.
    private static func percentU(_ scalars: [Unicode.Scalar], at start: Int) -> ([Unicode.Scalar], Int)? {
        guard scalars[start] == "%", start + 6 <= scalars.count, scalars[start + 1] == "u" || scalars[start + 1] == "U",
              let value = number(scalars[(start + 2)..<(start + 6)], radix: 16), let scalar = Unicode.Scalar(value)
        else { return nil }
        return ([scalar], 6)
    }

    /// `&#NN;` or `&#xHH;`, also without the `;` as HTML reads them, and `&amp;`, which hides a
    /// reference behind another (`&amp;#97;`).
    private static func reference(_ scalars: [Unicode.Scalar], at start: Int) -> ([Unicode.Scalar], Int)? {
        guard scalars[start] == "&", start + 2 < scalars.count else { return nil }
        if scalars[start...].prefix(5).elementsEqual("&amp;".unicodeScalars) { return (["&"], 5) }
        guard scalars[start + 1] == "#" else { return nil }
        let isHex = scalars[start + 2] == "x" || scalars[start + 2] == "X"
        let digitsStart = start + (isHex ? 3 : 2)
        var end = digitsStart
        while end < scalars.count, end - digitsStart < maximumReferenceDigits, isHex ? hex(scalars[end]) != nil : ("0"..."9").contains(scalars[end]) {
            end += 1
        }
        let digits = scalars[digitsStart..<end].drop(while: { $0 == "0" })
        guard end > digitsStart, let value = digits.isEmpty ? 0 : number(digits, radix: isHex ? 16 : 10), let scalar = Unicode.Scalar(value)
        else { return nil }
        let length = (end < scalars.count && scalars[end] == ";" ? end + 1 : end) - start
        return ([scalar], length)
    }

    /// `\uXXXX`, `\u{…}` or `\xXX`.
    private static func backslash(_ scalars: [Unicode.Scalar], at start: Int) -> ([Unicode.Scalar], Int)? {
        guard scalars[start] == "\\", start + 1 < scalars.count else { return nil }
        let digits: ArraySlice<Unicode.Scalar>
        let length: Int
        switch scalars[start + 1] {
        case "u" where start + 2 < scalars.count && scalars[start + 2] == "{":
            guard let close = scalars[(start + 3)...].prefix(9).firstIndex(of: "}") else { return nil }
            (digits, length) = (scalars[(start + 3)..<close], close + 1 - start)
        case "u":
            guard start + 6 <= scalars.count else { return nil }
            (digits, length) = (scalars[(start + 2)..<(start + 6)], 6)
        case "x":
            guard start + 4 <= scalars.count else { return nil }
            (digits, length) = (scalars[(start + 2)..<(start + 4)], 4)
        default:
            return nil
        }
        guard !digits.isEmpty, let value = number(digits, radix: 16), let scalar = Unicode.Scalar(value) else { return nil }
        return ([scalar], length)
    }

    private static func number(_ digits: ArraySlice<Unicode.Scalar>, radix: UInt32) -> UInt32? {
        guard digits.count <= 8 else { return nil }
        var value: UInt32 = 0
        for digit in digits {
            guard let digitValue = radix == 16 ? hex(digit) : ("0"..."9").contains(digit) ? digit.value - 0x30 : nil else { return nil }
            value = value * radix + digitValue
        }
        return value
    }

    private static func hex(_ scalar: Unicode.Scalar) -> UInt32? {
        switch scalar {
        case "0"..."9": scalar.value - 0x30
        case "a"..."f": scalar.value - 0x61 + 10
        case "A"..."F": scalar.value - 0x41 + 10
        default: nil
        }
    }
}
