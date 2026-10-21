/// Decodes the escapes a name written as a value may hide a secret name behind, so that
/// `pass%77ord`, `p&#97;ssword` and `pass%2577ord` read as `password` where a name in structured
/// input is read for secret words: a name held by a field (`{"ParameterKey":"Db%50assword"}`), an
/// element of a JSON array, a URL path segment and the words of JSON written into a line. Free
/// text itself never decodes an escape: one cuts the text (see
/// ``FreeTextScanner/isEscape(at:)``). The decoded name is never read alone: decoding takes the
/// hex letters that start a name for digits of the escape before it (`%card` decodes to U+FFFD
/// and `rd`, `&#xcvv` to U+000C and `vv`), so the name is read as written too, and the reading
/// that hides more counts (see ``FreeTextScanner/read(_:)``).
///
/// Decoded are percent escapes (as UTF-8, and `%uXXXX`), HTML character references by number
/// (`&#97;`, `&#x61;`, also without the `;` and with leading zeros) and `&amp;`, round after
/// round up to ``maximumRounds`` times. A backslash escape is never decoded, whatever its form:
/// a word with one cannot be read (see ``FreeTextScanner/backslashEscapes(at:)``), so a name
/// with one names a secret (`\u0070assword`, `pa\x{73}sword`). Keys are never decoded for an
/// allowlist: a key with an escape is not plain ASCII, so its value is hidden.
enum EscapeDecoder {
    static let maximumRounds = 4

    /// The most digits read in a character reference, leading zeros included.
    static let maximumReferenceDigits = 16

    /// Whether a scalar can start an escape.
    static func startsEscape(_ scalar: Unicode.Scalar) -> Bool {
        scalar == "%" || scalar == "&"
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
            if let (decoded, length) = percentRun(scalars, at: i) ?? percentU(scalars, at: i) ?? reference(scalars, at: i) {
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
