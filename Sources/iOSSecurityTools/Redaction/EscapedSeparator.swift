/// `=` or `:` written as an escape: percent-encoded (`%3D`, also encoded again as `%253D`), as an
/// HTML character reference (`&#61;`, `&#x3A;`, `&equals;`, `&colon;`) or as a JSON or
/// JavaScript escape (`=`, `\x3A`).
struct EscapedSeparator {
    /// Where the escape ends.
    let end: Int

    init?(in scalars: [Unicode.Scalar], at start: Int, upper: Int) {
        guard let (value, end) = Self.decode(scalars, at: start, upper: upper), value == 0x3D || value == 0x3A else { return nil }
        self.end = end
    }

    private static func decode(_ scalars: [Unicode.Scalar], at start: Int, upper: Int) -> (UInt32, Int)? {
        switch scalars[start] {
        case "%":
            guard var value = hexadecimal(scalars, from: start + 1, count: 2, upper: upper) else { return nil }
            var end = start + 3
            // `%25` is an encoded `%`: `%253D` is `%3D` encoded once more.
            for _ in 0..<3 where value == 0x25 {
                guard let inner = hexadecimal(scalars, from: end, count: 2, upper: upper) else { break }
                value = inner
                end += 2
            }
            return (value, end)
        case "\\":
            guard start + 1 < upper else { return nil }
            let count = scalars[start + 1] == "u" ? 4 : scalars[start + 1] == "x" ? 2 : 0
            guard count > 0, let value = hexadecimal(scalars, from: start + 2, count: count, upper: upper) else { return nil }
            return (value, start + 2 + count)
        case "&":
            return characterReference(scalars, at: start, upper: upper)
        default:
            return nil
        }
    }

    private static func characterReference(_ scalars: [Unicode.Scalar], at start: Int, upper: Int) -> (UInt32, Int)? {
        for (name, value) in [("&equals;", UInt32(0x3D)), ("&colon;", 0x3A)] {
            let letters = Array(name.unicodeScalars)
            if start + letters.count <= upper, Array(scalars[start..<start + letters.count]) == letters { return (value, start + letters.count) }
        }
        guard start + 2 < upper, scalars[start + 1] == "#" else { return nil }
        let isHexadecimal = scalars[start + 2] == "x" || scalars[start + 2] == "X"
        var j = start + (isHexadecimal ? 3 : 2)
        let digitsStart = j
        var value: UInt32 = 0
        while j < upper, j - digitsStart < 7, let digit = digitValue(scalars[j], hexadecimal: isHexadecimal) {
            value = value * (isHexadecimal ? 16 : 10) + digit
            j += 1
        }
        guard j > digitsStart, j < upper, scalars[j] == ";" else { return nil }
        return (value, j + 1)
    }

    private static func hexadecimal(_ scalars: [Unicode.Scalar], from start: Int, count: Int, upper: Int) -> UInt32? {
        guard start + count <= upper else { return nil }
        var value: UInt32 = 0
        for scalar in scalars[start..<start + count] {
            guard let digit = digitValue(scalar, hexadecimal: true) else { return nil }
            value = value * 16 + digit
        }
        return value
    }

    private static func digitValue(_ scalar: Unicode.Scalar, hexadecimal: Bool) -> UInt32? {
        switch scalar {
        case "0"..."9": scalar.value - 0x30
        case "a"..."f" where hexadecimal: scalar.value - 0x61 + 10
        case "A"..."F" where hexadecimal: scalar.value - 0x41 + 10
        default: nil
        }
    }
}
