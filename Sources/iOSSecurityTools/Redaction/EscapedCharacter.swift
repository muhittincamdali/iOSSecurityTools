/// A letter, digit or name punctuation written as an escape: `%77` (percent-encoding), `&#119;`
/// or `&#x77;` (an HTML character reference) and `w` (a JSON or JavaScript escape).
///
/// Field names are read with these decoded, so `pass%77ord=…` is read as `password=…`. Only
/// characters that cannot end a value are decoded (letters, digits, `_`, `-`, `.`, `:` and `=`),
/// so decoding never makes a value shorter: `password=a%26b` still hides `a%26b` whole.
struct EscapedCharacter {
    /// The decoded ASCII character.
    let byte: UInt8
    /// How many scalars the escape takes in the original text.
    let length: Int

    init?(in scalars: [Unicode.Scalar], at start: Int) {
        let decoded: (value: UInt32, length: Int)?
        switch scalars[start] {
        case "%": decoded = Self.hexadecimal(in: scalars, from: start + 1, count: 2).map { ($0.value, $0.length + 1) }
        case "\\":
            guard start + 1 < scalars.count, scalars[start + 1] == "u" else { return nil }
            decoded = Self.hexadecimal(in: scalars, from: start + 2, count: 4).map { ($0.value, $0.length + 2) }
        case "&": decoded = Self.characterReference(in: scalars, at: start)
        default: return nil
        }
        guard let decoded, decoded.value < 0x80, Self.isDecoded(UInt8(decoded.value)) else { return nil }
        byte = UInt8(decoded.value)
        length = decoded.length
    }

    private static func isDecoded(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"): true
        default: [UInt8(ascii: "_"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: ":"), UInt8(ascii: "=")].contains(byte)
        }
    }

    /// `&#119;` or `&#x77;`, with up to seven digits and the closing `;`.
    private static func characterReference(in scalars: [Unicode.Scalar], at start: Int) -> (value: UInt32, length: Int)? {
        guard start + 2 < scalars.count, scalars[start + 1] == "#" else { return nil }
        let isHexadecimal = scalars[start + 2] == "x" || scalars[start + 2] == "X"
        let digitsStart = start + (isHexadecimal ? 3 : 2)
        var value: UInt32 = 0
        var end = digitsStart
        while end < scalars.count, end - digitsStart < 7 {
            guard let digit = digitValue(scalars[end], hexadecimal: isHexadecimal) else { break }
            value = value * (isHexadecimal ? 16 : 10) + digit
            end += 1
        }
        guard end > digitsStart, end < scalars.count, scalars[end] == ";" else { return nil }
        return (value, end + 1 - start)
    }

    private static func hexadecimal(in scalars: [Unicode.Scalar], from start: Int, count: Int) -> (value: UInt32, length: Int)? {
        guard start + count <= scalars.count else { return nil }
        var value: UInt32 = 0
        for scalar in scalars[start..<start + count] {
            guard let digit = digitValue(scalar, hexadecimal: true) else { return nil }
            value = value * 16 + digit
        }
        return (value, count)
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
