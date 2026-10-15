import Foundation

/// Reads a scalar outside ASCII as the ASCII it stands for, so that a field name spelled with
/// look-alike letters (`pаssword` with a Cyrillic `а`), styled letters (`𝐩𝐚𝐬𝐬𝐰𝐨𝐫𝐝`, `ⓟassword`) or
/// accented letters is read like the plain one.
///
/// The results are cached per scalar: logs repeat the same few non-ASCII characters, and the
/// compatibility decomposition goes through Foundation.
struct LatinFolding {
    /// A scalar that is read as nothing the detectors match.
    static let unreadable: UInt8 = 0xFF

    private var cache: [UInt32: [UInt8]] = [:]

    mutating func bytes(for scalar: Unicode.Scalar) -> [UInt8] {
        if let cached = cache[scalar.value] { return cached }
        let folded = Self.fold(scalar)
        cache[scalar.value] = folded
        return folded
    }

    private static func fold(_ scalar: Unicode.Scalar) -> [UInt8] {
        let value = scalar.value
        if (0xFF01...0xFF5E).contains(value) { return [UInt8(value - 0xFEE0)] }
        if let digit = ScalarClass.decimalDigit(scalar) { return [UInt8(ascii: "0") + digit] }
        switch value {
        // Every space separator of Unicode (category Zs) except the ASCII space.
        case 0x00A0, 0x1680, 0x2000...0x200A, 0x202F, 0x205F, 0x3000: return [UInt8(ascii: " ")]
        // Single characters drawn as `:=`, `::=`, `==`, `===` and small or ratio forms of `=` and `:`.
        case 0x2254, 0x2A74, 0x2A75, 0x2A76, 0xFE66: return [UInt8(ascii: "=")]
        case 0x2236, 0xFE55: return [UInt8(ascii: ":")]
        default: break
        }
        if let latin = lookAlikes[value] { return Array(latin.utf8) }
        return compatibilityASCII(scalar) ?? [unreadable]
    }

    /// The compatibility decomposition of the scalar without its combining marks, when every
    /// scalar left is ASCII or a look-alike of it: `𝐩` and `ⓟ` read as `p`, `é` as `e`, `︓` as `:`.
    private static func compatibilityASCII(_ scalar: Unicode.Scalar) -> [UInt8]? {
        var bytes: [UInt8] = []
        for part in String(scalar).decomposedStringWithCompatibilityMapping.unicodeScalars
        where !ScalarClass.isInvisible(part) {
            if part.isASCII {
                bytes.append(UInt8(part.value))
            } else if let latin = lookAlikes[part.value] {
                bytes += Array(latin.utf8)
            } else {
                return nil
            }
        }
        return bytes.isEmpty ? nil : bytes
    }

    /// Letters of other scripts that look like a Latin letter, and Latin letters without a
    /// decomposition, mapped to the ASCII they are read as. Taken from the pairs in Unicode's
    /// confusables data that matter for field names.
    static let lookAlikes: [UInt32: String] = [
        // Cyrillic
        0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y", 0x0445: "x",
        0x0455: "s", 0x0456: "i", 0x0458: "j", 0x0501: "d", 0x051B: "q", 0x051D: "w", 0x04BB: "h",
        0x04CF: "l", 0x04AF: "y", 0x0475: "v", 0x043A: "k",
        0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M", 0x041D: "H", 0x041E: "O",
        0x0420: "P", 0x0421: "C", 0x0422: "T", 0x0425: "X", 0x0423: "Y", 0x0405: "S", 0x0406: "I",
        0x0408: "J", 0x051A: "Q", 0x051C: "W", 0x04AE: "Y", 0x04C0: "I", 0x04BA: "H",
        // Greek
        0x03B1: "a", 0x03B5: "e", 0x03B7: "n", 0x03B9: "i", 0x03BA: "k", 0x03BC: "u", 0x03BD: "v",
        0x03BF: "o", 0x03C1: "p", 0x03C4: "t", 0x03C5: "u", 0x03C7: "x", 0x03B3: "y", 0x03C9: "w",
        0x03F2: "c", 0x03F3: "j",
        0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I", 0x039A: "K",
        0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
        0x03F9: "C",
        // Armenian
        0x0585: "o", 0x057D: "u", 0x0570: "h", 0x0578: "n", 0x0566: "q",
        // Cherokee
        0x13AA: "A", 0x13F4: "B", 0x13DF: "C", 0x13AC: "E", 0x13BB: "H", 0x13AB: "J", 0x13E6: "K",
        0x13B7: "M", 0x13E2: "P", 0x13DA: "S", 0x13A2: "T", 0x13B3: "W", 0x13C3: "Z",
        // Latin letters that do not decompose
        0x0131: "i", 0x0237: "j", 0x0251: "a", 0x0261: "g", 0x0269: "i", 0x026A: "i", 0x00DF: "ss",
        0x00E6: "ae", 0x00C6: "AE", 0x0153: "oe", 0x0152: "OE", 0x00F8: "o", 0x00D8: "O", 0x00F0: "d",
        0x0111: "d", 0x0110: "D", 0x0127: "h", 0x0142: "l", 0x0141: "L", 0x014B: "n", 0x0138: "k",
    ]
}
