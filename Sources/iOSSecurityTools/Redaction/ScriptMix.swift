/// Whether a word mixes letters of scripts that are not written together, such as Latin and
/// Cyrillic in `pаssword` with a Cyrillic `а`.
///
/// Letters are sorted into Latin, Greek, Cyrillic, Armenian, Cherokee, Han with kana and Hangul,
/// and any other script. A word mixes scripts when it holds letters of two of these groups, except
/// that Latin goes with Han, kana and Hangul, as Japanese, Chinese and Korean text writes them
/// (`iPhoneで`). This sorts scripts by their Unicode blocks; it is not a table of look-alikes.
enum ScriptMix {
    /// Each group is a bit, so the groups seen in a word fit in one byte.
    private enum Group: UInt8 {
        case latin = 1, greek = 2, cyrillic = 4, armenian = 8, cherokee = 16, eastAsian = 32, other = 64
    }

    static func mixesScripts(_ scalars: some Sequence<Unicode.Scalar>) -> Bool {
        var seen: UInt8 = 0
        for scalar in scalars {
            if scalar.isASCII {
                if ASCII.isLetter(UInt8(scalar.value)) { seen |= Group.latin.rawValue }
                continue
            }
            guard let group = group(of: scalar) else { continue }
            seen |= group.rawValue
        }
        seen &= ~Group.eastAsian.rawValue
        // More than one bit is set.
        return seen & (seen &- 1) != 0
    }

    private static func group(of scalar: Unicode.Scalar) -> Group? {
        switch scalar.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter: break
        default: return nil
        }
        let value = scalar.value
        for (group, ranges) in blocks where ranges.contains(where: { $0.contains(value) }) {
            return group
        }
        return .other
    }

    private static let blocks: [(Group, [ClosedRange<UInt32>])] = [
        (.latin, [
            0x41...0x5A, 0x61...0x7A, 0xAA...0xAA, 0xBA...0xBA, 0xC0...0x24F, 0x250...0x2AF, 0x1D00...0x1DBF,
            0x1E00...0x1EFF, 0x2071...0x2071, 0x207F...0x207F, 0x2090...0x209C, 0x2C60...0x2C7F, 0xA720...0xA7FF,
            0xAB30...0xAB6F, 0xFB00...0xFB06, 0xFF21...0xFF3A, 0xFF41...0xFF5A,
        ]),
        (.greek, [0x370...0x3FF, 0x1F00...0x1FFF]),
        (.cyrillic, [0x400...0x52F, 0x1C80...0x1C8F, 0x2DE0...0x2DFF, 0xA640...0xA69F]),
        (.armenian, [0x530...0x58F, 0xFB13...0xFB17]),
        (.cherokee, [0x13A0...0x13FF, 0xAB70...0xABBF]),
        (.eastAsian, [
            0x1100...0x11FF, 0x2E80...0x2FDF, 0x3005...0x3007, 0x3040...0x30FF, 0x3100...0x318F, 0x31A0...0x31FF,
            0x3400...0x4DBF, 0x4E00...0x9FFF, 0xA960...0xA97F, 0xAC00...0xD7FF, 0xF900...0xFAFF, 0xFF66...0xFFDC,
            0x20000...0x3FFFF,
        ]),
    ]
}
