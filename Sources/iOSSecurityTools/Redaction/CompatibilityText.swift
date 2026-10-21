import Foundation

/// Reads a scalar outside ASCII as the ASCII it stands for under Unicode compatibility
/// decomposition (NFKD) without its marks: `ａ` and `𝐚` are `a`, `é` is `e`, `＝` and `︓` are `=`
/// and `:`, `≠` is `=`, a digit of any script is its digit, a dash of any kind is `-`, every space
/// is ` ` and a line or paragraph separator is `\n`. A scalar whose decomposition is not ASCII is
/// read as ``unreadable``. This is Unicode's own mapping, not a list of look-alikes: a Cyrillic
/// `а` stays unreadable.
///
/// The readings are cached, as logs repeat the same few non-ASCII characters and the
/// normalization goes through Foundation, in a table of at most ``maximumSlots`` readings in
/// which each scalar has one slot: a scalar whose slot holds another is read again and takes the
/// slot. A reading holds its bytes in place (see ``Reading``), so the table takes 24 bytes a slot
/// whatever a text holds. The twenty-first review measured 15 MiB of cached readings for a
/// megabyte of different scalars, which a dictionary kept one for each, each with an array of its
/// own.
final class CompatibilityText {
    /// A byte that no detector or separator matches.
    static let unreadable: UInt8 = 0xFF

    /// What a scalar outside ASCII is read as, worked out once: its ASCII reading, whether the
    /// scanning copy leaves it out (see ``ScalarClass/isInvisible(_:)``) and what the safe
    /// alphabet of free text makes of it. Up to four bytes of the reading are kept in place;
    /// a longer reading, which no scalar has today, is kept in an array.
    struct Reading {
        /// The first four bytes of the reading, the first in the low byte.
        private let packed: UInt32
        private let length: UInt8
        let isInvisible: Bool
        let alphabet: SafeAlphabet.Class
        /// The reading when it is longer than four bytes.
        private let long: [UInt8]?

        init(bytes: [UInt8], isInvisible: Bool, alphabet: SafeAlphabet.Class) {
            var packed: UInt32 = 0
            for (k, byte) in bytes.prefix(4).enumerated() { packed |= UInt32(byte) << (8 * k) }
            self.packed = packed
            length = UInt8(clamping: bytes.count)
            long = bytes.count > 4 ? bytes : nil
            self.isInvisible = isInvisible
            self.alphabet = alphabet
        }

        var bytes: Bytes { Bytes(packed: packed, count: Int(length), long: long) }

        /// The bytes of a reading, read where they are kept.
        struct Bytes: RandomAccessCollection {
            fileprivate let packed: UInt32
            let count: Int
            fileprivate let long: [UInt8]?

            fileprivate init(packed: UInt32, count: Int, long: [UInt8]?) {
                self.packed = packed
                self.count = count
                self.long = long
            }

            /// One ASCII byte.
            init(ascii byte: UInt8) {
                self.init(packed: UInt32(byte), count: 1, long: nil)
            }

            var startIndex: Int { 0 }
            var endIndex: Int { count }

            subscript(position: Int) -> UInt8 {
                if let long { return long[position] }
                return UInt8(truncatingIfNeeded: packed >> (8 * position))
            }
        }
    }

    /// The most readings the table keeps. It starts with ``firstSlots`` and doubles while scalars
    /// meet in a slot, so a text of a few non-ASCII characters keeps a small one.
    static let maximumSlots = 4_096
    private static let firstSlots = 64

    private struct Slot {
        /// The scalar whose reading the slot holds; 0, which is ASCII, when it holds none.
        var scalar: UInt32
        var reading: Reading
    }

    private static let emptySlot = Slot(scalar: 0, reading: Reading(bytes: [], isInvisible: false, alphabet: .unsafe))

    /// Empty until the first scalar outside ASCII is read.
    private var slots: [Slot] = []

    /// The slots of the table, for the tests.
    var slotCount: Int { slots.count }

    func ascii(_ scalar: Unicode.Scalar) -> Reading.Bytes {
        if scalar.isASCII { return Reading.Bytes(ascii: UInt8(scalar.value)) }
        return reading(scalar).bytes
    }

    /// The reading of a scalar outside ASCII.
    func reading(_ scalar: Unicode.Scalar) -> Reading {
        if slots.isEmpty { slots = Array(repeating: Self.emptySlot, count: Self.firstSlots) }
        var slot = Self.slot(of: scalar.value, in: slots.count)
        if slots[slot].scalar == scalar.value { return slots[slot].reading }
        let reading = Self.read(scalar)
        if slots[slot].scalar != 0, slots.count < Self.maximumSlots {
            grow()
            slot = Self.slot(of: scalar.value, in: slots.count)
        }
        slots[slot] = Slot(scalar: scalar.value, reading: reading)
        return reading
    }

    /// The slot of a scalar in a table of `count` slots, a power of two: the high bits of the
    /// scalar times the golden ratio, so that neighbouring scalars spread over the table.
    private static func slot(of scalar: UInt32, in count: Int) -> Int {
        Int((scalar &* 0x9E37_79B1) >> UInt32(32 - count.trailingZeroBitCount))
    }

    /// Doubles the table. A reading whose new slot is taken already is dropped.
    private func grow() {
        var grown = Array(repeating: Self.emptySlot, count: slots.count * 2)
        for old in slots where old.scalar != 0 {
            let slot = Self.slot(of: old.scalar, in: grown.count)
            if grown[slot].scalar == 0 { grown[slot] = old }
        }
        slots = grown
    }

    private static func read(_ scalar: Unicode.Scalar) -> Reading {
        let alphabet = SafeAlphabet.class(of: scalar)
        var bytes = readASCII(scalar)
        // A letter, mark or number is never read as punctuation or a space (`⑴` decomposes to
        // `(1)`, `🄁` to `0,`): a key or a word would be split where the text holds one character.
        // Free text is cut at such a scalar, as its class says (see ``SafeAlphabet/class(of:)``);
        // the value detectors, which read on where no cut is made, read it as one character.
        if ScalarClass.isLetterOrNumber(scalar), bytes.contains(where: { $0 < 0x80 && !ASCII.isAlphanumeric($0) }) { bytes = [unreadable] }
        return Reading(bytes: bytes, isInvisible: ScalarClass.isInvisible(scalar), alphabet: alphabet)
    }

    private static func readASCII(_ scalar: Unicode.Scalar) -> [UInt8] {
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
