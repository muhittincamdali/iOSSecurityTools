import Foundation

/// Reads a scalar outside ASCII as the ASCII it stands for under Unicode compatibility
/// decomposition (NFKD) without its marks: `ａ` and `𝐚` are `a`, `é` is `e`, `＝` and `︓` are `=`
/// and `:`, `≠` is `=`, a digit of any script is its digit, a dash of any kind is `-`, every space
/// is ` ` and a line or paragraph separator is `\n`. A scalar whose decomposition is not ASCII is
/// read as ``unreadable``. This is Unicode's own mapping, not a list of look-alikes: a Cyrillic
/// `а` stays unreadable.
///
/// The readings are cached, as logs repeat the same few non-ASCII characters and the
/// normalization goes through Foundation, in a table whose size is fixed when it is made: about one
/// slot for each scalar of the input it serves (a text cannot hold more different scalars than
/// that), from ``fewestSlots`` to ``mostSlots``. The table never grows. Its slots are in sets of
/// two, and a scalar's set is chosen with Swift's `Hasher`, which is seeded at random in every
/// process as `Dictionary` is, so no text can choose scalars that meet in a set; two scalars that
/// meet anyway both keep their readings, and a third takes the slot of the one read longer ago. A
/// reading holds its bytes in place (see ``Reading``), so a slot takes 24 bytes whatever a text
/// holds. One table serves a whole text, body or URL, with every field, part and segment in it.
///
/// The twenty-first review measured 15 MiB of cached readings for a megabyte of different
/// scalars, which a dictionary kept one for each, each with an array of its own. The table that
/// replaced it doubled whenever two scalars met in a slot, and the twenty-second review found
/// scalars that meet in every size (`丆幛`, `Âۿ`): seven of them took a new table to 4,096 slots,
/// and a megabyte of short log lines made of them took 1.77 s.
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

    /// The sizes of a table: slots for a text of a few scalars, and for a text, body or URL of
    /// 8,192 scalars or more (192 KiB), which holds the characters of a megabyte of Chinese.
    static let fewestSlots = 16
    static let mostSlots = 8_192

    private struct Slot {
        /// The scalar whose reading the slot holds; 0, which is ASCII, when it holds none.
        var scalar: UInt32
        var reading: Reading
    }

    private static let emptySlot = Slot(scalar: 0, reading: Reading(bytes: [], isInvisible: false, alphabet: .unsafe))

    /// The number of slots, a power of two, fixed when the table is made.
    private let size: Int
    /// Empty until the first scalar outside ASCII is read, so ASCII text makes no table.
    private var slots: [Slot] = []

    /// The slots of the table, for the tests: 0 until a scalar outside ASCII is read.
    var slotCount: Int { slots.count }
    /// How many readings were worked out through Foundation rather than found in the table, for
    /// the tests.
    private(set) var uncachedReadings = 0

    /// - Parameter length: The number of scalars (or bytes) of the input the table serves.
    init(length: Int = mostSlots) {
        var size = Self.fewestSlots
        while size < length, size < Self.mostSlots { size *= 2 }
        self.size = size
    }

    func ascii(_ scalar: Unicode.Scalar) -> Reading.Bytes {
        if scalar.isASCII { return Reading.Bytes(ascii: UInt8(scalar.value)) }
        return reading(scalar).bytes
    }

    /// The reading of a scalar outside ASCII.
    func reading(_ scalar: Unicode.Scalar) -> Reading {
        if slots.isEmpty { slots = Array(repeating: Self.emptySlot, count: size) }
        var hasher = Hasher()
        hasher.combine(scalar.value)
        // The first slot of the scalar's set; the slot after it is the other one of the set.
        let first = (hasher.finalize() & (size / 2 - 1)) * 2
        if slots[first].scalar == scalar.value { return slots[first].reading }
        if slots[first + 1].scalar == scalar.value {
            slots.swapAt(first, first + 1)
            return slots[first].reading
        }
        let reading = Self.read(scalar)
        uncachedReadings += 1
        slots[first + 1] = slots[first]
        slots[first] = Slot(scalar: scalar.value, reading: reading)
        return reading
    }

    private static func read(_ scalar: Unicode.Scalar) -> Reading {
        let alphabet = SafeAlphabet.class(of: scalar)
        var bytes = readsOutsideASCII(scalar) ? unreadableReading : readASCII(scalar)
        // A letter, mark or number is never read as punctuation or a space (`⑴` decomposes to
        // `(1)`, `🄁` to `0,`): a key or a word would be split where the text holds one character.
        // Free text is cut at such a scalar, as its class says (see ``SafeAlphabet/class(of:)``);
        // the value detectors, which read on where no cut is made, read it as one character.
        if ScalarClass.isLetterOrNumber(scalar), bytes.contains(where: { $0 < 0x80 && !ASCII.isAlphanumeric($0) }) { bytes = [unreadable] }
        return Reading(bytes: bytes, isInvisible: ScalarClass.isInvisible(scalar), alphabet: alphabet)
    }

    /// Whether a scalar is an ideograph or a Hangul syllable, which is read as ``unreadable``
    /// without asking Foundation: an ideograph has no decomposition or one to other ideographs, and
    /// a syllable decomposes to Hangul letters. They are most of the different characters a text
    /// can hold, so a text of more of them than its table has slots (a megabyte of Chinese) does not
    /// go through Foundation for each one it reads again. A test compares this with
    /// ``readASCII(_:)`` for every such scalar.
    static func readsOutsideASCII(_ scalar: Unicode.Scalar) -> Bool {
        scalar.properties.isIdeographic || hangulSyllables.contains(scalar.value)
    }

    private static let hangulSyllables: ClosedRange<UInt32> = 0xAC00...0xD7A3
    /// One array for every such reading, so reading a scalar makes none.
    private static let unreadableReading = [unreadable]

    /// The reading of a scalar through Foundation's compatibility decomposition.
    static func readASCII(_ scalar: Unicode.Scalar) -> [UInt8] {
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
