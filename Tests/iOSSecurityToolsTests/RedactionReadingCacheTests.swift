import Foundation
import Testing
@testable import iOSSecurityTools

/// The readings of scalars outside ASCII are cached in a table whose size is fixed when it is made,
/// from ``CompatibilityText/fewestSlots`` to ``CompatibilityText/mostSlots`` slots of 24 bytes,
/// each reading with its bytes in place. The twenty-first review measured 15 MiB of cached
/// readings for a megabyte of different scalars, which a dictionary kept one for each, every
/// reading with an array of its own. The table that replaced it doubled whenever two scalars met
/// in a slot, and the twenty-second review found scalars that meet in every size: `丆幛丆幛丆幛丆`
/// took a new table from 64 to 4,096 slots, and a megabyte of short log lines of them took 1.77 s.
@Suite("SensitiveDataRedactor readings cache")
struct RedactionReadingCacheTests {
    @Test("the readings cache keeps a fixed number of slots and gives each scalar its own reading")
    func theCacheIsBounded() {
        let cached = CompatibilityText()
        let scalars = (UInt32(0x80)...0x3FFFF).compactMap(Unicode.Scalar.init)
        let first = scalars.map { cached.reading($0) }
        #expect(cached.slotCount == CompatibilityText.mostSlots)
        // Read again in the other order, after the table has dropped and taken readings, and once
        // more from a table of its own for every 97th scalar.
        var mismatches: [String] = []
        for index in scalars.indices.reversed() {
            let again = cached.reading(scalars[index])
            let fresh = index % 97 == 0 ? CompatibilityText(length: 1).reading(scalars[index]) : again
            for reading in [again, fresh] where Array(reading.bytes) != Array(first[index].bytes) || reading.alphabet != first[index].alphabet
                || reading.isInvisible != first[index].isInvisible {
                mismatches.append(String(format: "U+%04X", scalars[index].value))
            }
        }
        #expect(mismatches.isEmpty, "\(mismatches.prefix(10))")
        #expect(cached.slotCount == CompatibilityText.mostSlots)
        #expect(MemoryLayout<CompatibilityText.Reading>.stride <= 16)
        // A text of a few scalars outside ASCII keeps a small table, and one of ASCII none.
        let sentence = "Kullanıcı giriş yaptı ve sipariş verdi"
        let small = CompatibilityText(length: sentence.unicodeScalars.count)
        for scalar in sentence.unicodeScalars where !scalar.isASCII { _ = small.reading(scalar) }
        #expect(small.slotCount == 64)
        #expect(small.uncachedReadings == 2)
        #expect(CompatibilityText().slotCount == 0)
    }

    @Test("a table has about one slot for each scalar of its input, from 16 to 8,192")
    func theSizeFollowsTheInput() {
        for (length, slots) in [(0, 16), (1, 16), (7, 16), (16, 16), (17, 32), (38, 64), (1_000, 1_024), (4_096, 4_096), (5_000, 8_192), (1_000_000, 8_192)] {
            let table = CompatibilityText(length: length)
            _ = table.reading("é")
            #expect(table.slotCount == slots, "\(length)")
        }
    }

    /// `丆幛` met in every table of 64 to 4,096 slots and `Âۿ` in every one of 64 to 2,048, so
    /// each new one doubled the table again.
    static let collidingPairs: [(Unicode.Scalar, Unicode.Scalar)] = [("\u{4E06}", "\u{5E5B}"), ("\u{00C2}", "\u{06FF}")]

    @Test("scalars that met in every size of the earlier table keep the table's size and are read once each")
    func collidingScalarsKeepTheSize() {
        for (a, b) in Self.collidingPairs {
            for count in 7...16 {
                for length in [count + 4, 64, 256, 4_096] {
                    let table = CompatibilityText(length: length)
                    let size = CompatibilityText(length: length).sizeAfterOneReading
                    for k in 0..<count { _ = table.reading(k % 2 == 0 ? a : b) }
                    #expect(table.slotCount == size, "\(a)\(b) × \(count) in \(length)")
                    #expect(table.slotCount <= 128 || length > 128)
                    #expect(table.uncachedReadings == 2, "\(a)\(b) × \(count) in \(length)")
                }
            }
        }
    }

    @Test("any two scalars read in turn are worked out once each, in a table of any size")
    func anyTwoScalarsShareASet() {
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<2_000 {
            let a = Self.randomScalar(using: &generator)
            var b = Self.randomScalar(using: &generator)
            while b == a { b = Self.randomScalar(using: &generator) }
            let length = [1, 20, 100, 1_000, 10_000].randomElement(using: &generator)!
            let table = CompatibilityText(length: length)
            for k in 0..<16 { _ = table.reading(k % 2 == 0 ? a : b) }
            #expect(table.uncachedReadings == 2, "U+\(String(a.value, radix: 16)) U+\(String(b.value, radix: 16)) in \(length)")
        }
    }

    private static func randomScalar(using generator: inout some RandomNumberGenerator) -> Unicode.Scalar {
        while true {
            if let scalar = Unicode.Scalar(UInt32.random(in: 0x80...0x3FFFF, using: &generator)) { return scalar }
        }
    }

    @Test("every ideograph and Hangul syllable read without Foundation reads as Foundation reads it")
    func ideographsAndSyllablesReadAsFoundationReadsThem() {
        let scalars = (UInt32(0x80)...0x10FFFF).compactMap(Unicode.Scalar.init).filter(CompatibilityText.readsOutsideASCII)
        // The CJK blocks, the compatibility ideographs, Tangut, Nüshu, Khitan and the syllables.
        #expect(scalars.count > 100_000)
        let different = scalars.filter { CompatibilityText.readASCII($0) != [CompatibilityText.unreadable] }
        #expect(different.isEmpty, "\(different.prefix(10).map { String($0.value, radix: 16) })")
    }

    @Test("a reading keeps up to four bytes in place and a longer one whole")
    func readingsKeepTheirBytes() {
        for bytes in [[], [0x61], [0x66, 0x69], Array("viii".utf8), Array("abcdefgh".utf8), [CompatibilityText.unreadable]] as [[UInt8]] {
            let reading = CompatibilityText.Reading(bytes: bytes, isInvisible: false, alphabet: .letter)
            #expect(Array(reading.bytes) == bytes)
        }
        // No scalar of Unicode has a reading longer than four bytes today (`Ⅷ` is `VIII`).
        #expect(Array(CompatibilityText().reading("\u{2167}").bytes) == Array("VIII".utf8))
    }
}

private extension CompatibilityText {
    /// The slots of the table once it holds a reading.
    var sizeAfterOneReading: Int {
        _ = reading("é")
        return slotCount
    }
}
