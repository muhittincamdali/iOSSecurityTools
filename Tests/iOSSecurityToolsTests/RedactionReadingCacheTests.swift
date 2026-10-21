import Foundation
import Testing
@testable import iOSSecurityTools

/// The readings of scalars outside ASCII are cached in a table of at most
/// ``CompatibilityText/maximumSlots`` readings, each 16 bytes with its bytes in place. The
/// twenty-first review measured 15 MiB of cached readings for a megabyte of different scalars,
/// which a dictionary kept one for each, every reading with an array of its own.
@Suite("SensitiveDataRedactor readings cache")
struct RedactionReadingCacheTests {
    @Test("the readings cache keeps at most its slots and gives each scalar its own reading")
    func theCacheIsBounded() {
        let cached = CompatibilityText()
        let scalars = (UInt32(0x80)...0x3FFFF).compactMap(Unicode.Scalar.init)
        let first = scalars.map { cached.reading($0) }
        #expect(cached.slotCount == CompatibilityText.maximumSlots)
        // Read again in the other order, after the table has dropped and taken readings, and once
        // more from a table of its own for every 97th scalar.
        var mismatches: [String] = []
        for index in scalars.indices.reversed() {
            let again = cached.reading(scalars[index])
            let fresh = index % 97 == 0 ? CompatibilityText().reading(scalars[index]) : again
            for reading in [again, fresh] where Array(reading.bytes) != Array(first[index].bytes) || reading.alphabet != first[index].alphabet
                || reading.isInvisible != first[index].isInvisible {
                mismatches.append(String(format: "U+%04X", scalars[index].value))
            }
        }
        #expect(mismatches.isEmpty, "\(mismatches.prefix(10))")
        #expect(cached.slotCount == CompatibilityText.maximumSlots)
        #expect(MemoryLayout<CompatibilityText.Reading>.stride <= 16)
        // A text of a few scalars outside ASCII keeps a small table, and one of ASCII none.
        let small = CompatibilityText()
        for scalar in "Kullanıcı giriş yaptı ve sipariş verdi".unicodeScalars where !scalar.isASCII { _ = small.reading(scalar) }
        #expect(small.slotCount <= 128)
        #expect(CompatibilityText().slotCount == 0)
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
