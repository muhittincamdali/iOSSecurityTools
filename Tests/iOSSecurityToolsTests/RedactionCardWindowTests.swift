import Testing
@testable import iOSSecurityTools

/// The card number detector reads digit groups through a window and keeps the Luhn sums as a run
/// grows. It finds what the earlier reading of every group of a chain at once found, which this
/// test keeps as the reference.
@Suite("SensitiveDataRedactor card number window")
struct RedactionCardWindowTests {
    private static func passesLuhn(_ digits: [UInt8]) -> Bool {
        var sum = 0
        for (position, digit) in digits.reversed().enumerated() {
            var value = Int(digit)
            if position % 2 == 1 {
                value *= 2
                if value > 9 { value -= 9 }
            }
            sum += value
        }
        return sum % 10 == 0
    }

    /// The card numbers of the earlier reading, as byte ranges of the scanning copy.
    private static func reference(_ text: NormalizedText) -> [Range<Int>] {
        var found: [Range<Int>] = []
        var i = 0
        let bytes = text.bytes
        func isDigit(_ k: Int) -> Bool { ASCII.isDigit(bytes[k]) }
        func isSeparator(_ k: Int) -> Bool { bytes[k] == UInt8(ascii: " ") || bytes[k] == UInt8(ascii: "-") || bytes[k] == UInt8(ascii: "\t") }
        while i < bytes.count {
            guard isDigit(i), i == 0 || !text.gluesToWord(i - 1) else {
                i += 1
                continue
            }
            var groups: [Range<Int>] = []
            var groupStart = i
            var j = i
            while j < bytes.count {
                if isDigit(j) {
                    j += 1
                    continue
                }
                var separatorEnd = j
                while separatorEnd < bytes.count, separatorEnd - j < 3, isSeparator(separatorEnd) { separatorEnd += 1 }
                guard separatorEnd > j, separatorEnd < bytes.count, isDigit(separatorEnd) else { break }
                groups.append(groupStart..<j)
                groupStart = separatorEnd
                j = separatorEnd
            }
            groups.append(groupStart..<j)
            if j < bytes.count, text.isLetter(j), text.gluesToWord(j) { groups.removeLast() }
            var first = 0
            while first < groups.count {
                var digits: [UInt8] = []
                var best: Int?
                var last = first
                while last < groups.count {
                    digits += groups[last].map { bytes[$0] - UInt8(ascii: "0") }
                    if digits.count > 19 { break }
                    if digits.count >= 13, passesLuhn(digits) { best = last }
                    last += 1
                }
                if let best {
                    found.append(groups[first].lowerBound..<groups[best].upperBound)
                    first = best + 1
                } else {
                    first += 1
                }
            }
            i = max(j, i + 1)
        }
        return found
    }

    @Test("the window finds what reading every group at once found", arguments: 0..<4)
    func sameAsReference(seed: Int) {
        var random = SeededRandom(seed: 0xCA4D_0000 + UInt64(seed))
        let separators = [" ", "-", "\t", "  ", " - ", "x", ".", "", "a "]
        for _ in 0..<2_000 {
            var text = ""
            for _ in 0..<Int.random(in: 1...30, using: &random) {
                text += String((0..<Int.random(in: 1...8, using: &random)).map { _ in "0123456789".randomElement(using: &random)! })
                text += separators.randomElement(using: &random)!
            }
            if Int.random(in: 0..<4, using: &random) == 0 { text += "4242424242424242" }
            let normalized = NormalizedText(Array(text.unicodeScalars), compatibility: CompatibilityText())
            let spans = normalized.cardSpans().map { normalized.byteIndex(atOrAfter: $0.start)..<normalized.byteIndex(atOrAfter: $0.end) }
            #expect(spans == Self.reference(normalized), "\(text.debugDescription)")
        }
    }

    @Test("a megabyte of digit groups keeps a window of them")
    func longChains() {
        let text = String(repeating: "4242 ", count: 200_000)
        let normalized = NormalizedText(Array(text.unicodeScalars), compatibility: CompatibilityText())
        #expect(normalized.cardSpans().count == 50_000)
    }
}
