import Foundation
import Testing
@testable import iOSSecurityTools

/// How a word of free text is matched with the secret words: one pass per secret word, with at
/// most one letter that has no ASCII form (a wildcard) standing for a letter or, between two
/// letters, for none.
@Suite("SensitiveDataRedactor name matching")
struct RedactionNameMatchingTests {
    let redactor = SensitiveDataRedactor()

    @Test("one letter without an ASCII form stands for a letter or for none", arguments: [
        "pɑssword hunter2", "passwıord hunter2", "passꞏword hunter2", "ıd_token hunter2", "tokɛns hunter2", "ɑpi_key hunter2",
        "Authorizɑtion hunter2", "user_pın hunter2", "sɛcret hunter2",
    ])
    func oneWildcard(line: String) {
        #expect(!redactor.redact(line).contains("hunter2"), "\(line)")
    }

    // The logging guide names this limit under "What it does not find": free text without a
    // separator is a best effort, and no list of look-alikes is kept to chase it.
    @Test("a name written without a separator and two or more letters without an ASCII form is not found", arguments: [
        "pɑsswoʀd hunter2", "tɵkɛn hunter2", "passꞏwoꞏrd hunter2",
    ])
    func twoWildcards(line: String) {
        #expect(redactor.redact(line).contains("hunter2"), "\(line) is found: update the guide")
        let separated = line.replacingOccurrences(of: " hunter2", with: ": hunter2")
        #expect(!redactor.redact(separated).contains("hunter2"), "\(separated)")
    }

    @Test("words in Turkish and other languages that hold a wildcard stay readable", arguments: [
        "Kullanıcı sisteme başarıyla giriş yaptı", "kapıdaki ılgın ağaçları", "Ayşe ılgın", "bjørn dæhlie kom hjem",
    ])
    func ordinaryWords(line: String) {
        #expect(redactor.redact(line) == line)
    }

    /// The one-pass match finds the same secret words as trying the wildcard at every position,
    /// the way 2.1.0's first change did, on generated words.
    @Test("one pass finds what trying every wildcard position finds", arguments: 0..<8)
    func sameAsEveryPosition(seed: Int) {
        var random = SeededRandom(seed: UInt64(seed) + 71)
        var found = 0
        for _ in 0..<2_000 {
            let (bytes, wildcards) = Self.word(using: &random)
            guard let name = PlainName(looseBytes: bytes, wildcards: wildcards) else { continue }
            let reference = ReferenceMatch(looseBytes: bytes, wildcards: wildcards)
            let split = Int.random(in: 0...max(1, name.letters.count), using: &random)
            let across = { (range: Range<Int>) in range.lowerBound < split && range.upperBound > split }
            let first = name.firstSecret { _ in true }
            #expect(first == reference.firstSecret { _ in true }, "\(Self.shown(bytes, wildcards))")
            #expect(name.firstSecret(where: across) == reference.firstSecret(where: across), "\(Self.shown(bytes, wildcards)) split \(split)")
            if first != nil { found += 1 }
        }
        // Most generated words hold a secret word, some do not: both kinds are compared.
        #expect(found > 1_000 && found < 2_000)
    }

    /// A word made of a secret word or two, changed: letters made wildcards, uppercase or left
    /// out, wildcards and separators put in, other letters around them.
    private static func word(using random: inout SeededRandom) -> ([UInt8], [Bool]) {
        var bytes: [UInt8] = []
        var wildcards: [Bool] = []
        func append(_ byte: UInt8, wildcard: Bool = false) {
            bytes.append(byte)
            wildcards.append(wildcard)
        }
        let letters = Array("abcdeikmnoprstuwxyz".utf8)
        for _ in 0..<Int.random(in: 1...2, using: &random) {
            for _ in 0..<Int.random(in: 0...2, using: &random) { append(letters.randomElement(using: &random)!) }
            let secret = SecretNames.entries.randomElement(using: &random)!.letters
            for letter in secret {
                switch Int.random(in: 0..<20, using: &random) {
                case 0: append(CompatibilityText.unreadable, wildcard: true)
                case 1: append(letter)
                    append(CompatibilityText.unreadable, wildcard: true)
                case 2: append(ASCII.isLetter(letter) ? letter - 32 : letter)
                case 3: continue
                case 4: append(letter)
                    append(["_", "-", ".", " ", "~"].randomElement(using: &random)!.utf8.first!)
                default: append(letter)
                }
            }
            if Bool.random(using: &random) { append(UInt8(ascii: "s")) }
            if Int.random(in: 0..<4, using: &random) == 0 { append(UInt8(ascii: "_")) }
        }
        return (bytes, wildcards)
    }

    private static func shown(_ bytes: [UInt8], _ wildcards: [Bool]) -> String {
        String(zip(bytes, wildcards).map { $1 ? "?" : Character(Unicode.Scalar($0)) })
    }
}

/// The matching that tried a wildcard as no letter at every position of a secret word in turn,
/// kept here to check the one-pass match against.
private struct ReferenceMatch {
    let letters: [UInt8]
    let startsWord: [Bool]

    init(looseBytes bytes: [UInt8], wildcards: [Bool]) {
        var name = bytes
        for i in name.indices where !ASCII.isNameCharacter(name[i]) {
            name[i] = wildcards[i] ? UInt8(ascii: "x") : UInt8(ascii: "_")
        }
        var letters: [UInt8] = []
        var startsWord: [Bool] = []
        for i in name.indices where ASCII.isAlphanumeric(name[i]) {
            letters.append(wildcards[i] ? PlainName.wildcard : ASCII.lowercased(name[i]))
            startsWord.append(Self.startsWord(i, in: name))
        }
        self.letters = letters
        self.startsWord = startsWord
    }

    func firstSecret(where accepts: (Range<Int>) -> Bool) -> Range<Int>? {
        for start in letters.indices {
            let entries = SecretNames.entries.filter { letters[start] == PlainName.wildcard || $0.letters[0] == letters[start] }
            for entry in entries {
                guard let end = matchEnd(of: entry.letters, at: start), holds(entry.placement, start: start, end: end), accepts(start..<end)
                else { continue }
                return start..<end
            }
        }
        return nil
    }

    private func matchEnd(of word: [UInt8], at start: Int) -> Int? {
        if let end = spelledEnd(of: word, at: start, skipping: nil) { return end }
        guard letters.contains(PlainName.wildcard), word.count > 1 else { return nil }
        for k in (start + 1)..<max(start + 1, min(start + word.count, letters.count)) where letters[k] == PlainName.wildcard {
            if let end = spelledEnd(of: word, at: start, skipping: k) { return end }
        }
        return nil
    }

    private func spelledEnd(of word: [UInt8], at start: Int, skipping skipped: Int?) -> Int? {
        var end = start + word.count + (skipped == nil ? 0 : 1)
        guard end <= letters.count else { return nil }
        var usedWildcard = skipped != nil
        var k = start
        for expected in word {
            if k == skipped { k += 1 }
            if letters[k] != expected {
                guard letters[k] == PlainName.wildcard, !usedWildcard else { return nil }
                usedWildcard = true
            }
            k += 1
        }
        if end < letters.count, letters[end] == UInt8(ascii: "s"), !startsWord[end], endsWord(end + 1) { end += 1 }
        return end
    }

    private func holds(_ placement: SecretNames.Placement, start: Int, end: Int) -> Bool {
        switch placement {
        case .anywhere: true
        case .wordOrEnd: end == letters.count || (startsWord[start] && endsWord(end))
        case .word: startsWord[start] && endsWord(end)
        case .lastWord: startsWord[start] && end == letters.count
        }
    }

    private func endsWord(_ k: Int) -> Bool { k == letters.count || startsWord[k] }

    private static func startsWord(_ i: Int, in bytes: [UInt8]) -> Bool {
        guard i > 0 else { return true }
        let previous = bytes[i - 1]
        if !ASCII.isAlphanumeric(previous) || ASCII.isDigit(previous) != ASCII.isDigit(bytes[i]) { return true }
        guard ASCII.isUppercase(bytes[i]), ASCII.isLetter(previous) else { return false }
        if !ASCII.isUppercase(previous) { return true }
        return i + 1 < bytes.count && ASCII.isLetter(bytes[i + 1]) && !ASCII.isUppercase(bytes[i + 1])
    }
}
