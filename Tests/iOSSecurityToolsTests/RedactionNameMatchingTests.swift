import Foundation
import Testing
@testable import iOSSecurityTools

/// How a word of free text is compared with the secret names: by its ASCII skeleton. Every letter
/// that has no ASCII form once the text is read in compatibility form is left out, and what
/// remains is compared with the names, a plural `s` included; a name also counts with one of its
/// letters missing where letters were left out. The sixteenth review found the matching that read
/// such a letter as any letter or as none, trying one and then the other, missing a name when the
/// letter came right before the last letter of a short name (`piꞏn`, `tokeın`) or before its
/// plural `s` (`tokenꞏs`); the skeleton reads both at once.
@Suite("SensitiveDataRedactor name matching")
struct RedactionNameMatchingTests {
    let redactor = SensitiveDataRedactor()

    @Test("letters without an ASCII form are left out of a word, anywhere and as many as there are", arguments: [
        "piꞏn hunter2", "tokeın hunter2", "keꞏy hunter2", "pꞏw hunter2", "sessioꞏn hunter2", "otꞏp hunter2", "cvꞏc hunter2",
        "autꞏh hunter2", "tokenꞏs hunter2", "pinꞏs hunter2", "keyıs hunter2", "secretꞏs hunter2", "otpıs hunter2", "passwıord hunter2",
        "passꞏword hunter2", "passꞏwoꞏrd hunter2", "tꞏoꞏkꞏeꞏn hunter2", "ıd_token hunter2", "ɑpi_key hunter2", "user_piꞏn hunter2",
        "status=200 piꞏn hunter2", "piłn hunter2", "otøp hunter2", "autßh hunter2", "pinǃ hunter2", "cvvʔ hunter2", "tokenı hunter2",
    ])
    func lettersAreLeftOut(line: String) {
        for (path, output) in RedactionCutRuleTests.everyPath(line) {
            #expect(!output.contains("hunter2"), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a name counts with one of its letters missing where a letter was left out", arguments: [
        "pɑssword hunter2", "user_pın hunter2", "sɛcret hunter2", "Authorizɑtion hunter2", "tokɛns hunter2", "pın hunter2",
        "login ᴘassword hunter2", "login tokeɴ hunter2", "login ıban hunter2", "cʟient_secrɛt hunter2", "pɑssꞏword hunter2",
        "tokɛnꞏs hunter2",
    ])
    func oneLetterInPlace(line: String) {
        for (path, output) in RedactionCutRuleTests.everyPath(line) {
            #expect(!output.contains("hunter2"), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
        }
    }

    // The logging guide names this limit under "What it does not find": free text without a
    // separator is a best effort, and no list of look-alikes is kept to chase it.
    @Test("two letters without an ASCII form in place of letters of one name, without a separator, are not found", arguments: [
        "pɑsswoʀd hunter2", "tɵkɛn hunter2", "pɑɑsword hunter2",
    ])
    func twoLettersInPlace(line: String) {
        #expect(redactor.redact(line).contains("hunter2"), "\(line) is found: update the guide")
        for separator in [": ", "=", "=\""] {
            let separated = line.replacingOccurrences(of: " hunter2", with: separator + "hunter2")
            #expect(!redactor.redact(separated).contains("hunter2"), "\(separated)")
        }
        #expect(!redactor.redact("\"" + line.replacingOccurrences(of: " hunter2", with: "\": hunter2")).contains("hunter2"))
    }

    @Test("words in Turkish and other languages stay readable", arguments: [
        "Kullanıcı sisteme başarıyla giriş yaptı", "kapıdaki ılgın ağaçları", "Ayşe ılgın", "bjørn dæhlie kom hjem", "Pınar kapıyı açtı",
    ])
    func ordinaryWords(line: String) {
        #expect(redactor.redact(line) == line)
    }

    // A word of another language that reads as a name with one letter missing is read as the
    // name: the guide names `yapın` (Turkish, "do") as hiding what follows it.
    @Test("a word that reads as a name with a letter missing hides what follows it, on purpose")
    func overHiding() {
        #expect(redactor.redact("lütfen kaydı yapın ve çıkın") == "lütfen kaydı yapın [redacted]")
    }

    /// Where a generated secret name with letters put in is written: free text without a
    /// separator, after an allowed key, before a tab or a line break.
    static let contexts: [@Sendable (String, String) -> String] = [
        { n, v in "\(n) \(v)" }, { n, v in "INFO login \(n) \(v) ok" }, { n, v in "status=200 \(n) \(v)" }, { n, v in "\(n)\t\(v)" },
        { n, v in "\(n)\n\(v)" }, { n, v in "(\(n) | \(v))" },
    ]

    @Test("no generated secret name with letters without an ASCII form put in or one put in place shows its value, on any path")
    func generatedNames() {
        var random = SeededRandom(seed: 0x5E_1E_70)
        for _ in 0..<500 {
            let entry = SecretNames.entries.randomElement(using: &random)!
            var name = entry.letters.map { Character(Unicode.Scalar($0)) }
            if entry.placement != .word, Bool.random(using: &random) { name.append("s") }
            // One letter put in place of a letter of the name, and letters put in anywhere.
            if Bool.random(using: &random) { name[Int.random(in: 0..<entry.letters.count, using: &random)] = Self.foreignLetters.randomElement(using: &random)! }
            for _ in 0..<Int.random(in: 1...3, using: &random) {
                name.insert(Self.foreignLetters.randomElement(using: &random)!, at: Int.random(in: 0...name.count, using: &random))
            }
            if name[0].isASCII, Bool.random(using: &random) { name[0] = Character(name[0].uppercased()) }
            let value = RedactionPropertyTests.value(using: &random)
            let line = Self.contexts.randomElement(using: &random)!(String(name), value)
            for (path, output) in RedactionCutRuleTests.everyPath(line) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    /// The matching of generated words finds the same secret word as trying every letter of every
    /// name as the missing one, on a skeleton written out from the word's characters on its own.
    @Test("one pass finds what trying every missing letter finds", arguments: 0..<8)
    func sameAsEveryMissingLetter(seed: Int) {
        var random = SeededRandom(seed: UInt64(seed) + 71)
        var found = 0
        for _ in 0..<2_000 {
            let word = Self.word(using: &random)
            let reference = ReferenceSkeleton(word)
            let scalars = Array(word.unicodeScalars)
            let text = NormalizedText(scalars, compatibility: CompatibilityText())
            let reading = LooseReading(text, [0..<text.count], source: scalars)?.secretEnd { _ in true }
            let first = reference.firstSecret { _ in true }
            #expect((reading != nil) == (first != nil), "\(word.debugDescription)")
            if let name = PlainName(skeleton: reference.bytes, leftOutBefore: reference.leftOutBefore, leftOutAtEnd: reference.leftOutAtEnd) {
                let split = Int.random(in: 0...max(1, name.letters.count), using: &random)
                let across = { (range: Range<Int>) in range.lowerBound < split && range.upperBound > split }
                #expect(name.firstSecret { _ in true } == first, "\(word.debugDescription)")
                #expect(name.firstSecret(where: across) == reference.firstSecret(where: across), "\(word.debugDescription) split \(split)")
            }
            if first != nil { found += 1 }
        }
        // Most generated words hold a secret word, some do not: both kinds are compared.
        #expect(found > 1_000 && found < 2_000)
    }

    /// Letters without an ASCII form, of scripts that do not mix with Latin, so that the words
    /// are read rather than cut as words that mix scripts.
    static let foreignLetters: [Character] = ["ꞏ", "ı", "ɑ", "ø", "ł", "ß", "ǃ", "ʔ", "ɛ", "ŧ", "ꞌ", "ð", "þ", "ħ"]

    /// A word made of a secret word or two, changed: letters without an ASCII form put in or put
    /// in place of a letter, letters uppercased or left out, separators put in, other letters
    /// around them.
    private static func word(using random: inout SeededRandom) -> String {
        var word = ""
        let letters = Array("abcdeikmnoprstuwxyz")
        for _ in 0..<Int.random(in: 1...2, using: &random) {
            for _ in 0..<Int.random(in: 0...2, using: &random) { word.append(letters.randomElement(using: &random)!) }
            let secret = String(decoding: SecretNames.entries.randomElement(using: &random)!.letters, as: UTF8.self)
            for letter in secret {
                switch Int.random(in: 0..<20, using: &random) {
                case 0: word.append(foreignLetters.randomElement(using: &random)!)
                case 1: word.append(letter)
                    word.append(foreignLetters.randomElement(using: &random)!)
                case 2: word.append(Character(letter.uppercased()))
                case 3: continue
                case 4: word.append(letter)
                    word.append(["_", "-", ".", " ", "~"].randomElement(using: &random)!)
                default: word.append(letter)
                }
            }
            if Bool.random(using: &random) { word.append("s") }
            if Int.random(in: 0..<4, using: &random) == 0 { word.append("_") }
        }
        return word
    }
}

/// The skeleton of a word written out from its characters, and its secret words found by trying
/// each name at each letter with all its letters and with each of them missing in turn, kept here
/// to check the one-pass match against.
private struct ReferenceSkeleton {
    /// ASCII as it is, a letter without an ASCII form left out, anything else a separator.
    let bytes: [UInt8]
    let leftOutBefore: [Bool]
    let leftOutAtEnd: Bool
    private let letters: [UInt8]
    private let startsWord: [Bool]
    private let gaps: [Bool]

    init(_ word: String) {
        var bytes: [UInt8] = []
        var leftOutBefore: [Bool] = []
        var isLeavingOut = false
        for scalar in word.unicodeScalars {
            if !scalar.isASCII, scalar.properties.isAlphabetic {
                isLeavingOut = true
                continue
            }
            let byte = scalar.isASCII ? UInt8(scalar.value) : UInt8(ascii: "_")
            bytes.append(byte)
            leftOutBefore.append(isLeavingOut)
            if ASCII.isAlphanumeric(byte) { isLeavingOut = false }
        }
        self.bytes = bytes
        self.leftOutBefore = leftOutBefore
        leftOutAtEnd = isLeavingOut
        let name = bytes.map { ASCII.isNameCharacter($0) ? $0 : UInt8(ascii: "_") }
        var letters: [UInt8] = []
        var startsWord: [Bool] = []
        var gaps: [Bool] = []
        for i in name.indices where ASCII.isAlphanumeric(name[i]) {
            letters.append(ASCII.lowercased(name[i]))
            startsWord.append(Self.startsWord(i, in: name))
            gaps.append(leftOutBefore[i])
        }
        gaps.append(isLeavingOut)
        self.letters = letters
        self.startsWord = startsWord
        self.gaps = gaps
    }

    func firstSecret(where accepts: (Range<Int>) -> Bool) -> Range<Int>? {
        for start in letters.indices {
            let first = SecretNames.entries.filter { $0.letters[0] == letters[start] }
            let second = gaps[start] ? SecretNames.entries.filter { $0.letters[1] == letters[start] && $0.letters[0] != letters[start] } : []
            for entry in first + second {
                var ends: [Int] = []
                if start + entry.letters.count <= letters.count, Array(letters[start..<(start + entry.letters.count)]) == entry.letters {
                    ends.append(start + entry.letters.count)
                }
                for missing in entry.letters.indices where start + entry.letters.count - 1 <= letters.count && gaps[start + missing] {
                    var spelled = entry.letters
                    spelled.remove(at: missing)
                    if Array(letters[start..<(start + spelled.count)]) == spelled {
                        ends.append(start + spelled.count)
                        break
                    }
                }
                for spelled in ends {
                    var end = spelled
                    if end < letters.count, letters[end] == UInt8(ascii: "s"), !startsWord[end], endsWord(end + 1) { end += 1 }
                    if holds(entry.placement, start: start, end: end), accepts(start..<end) { return start..<end }
                }
            }
        }
        return nil
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
