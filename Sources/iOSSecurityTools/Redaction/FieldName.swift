/// Decides whether the value of a field is hidden. JSON, form, multipart and free text all use
/// this one rule.
///
/// Only a plain-ASCII name is compared with the secret names: one made of `A`–`Z`, `a`–`z`,
/// `0`–`9`, `_` and `-` with at least one letter or digit. `_` and `-` are folded away when it is
/// compared, so `pass_word` and `PASS-WORD` read as `password`. The value of every other name is
/// hidden whatever the name says: a letter outside ASCII, a combining mark, an invisible format
/// character, a space, a dot, an escape or any other punctuation can make a name look like a
/// secret name that a comparison would miss, and no list of look-alikes is ever complete.
enum FieldName {
    /// Whether the value of a field with this name is hidden.
    static func hidesValue(_ name: some Collection<Unicode.Scalar>) -> Bool {
        guard let plain = PlainName(name) else { return true }
        return plain.namesSecret
    }
}

/// A field name made only of ASCII letters, digits, `_` and `-`.
struct PlainName {
    let bytes: [UInt8]

    init?(_ name: some Collection<Unicode.Scalar>) {
        var bytes: [UInt8] = []
        var hasAlphanumeric = false
        for scalar in name {
            guard scalar.isASCII else { return nil }
            let byte = UInt8(scalar.value)
            if ASCII.isAlphanumeric(byte) {
                hasAlphanumeric = true
            } else if byte != ASCII.underscore, byte != ASCII.hyphen {
                return nil
            }
            bytes.append(byte)
        }
        guard hasAlphanumeric else { return nil }
        self.bytes = bytes
    }

    /// Whether the name holds a secret: `password`, `aws_secret_access_key`, `passwordConfirm`,
    /// `dbPassword` or `apitoken`, but not `passwordHint`, `token_type`, `tokenizer` or `bypass`.
    var namesSecret: Bool {
        let folded = bytes.filter(ASCII.isAlphanumeric).map(ASCII.lowercased)
        if SensitiveDataRedactor.wholeSecretFieldNames.contains(folded) { return true }
        for start in bytes.indices where ASCII.isLetter(bytes[start]) {
            for secret in SensitiveDataRedactor.secretFieldNames {
                guard let end = spelledEnd(of: secret[...], from: start), !isDescribingWord(at: end) else { continue }
                let isWord = startsWord(start) && endsWord(end)
                let endsName = bytes[end...].allSatisfy { !ASCII.isAlphanumeric($0) }
                if isWord
                    || SensitiveDataRedactor.unboundedSecretFieldNames.contains(secret)
                    || (endsName && SensitiveDataRedactor.trailingSecretFieldNames.contains(secret)) {
                    return true
                }
            }
        }
        return false
    }

    /// Whether a secret word starts in the words before the name and ends in the name, as
    /// `pass word=` and `API key:` spell `password` and `apikey` across a space.
    ///
    /// The words are held to the same rule as one name: a secret word that counts anywhere in a
    /// name (`mypa ssword`) or at its end (`myto ken`) needs no word boundary there either.
    /// `preceding` is read only when part of a secret word starts the name.
    func continuesSecret(after preceding: @autoclosure () -> PrecedingWords) -> Bool {
        guard let first = bytes.firstIndex(where: ASCII.isAlphanumeric) else { return false }
        let firstLetter = ASCII.lowercased(bytes[first])
        var words: PrecedingWords?
        for secret in SensitiveDataRedactor.secretFieldNames {
            let isUnbounded = SensitiveDataRedactor.unboundedSecretFieldNames.contains(secret)
            let isTrailing = SensitiveDataRedactor.trailingSecretFieldNames.contains(secret)
            for split in 1..<secret.count where secret[split] == firstLetter {
                guard let end = spelledEnd(of: secret[split...], from: first), !isDescribingWord(at: end) else { continue }
                let endsName = bytes[end...].allSatisfy { !ASCII.isAlphanumeric($0) }
                let isFree = isUnbounded || (isTrailing && endsName)
                guard isFree || endsWord(end) else { continue }
                if words == nil { words = preceding() }
                if words!.endsWith(secret[..<split], fromWordStart: !isFree) { return true }
            }
        }
        return false
    }

    // MARK: Words

    /// Whether a word starts at `i`: after `_` or `-`, between letters and digits, at a
    /// camel-case hump (`accessToken`) or at the last capital of an acronym (`AWSSecret`).
    func startsWord(_ i: Int) -> Bool { Self.startsWord(i, in: bytes) }

    private func endsWord(_ i: Int) -> Bool {
        i == bytes.count || !ASCII.isAlphanumeric(bytes[i]) || startsWord(i)
    }

    static func startsWord(_ i: Int, in bytes: [UInt8]) -> Bool {
        guard i > 0 else { return true }
        guard i < bytes.count, ASCII.isAlphanumeric(bytes[i]) else { return false }
        let previous = bytes[i - 1]
        if !ASCII.isAlphanumeric(previous) || ASCII.isDigit(previous) != ASCII.isDigit(bytes[i]) { return true }
        guard ASCII.isUppercase(bytes[i]), ASCII.isLetter(previous) else { return false }
        if !ASCII.isUppercase(previous) { return true }
        return i + 1 < bytes.count && ASCII.isLetter(bytes[i + 1]) && !ASCII.isUppercase(bytes[i + 1])
    }

    /// Where `word` ends if it is spelled from `start`, ignoring `_` and `-` between its letters.
    private func spelledEnd(of word: ArraySlice<UInt8>, from start: Int) -> Int? {
        var j = start
        for (k, letter) in word.enumerated() {
            if k > 0 { while j < bytes.count, !ASCII.isAlphanumeric(bytes[j]) { j += 1 } }
            guard j < bytes.count, ASCII.lowercased(bytes[j]) == letter else { return nil }
            j += 1
        }
        return j
    }

    /// Whether the word after `wordEnd` only describes the secret: `passwordHint`, `token_type`.
    private func isDescribingWord(at wordEnd: Int) -> Bool {
        var start = wordEnd
        while start < bytes.count, !ASCII.isAlphanumeric(bytes[start]) { start += 1 }
        guard start < bytes.count else { return false }
        var end = start + 1
        while !endsWord(end) { end += 1 }
        return SensitiveDataRedactor.describingWords.contains(bytes[start..<end].map(ASCII.lowercased))
    }
}

/// The letters of the words right before a name in free text, nearest letter first, when only
/// whitespace separates those words from the name.
struct PrecedingWords {
    /// No secret word is longer than this plus one letter, which has to be in the name.
    static let capacity = (SensitiveDataRedactor.secretFieldNames.map(\.count).max() ?? 1) - 1

    private(set) var letters: [UInt8] = []
    private(set) var startsWord: [Bool] = []
    /// Whether a word with characters that cannot be read as plain ASCII comes before the
    /// letters. It could spell anything, so it matches whatever is left of a secret word.
    var endsInUnreadableWord = false

    var isFull: Bool { letters.count >= Self.capacity }

    /// Adds a word of ASCII letters, digits and punctuation, read as separators, in front of the
    /// words added so far.
    mutating func prepend(_ word: [UInt8]) {
        for i in word.indices.reversed() where ASCII.isAlphanumeric(word[i]) && !isFull {
            letters.append(ASCII.lowercased(word[i]))
            startsWord.append(PlainName.startsWord(i, in: word))
        }
    }

    /// Whether the letters spell `head` up to the name, starting at the start of a word when
    /// `fromWordStart`.
    func endsWith(_ head: ArraySlice<UInt8>, fromWordStart: Bool) -> Bool {
        var k = 0
        for letter in head.reversed() {
            guard k < letters.count else { return endsInUnreadableWord }
            guard letters[k] == letter else { return false }
            k += 1
        }
        return !fromWordStart || startsWord[k - 1]
    }
}

/// ASCII character classes on bytes.
enum ASCII {
    static let underscore = UInt8(ascii: "_")
    static let hyphen = UInt8(ascii: "-")

    static func isDigit(_ byte: UInt8) -> Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) }
    static func isUppercase(_ byte: UInt8) -> Bool { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) }
    static func isLetter(_ byte: UInt8) -> Bool { (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte | 0x20) }
    static func isAlphanumeric(_ byte: UInt8) -> Bool { isDigit(byte) || isLetter(byte) }
    static func lowercased(_ byte: UInt8) -> UInt8 { isUppercase(byte) ? byte | 0x20 : byte }
}
