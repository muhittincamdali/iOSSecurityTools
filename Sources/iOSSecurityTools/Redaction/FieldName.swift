/// The rule for keys: JSON member names, form and multipart field names, query parameter names
/// and the keys of `key=value` pairs in free text.
///
/// Only a plain-ASCII key is compared with the secret names: one made of `A`–`Z`, `a`–`z`, `0`–`9`
/// and the separators `_`, `-`, `.` and space, with at least one letter or digit and at most
/// ``PlainName/maximumKeyLength`` characters. The separators are folded away and the letters
/// lowercased, so `pass_word`, `PASS-WORD` and `pass.word` read as `password`. Every other key is
/// treated as secret whatever it says: a letter outside ASCII (also one that Unicode normalization
/// would turn into ASCII), a mark, a format character, mixed scripts, an escape or any other
/// punctuation can make a key look like something it is not, and no list of look-alikes is ever
/// complete.
enum FieldName {
    /// Whether the value under a key of structured input (JSON, form, multipart) is hidden: the key
    /// is not plain ASCII, or it names a secret.
    static func hidesValue(_ name: some Collection<Unicode.Scalar>) -> Bool {
        guard let plain = PlainName(name) else { return true }
        return plain.namesSecret
    }

    /// The key folded for an allowlist: lowercase letters and digits without separators; nil when
    /// the key is not plain ASCII or names a secret, so it can never be allowed.
    static func allowableFold(_ name: some Collection<Unicode.Scalar>) -> String? {
        guard let plain = PlainName(name), !plain.namesSecret else { return nil }
        return plain.folded
    }
}

/// A key made only of ASCII letters, digits, `_`, `-`, `.` and spaces.
///
/// The key is read as its letters and digits, lowercased, and where its words start: after a
/// separator, between letters and digits, at a camel-case hump (`accessToken`) and at the last
/// capital of an acronym (`AWSSecret`). Comparing it takes time linear in its length.
struct PlainName {
    /// Longer keys are not plain: their value is hidden without reading them.
    static let maximumKeyLength = 256

    /// The letters and digits, lowercased; ``wildcard`` for a letter read as any letter.
    let letters: [UInt8]
    /// Whether a word starts at each letter.
    private let startsWord: [Bool]

    /// Stands for a letter of free text that has no ASCII form (`ɑ`, `ı`) in a loose reading: it
    /// matches any one letter of a secret word.
    static let wildcard: UInt8 = 0

    /// - Parameter maximumLength: Longer names are not read; nil reads any length.
    init?(_ name: some Collection<Unicode.Scalar>, maximumLength: Int? = maximumKeyLength) {
        var bytes: [UInt8] = []
        for scalar in name {
            guard scalar.isASCII else { return nil }
            bytes.append(UInt8(scalar.value))
        }
        self.init(bytes: bytes, maximumLength: maximumLength)
    }

    init?(bytes: some Collection<UInt8>, maximumLength: Int? = maximumKeyLength) {
        let bytes = Array(bytes)
        if let maximumLength, bytes.count > maximumLength { return nil }
        guard bytes.allSatisfy(ASCII.isNameCharacter) else { return nil }
        self.init(nameBytes: bytes, wildcards: [])
    }

    /// A word of free text read loosely, to find the secret words in it: punctuation between its
    /// letters is read as a separator (`pass~word`, `t*okens`), and the bytes at `wildcards` as
    /// letters that match any letter. Never used for keys, which are compared only when plain.
    init?(looseBytes bytes: [UInt8], wildcards: Set<Int>) {
        var name = bytes
        for i in name.indices where !ASCII.isNameCharacter(name[i]) {
            name[i] = wildcards.contains(i) ? UInt8(ascii: "x") : UInt8(ascii: "_")
        }
        self.init(nameBytes: name, wildcards: wildcards)
    }

    private init?(nameBytes bytes: [UInt8], wildcards: Set<Int>) {
        var letters: [UInt8] = []
        var startsWord: [Bool] = []
        for i in bytes.indices where ASCII.isAlphanumeric(bytes[i]) {
            letters.append(wildcards.contains(i) ? Self.wildcard : ASCII.lowercased(bytes[i]))
            startsWord.append(Self.startsWord(i, in: bytes))
        }
        guard !letters.isEmpty else { return nil }
        self.letters = letters
        self.startsWord = startsWord
    }

    /// The letters and digits as a string, for allowlists.
    var folded: String { String(decoding: letters, as: UTF8.self) }

    /// Whether the name holds a secret word where ``SecretNames/Placement`` requires it:
    /// `password`, `aws_secret_access_key`, `dbPassword`, `apitoken`, `user_pin` or `tokens`, but
    /// not `tokenizer`, `keyboard` or `bypass`. A plural `s` after the secret word counts.
    var namesSecret: Bool { secretEnd != nil }

    /// The number of letters up to the end of the first secret word, its plural `s` included; nil
    /// when the name holds none.
    var secretEnd: Int? { firstSecret { _ in true }?.upperBound }

    /// The letters of the first secret word that `accepts` takes, its plural `s` included. A secret
    /// word may hold one ``wildcard``.
    func firstSecret(where accepts: (Range<Int>) -> Bool) -> Range<Int>? {
        for start in letters.indices {
            let entries = letters[start] == Self.wildcard ? SecretNames.entries : SecretNames.entries(startingWith: letters[start])
            for entry in entries {
                guard let end = matchEnd(of: entry.letters, at: start), holds(entry.placement, start: start, end: end),
                      accepts(start..<end)
                else { continue }
                return start..<end
            }
        }
        return nil
    }

    /// Where `word` ends when it is spelled at `start`, with at most one ``wildcard`` and a plural
    /// `s` after it.
    private func matchEnd(of word: [UInt8], at start: Int) -> Int? {
        var end = start + word.count
        guard end <= letters.count else { return nil }
        var usedWildcard = false
        for (letter, expected) in zip(letters[start..<end], word) where letter != expected {
            guard letter == Self.wildcard, !usedWildcard else { return nil }
            usedWildcard = true
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

    /// Whether a word starts at byte `i`: after a separator, between letters and digits, at a
    /// camel-case hump (`accessToken`) or at the last capital of an acronym (`AWSSecret`).
    private static func startsWord(_ i: Int, in bytes: [UInt8]) -> Bool {
        guard i > 0 else { return true }
        let previous = bytes[i - 1]
        if !ASCII.isAlphanumeric(previous) || ASCII.isDigit(previous) != ASCII.isDigit(bytes[i]) { return true }
        guard ASCII.isUppercase(bytes[i]), ASCII.isLetter(previous) else { return false }
        if !ASCII.isUppercase(previous) { return true }
        return i + 1 < bytes.count && ASCII.isLetter(bytes[i + 1]) && !ASCII.isUppercase(bytes[i + 1])
    }
}

/// ASCII character classes on bytes.
enum ASCII {
    static func isDigit(_ byte: UInt8) -> Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) }
    static func isUppercase(_ byte: UInt8) -> Bool { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) }
    static func isLetter(_ byte: UInt8) -> Bool { (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte | 0x20) }
    static func isAlphanumeric(_ byte: UInt8) -> Bool { isDigit(byte) || isLetter(byte) }
    static func lowercased(_ byte: UInt8) -> UInt8 { isUppercase(byte) ? byte | 0x20 : byte }

    /// The control characters other than tab, line feed, carriage return, vertical tab and form
    /// feed, and DEL.
    static func isHidingControl(_ byte: UInt8) -> Bool { (byte < 0x20 && !(0x09...0x0D).contains(byte)) || byte == 0x7F }

    /// `_`, `-`, `.` and the space: the separators a plain name may hold, folded away when it is
    /// compared.
    static func isNameSeparator(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".") || byte == UInt8(ascii: " ")
    }

    static func isNameCharacter(_ byte: UInt8) -> Bool { isAlphanumeric(byte) || isNameSeparator(byte) }
}
