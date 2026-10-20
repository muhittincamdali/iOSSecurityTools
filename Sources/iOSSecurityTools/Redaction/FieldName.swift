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

/// A key made only of ASCII letters, digits, `_`, `-`, `.` and spaces, or the ASCII skeleton of a
/// word of free text.
///
/// The key is read as its letters and digits, lowercased, and where its words start: after a
/// separator, between letters and digits, at a camel-case hump (`accessToken`) and at the last
/// capital of an acronym (`AWSSecret`). Comparing it with the secret names takes time linear in
/// its length: each letter is tried only with the names that can start there, each in one pass.
struct PlainName {
    /// Longer keys are not plain: their value is hidden without reading them.
    static let maximumKeyLength = 256

    /// The letters and digits, lowercased.
    let letters: [UInt8]
    /// Whether a word starts at each letter.
    private let startsWord: [Bool]
    /// Of a skeleton, whether letters without an ASCII form were left out right before each
    /// letter, and at the end; nil for a key, which has no such letters.
    private let gaps: [Bool]?

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
        self.init(nameBytes: bytes, leftOutBefore: nil, leftOutAtEnd: false)
    }

    /// The ASCII skeleton of a word of free text (see ``LooseReading``): its bytes once the letters
    /// that have no ASCII form are left out, with any other punctuation between its letters read
    /// as a separator (`pass~word`, `t*okens`). `leftOutBefore` says for each byte whether such
    /// letters were left out after the letter before it, and `leftOutAtEnd` whether some were
    /// after the last one. Never used for keys, which are compared only when plain.
    init?(skeleton bytes: [UInt8], leftOutBefore: [Bool], leftOutAtEnd: Bool) {
        var name = bytes
        for i in name.indices where !ASCII.isNameCharacter(name[i]) { name[i] = UInt8(ascii: "_") }
        self.init(nameBytes: name, leftOutBefore: leftOutBefore, leftOutAtEnd: leftOutAtEnd)
    }

    private init?(nameBytes bytes: [UInt8], leftOutBefore: [Bool]?, leftOutAtEnd: Bool) {
        var letters: [UInt8] = []
        var startsWord: [Bool] = []
        var gaps: [Bool] = []
        letters.reserveCapacity(bytes.count)
        startsWord.reserveCapacity(bytes.count)
        for i in bytes.indices where ASCII.isAlphanumeric(bytes[i]) {
            letters.append(ASCII.lowercased(bytes[i]))
            startsWord.append(Self.startsWord(i, in: bytes))
            if let leftOutBefore { gaps.append(leftOutBefore[i]) }
        }
        guard !letters.isEmpty else { return nil }
        self.letters = letters
        self.startsWord = startsWord
        if leftOutBefore != nil, gaps.contains(true) || leftOutAtEnd {
            gaps.append(leftOutAtEnd)
            self.gaps = gaps
        } else {
            self.gaps = nil
        }
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

    /// The letters of the first secret word that `accepts` takes, its plural `s` included.
    ///
    /// A secret word is spelled by the letters as they are, or, in a skeleton, by the letters with
    /// one of its own letters missing where letters were left out (`pɑssword` is `pssword`, which
    /// is `password` without its `a`, and an `ɑ` was left out there). Each start is tried only with
    /// the words that can start there (see ``SecretNames/entries(startingWith:)``): those that
    /// start with its letter, and after a gap those whose second letter it is. Each word is read in
    /// one pass from each end, so both ways of spelling it are known at once and nothing is tried
    /// again.
    func firstSecret(where accepts: (Range<Int>) -> Bool) -> Range<Int>? {
        for start in letters.indices {
            let letter = letters[start]
            if let found = firstSecret(in: SecretNames.entries(startingWith: letter), at: start, where: accepts) { return found }
            guard let gaps, gaps[start] else { continue }
            let afterGap = SecretNames.entries(withSecondLetter: letter).lazy.filter { $0.letters[0] != letter }
            if let found = firstSecret(in: afterGap, at: start, where: accepts) { return found }
        }
        return nil
    }

    private func firstSecret(
        in entries: some Sequence<SecretNames.Entry>, at start: Int, where accepts: (Range<Int>) -> Bool
    ) -> Range<Int>? {
        for entry in entries {
            let (whole, withGap) = spelledEnds(of: entry.letters, at: start)
            if let whole, let found = accepted(entry, from: start, to: whole, where: accepts) { return found }
            if let withGap, let found = accepted(entry, from: start, to: withGap, where: accepts) { return found }
        }
        return nil
    }

    /// The letters of `entry` spelled from `start` to `spelled`, its plural `s` included, when its
    /// placement holds and `accepts` takes them.
    private func accepted(
        _ entry: SecretNames.Entry, from start: Int, to spelled: Int, where accepts: (Range<Int>) -> Bool
    ) -> Range<Int>? {
        let end = withPlural(spelled)
        guard holds(entry.placement, start: start, end: end), accepts(start..<end) else { return nil }
        return start..<end
    }

    /// Where `word` ends when it is spelled from letter `start`: with all its letters, and, in a
    /// skeleton, with one of them missing at a gap. `word` has two letters or more.
    private func spelledEnds(of word: [UInt8], at start: Int) -> (whole: Int?, withGap: Int?) {
        let count = word.count
        var prefix = 0
        while prefix < count, start + prefix < letters.count, letters[start + prefix] == word[prefix] { prefix += 1 }
        let whole = prefix == count ? start + count : nil
        guard let gaps, start + count - 1 <= letters.count else { return (whole, nil) }
        // With letter `j` of the word missing, its letters after `j` are the letters read right
        // before `start + count - 1`: `suffix` counts how many of them match, from the end.
        var suffix = 0
        while suffix < count - 1, letters[start + count - 2 - suffix] == word[count - 1 - suffix] { suffix += 1 }
        let lowest = max(0, count - 1 - suffix)
        let highest = min(prefix, count - 1)
        guard lowest <= highest else { return (whole, nil) }
        for j in lowest...highest where gaps[start + j] { return (whole, start + count - 1) }
        return (whole, nil)
    }

    /// `end`, or the letter after it when a plural `s` ends the word there.
    private func withPlural(_ end: Int) -> Int {
        guard end < letters.count, letters[end] == UInt8(ascii: "s"), !startsWord[end], endsWord(end + 1) else { return end }
        return end + 1
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
