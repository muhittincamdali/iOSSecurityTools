extension NormalizedText {
    // MARK: IBANs

    static let ibanLength = 15...34

    /// A country code, two check digits and up to 30 more capital letters or digits, optionally
    /// grouped by single spaces, whose mod-97 remainder is 1. Shown as `•••• 3000`.
    func ibanSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i + 4 <= count {
            guard startsIBAN(at: i), let end = ibanEnd(from: i) else {
                i += 1
                continue
            }
            let compact = bytes[i..<end].filter { $0 != UInt8(ascii: " ") }
            spans.append(span(i..<end, .ibans, Mask.trailing(String(decoding: compact, as: UTF8.self))))
            i = end
        }
        return spans
    }

    private func isIBANCharacter(_ i: Int) -> Bool { isDigit(i) || isUppercase[i] }

    private func startsIBAN(at i: Int) -> Bool {
        (i == 0 || !gluesToWord(i - 1)) && isUppercase[i] && isUppercase[i + 1] && isDigit(i + 2) && isDigit(i + 3)
    }

    /// The end of the longest IBAN that starts at `start` and ends where its group ends.
    private func ibanEnd(from start: Int) -> Int? {
        var characters: [UInt8] = []
        var ends: [Int] = []
        var j = start
        while j < count, characters.count < Self.ibanLength.upperBound {
            if isIBANCharacter(j) {
                characters.append(bytes[j])
                j += 1
                ends.append(j)
            } else if bytes[j] == UInt8(ascii: " "), j + 1 < count, isIBANCharacter(j + 1), !characters.isEmpty {
                j += 1
            } else {
                break
            }
        }
        guard characters.count >= Self.ibanLength.lowerBound else { return nil }
        for length in stride(from: characters.count, through: Self.ibanLength.lowerBound, by: -1) {
            let end = ends[length - 1]
            guard end == count || !gluesToWord(end) else { continue }
            if Self.ibanRemainder(characters[..<length]) == 1 { return end }
        }
        return nil
    }

    /// The first four characters moved to the end, letters read as 10 to 35, modulo 97.
    static func ibanRemainder(_ characters: ArraySlice<UInt8>) -> Int {
        var remainder = 0
        for character in characters.dropFirst(4) + characters.prefix(4) {
            if ASCII.isDigit(character) {
                remainder = (remainder * 10 + Int(character - UInt8(ascii: "0"))) % 97
            } else {
                remainder = (remainder * 100 + Int(character - UInt8(ascii: "A")) + 10) % 97
            }
        }
        return remainder
    }

    // MARK: Long hex and base64 strings

    static let longTokenLength = 32

    /// Runs of 32 or more hexadecimal digits, and runs of 32 or more base64 characters with both
    /// letters and digits. A run of hex digits and hyphens, such as a UUID, is an identifier and a
    /// run with many slashes is a path; both are kept.
    func longTokenSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i < count {
            guard isBase64(i) else {
                i += 1
                continue
            }
            let start = i
            var digits = 0, letters = 0, slashes = 0, hyphens = 0, nonHex = 0
            while i < count, isBase64(i) {
                if isDigit(i) { digits += 1 } else if isLetter(i) { letters += 1 }
                if bytes[i] == UInt8(ascii: "/") { slashes += 1 } else if bytes[i] == UInt8(ascii: "-") { hyphens += 1 }
                if !isHexDigit(i), bytes[i] != UInt8(ascii: "-") { nonHex += 1 }
                i += 1
            }
            let length = i - start
            guard length >= Self.longTokenLength else { continue }
            var end = i
            while end < count, end - i < 2, bytes[end] == UInt8(ascii: "=") { end += 1 }
            let isHex = nonHex == 0 && hyphens == 0
            let isHyphenatedHex = nonHex == 0 && hyphens > 0
            let isBase64Token = digits > 0 && letters > 0 && slashes * 8 < length
            if isHex || (!isHyphenatedHex && isBase64Token) {
                spans.append(span(start..<end, .longTokens, SensitiveDataRedactor.replacement))
            }
        }
        return spans
    }

    private func isBase64(_ i: Int) -> Bool {
        isBase64URL(i) || bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "/")
    }

    private func isHexDigit(_ i: Int) -> Bool {
        isDigit(i) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(bytes[i] | 0x20)
    }

    // MARK: Passwords in URLs

    /// The password in `user:password@host`, as URLs write credentials: the text between the last
    /// `:` and the `@`, after a user name that may be empty (`redis://:password@host`).
    func userInfoPasswordSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var previousAt = -1
        for at in 0..<count where bytes[at] == UInt8(ascii: "@") {
            var start = at
            var colon: Int?
            while start > previousAt + 1, isUserInfoCharacter(start - 1) {
                start -= 1
                if colon == nil, bytes[start] == UInt8(ascii: ":") { colon = start }
            }
            previousAt = at
            guard let colon, colon + 1 < at else { continue }
            spans.append(span((colon + 1)..<at, .secretFields, SensitiveDataRedactor.replacement))
        }
        return spans
    }

    /// Everything but whitespace, `/`, `@`, quotes, brackets and `,` `;`.
    private func isUserInfoCharacter(_ i: Int) -> Bool {
        let byte = bytes[i]
        guard byte > 0x20, byte < 0x7F else { return false }
        return !"/@\"'<>()[]{},;`".utf8.contains(byte)
    }
}
