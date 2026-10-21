/// The separators of `key=value` and `key: value` in free text.
extension FreeTextScanner {
    /// `=` and `:`, apart from a `:` that is part of a number (see ``isInNumber(colon:)``).
    func isSeparator(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        if byte == UInt8(ascii: "=") { return true }
        guard byte == UInt8(ascii: ":") else { return false }
        return !isInNumber(colon: i)
    }

    /// Whether the `:` at byte `i` is part of a time, a date and time, an address and its port or
    /// a line and column (`12:30:45`, `2026-10-19T12:30:45Z`, `10.0.0.1:8080`, `42:10`): both
    /// sides have the whole shape of a number, so no key and value can be read in it.
    ///
    /// The word before it is a number (see ``numberStart(beforeColon:)``). What follows it is
    /// one to four digits — five after an IPv4 address, a port — then, but not after an address,
    /// more such groups after `:`, a fraction of up to nine digits after `.`, and `Z` or an offset
    /// (`+03:00`, `-0500`), and then the word ends (see ``endsNumber(at:)``). Anything else makes
    /// the `:` a separator: a letter (`12:3hunter2`, `7:9abc`, `1.2.3.4:5abc`), five or more
    /// digits in a row after it (`1:482913`), and a word that goes on past
    /// ``longestNumber`` bytes. A key that ends in digits (`user1:2345`) is a key too.
    func isInNumber(colon i: Int) -> Bool {
        guard i > 0, i + 1 < text.count, text.isDigit(i - 1), text.isDigit(i + 1) else { return false }
        guard let start = numberStart(beforeColon: i) else { return false }
        let isAddress = isIPv4Address(start..<i)
        guard var k = digitsEnd(from: i + 1, most: isAddress ? 5 : 4) else { return false }
        if isAddress { return endsNumber(at: k) }
        let limit = min(text.count, i + 1 + Self.longestNumber)
        while k < limit, text.bytes[k] == UInt8(ascii: ":"), let end = digitsEnd(from: k + 1, most: 4) { k = end }
        if k < limit, text.bytes[k] == UInt8(ascii: "."), let end = digitsEnd(from: k + 1, most: 9) { k = end }
        if k < limit { k = zoneEnd(from: k) }
        return k <= limit && endsNumber(at: k)
    }

    /// Where the number that ends right before the `:` at byte `i` starts, or nil when the word
    /// there is not a number. The number has one or two digits after its last `.`, `-` or `T`
    /// (three after a `.`, as in an address), holds no letter other than the `T` between a date
    /// and a time, and does not follow a letter, a digit or `_`.
    private func numberStart(beforeColon i: Int) -> Int? {
        var k = i
        while k > 0, text.isDigit(k - 1), i - k <= 3 { k -= 1 }
        let digits = i - k
        guard digits <= 2 || (digits == 3 && k > 0 && text.bytes[k - 1] == UInt8(ascii: ".")) else { return nil }
        let wordLimit = max(0, i - Self.longestNumber)
        while k > wordLimit {
            let previous = text.bytes[k - 1]
            if text.isDigit(k - 1) || Self.numberMarks.contains(previous) {
                k -= 1
            } else if previous == UInt8(ascii: "T"), k > 1, text.isDigit(k - 2), text.isDigit(k) {
                k -= 1
            } else {
                break
            }
        }
        guard k > 0 else { return 0 }
        // A number longer than ``longestNumber`` is read as a key: the text is cut.
        guard k > wordLimit, !text.isAnyAlphanumeric(k - 1), text.bytes[k - 1] != UInt8(ascii: "_") else { return nil }
        return k
    }

    /// Whether the bytes `range` are four groups of one to three digits joined by `.`.
    private func isIPv4Address(_ range: Range<Int>) -> Bool {
        var groups = 0
        var k = range.lowerBound
        while k < range.upperBound {
            guard let end = digitsEnd(from: k, most: 3), end <= range.upperBound else { return false }
            groups += 1
            guard end < range.upperBound else { break }
            guard text.bytes[end] == UInt8(ascii: ".") else { return false }
            k = end + 1
        }
        return groups == 4
    }

    /// The byte after a run of one to `most` digits from `k`; nil when there is none, or a longer
    /// one.
    private func digitsEnd(from k: Int, most: Int) -> Int? {
        var end = k
        while end < text.count, text.isDigit(end) {
            end += 1
            if end - k > most { return nil }
        }
        return end > k ? end : nil
    }

    /// The byte after `Z`, or after an offset at `k`: `+` or `-` and two digits, then optionally
    /// two more, after a `:` or not (`+03`, `+03:00`, `-0500`); `k` when neither is there.
    private func zoneEnd(from k: Int) -> Int {
        let byte = text.bytes[k]
        if byte == UInt8(ascii: "Z") { return k + 1 }
        guard byte == UInt8(ascii: "+") || byte == UInt8(ascii: "-") else { return k }
        let hours = digitsEnd(from: k + 1, most: 4)
        if hours == k + 5 { return k + 5 }
        guard hours == k + 3 else { return k }
        guard k + 3 < text.count, text.bytes[k + 3] == UInt8(ascii: ":"), digitsEnd(from: k + 4, most: 2) == k + 6 else { return k + 3 }
        return k + 6
    }

    /// Whether a number ends right before byte `k`: the text ends, or white space, a line break
    /// or punctuation that closes or follows a number comes next (`(12:30)`, `12:30,`), or a `.`
    /// or `:` that ends a sentence or a label (`at 12:30.`, `line 42:10: error`).
    private func endsNumber(at k: Int) -> Bool {
        guard k < text.count else { return true }
        if isBlank(k) || Self.numberEnds.contains(text.bytes[k]) { return true }
        guard text.bytes[k] == UInt8(ascii: ".") || text.bytes[k] == UInt8(ascii: ":") else { return false }
        return k + 1 == text.count || isBlank(k + 1) || Self.numberEnds.contains(text.bytes[k + 1])
    }

    private func isBlank(_ k: Int) -> Bool { text.isSpace(k) || text.isLineTerminator(k) }

    /// The longest number, date and time that a `:` is read in, in bytes, on each side.
    static let longestNumber = 64

    private static let numberMarks = ByteSet(".-")
    /// Punctuation after which a number has ended.
    private static let numberEnds = ByteSet(",;)]}>\"'`|!?&")
}
