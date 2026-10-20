/// The separators of `key=value` and `key: value` in free text.
extension FreeTextScanner {
    /// `=` and `:`, apart from a `:` that is part of a number (see ``isInNumber(colon:)``).
    func isSeparator(_ i: Int) -> Bool {
        let byte = text.bytes[i]
        if byte == UInt8(ascii: "=") { return true }
        guard byte == UInt8(ascii: ":") else { return false }
        return !isInNumber(colon: i)
    }

    /// Whether the `:` at byte `i` is part of a time, a date and time or an address and its port
    /// (`12:30:45`, `2026-10-19T12:30:45Z`, `10.0.0.1:8080`): a digit follows it, and the word
    /// before it is a number. That word has one or two digits after its last `.`, `-` or `T`
    /// (three after a `.`, as in an address), holds no letter other than the `T` between the date
    /// and the time, and does not follow a letter, a digit or `_`. A key that ends in digits
    /// (`user1:2345`, `acct2:…`, `user_id2:…`) is a key, so its `:` is a separator.
    func isInNumber(colon i: Int) -> Bool {
        guard i > 0, i + 1 < text.count, text.isDigit(i - 1), text.isDigit(i + 1) else { return false }
        var k = i
        while k > 0, text.isDigit(k - 1), i - k <= 3 { k -= 1 }
        let digits = i - k
        guard digits <= 2 || (digits == 3 && k > 0 && text.bytes[k - 1] == UInt8(ascii: ".")) else { return false }
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
        guard k > 0 else { return true }
        // A number longer than ``longestNumber`` is read as a key: the text is cut.
        return k > wordLimit && !text.isAnyAlphanumeric(k - 1) && text.bytes[k - 1] != UInt8(ascii: "_")
    }

    /// The longest number, date and time that a `:` is read in, in bytes.
    static let longestNumber = 64

    private static let numberMarks = ByteSet(".-")
}
