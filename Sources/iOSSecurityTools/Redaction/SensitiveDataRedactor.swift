import Foundation

/// Finds card numbers, email addresses, tokens and password fields in free text and hides them,
/// for log messages, crash reports and analytics events.
///
/// ```swift
/// let redactor = SensitiveDataRedactor()
/// redactor.redact(#"POST /login {"user":"alice@example.com","password":"hunter2"}"#)
/// // POST /login {"user":"a•••@example.com","password":"[redacted]"}
/// ```
///
/// What it recognizes:
///
/// - **Card numbers**: 13 to 19 digits that pass the Luhn check, optionally grouped with spaces
///   or hyphens. Shown as `•••• 4242`.
/// - **Email addresses**: shown with ``Mask/email(_:)``.
/// - **JSON Web Tokens**: `eyJ…​.…​.…` — replaced completely.
/// - **Bearer tokens**: the token after `Bearer `.
/// - **Secret fields**: the value after `password`, `token`, `secret`, `api_key`, `authorization`
///   and similar names followed by `:` or `=`, in JSON, query strings, headers and `key: value`
///   text, including `camelCase` and `snake_case` forms such as `accessToken` or `client_secret`.
///
/// Text written to get past a filter is normalized before matching: zero-width and other
/// invisible characters, combining marks, full-width letters (`ｐａｓｓｗｏｒｄ`) and digits from
/// other scripts do not hide a value. The scan is linear in the length of the text and does not
/// use regular expressions, so no input makes it slow.
///
/// Redaction is a safety net for mistakes, not a reason to log secrets: it cannot recognize a
/// password that is not labelled as one.
public struct SensitiveDataRedactor: Sendable {
    /// The kinds of data to look for.
    public struct Kinds: OptionSet, Sendable, Hashable {
        public let rawValue: Int
        public init(rawValue: Int) { self.rawValue = rawValue }

        /// Payment card numbers that pass the Luhn check.
        public static let cardNumbers = Kinds(rawValue: 1 << 0)
        /// Email addresses.
        public static let emailAddresses = Kinds(rawValue: 1 << 1)
        /// JSON Web Tokens.
        public static let jsonWebTokens = Kinds(rawValue: 1 << 2)
        /// Tokens after the word `Bearer`.
        public static let bearerTokens = Kinds(rawValue: 1 << 3)
        /// Values of fields named like a secret (`password`, `token`, `api_key`, ...).
        public static let secretFields = Kinds(rawValue: 1 << 4)
        /// Everything above.
        public static let all: Kinds = [.cardNumbers, .emailAddresses, .jsonWebTokens, .bearerTokens, .secretFields]
    }

    /// A piece of sensitive data found in a text.
    public struct Match: Sendable, Hashable {
        /// What was found; one of the ``Kinds`` constants.
        public let kind: Kinds
        /// Where it is in the text.
        public let range: Range<String.Index>
    }

    /// The text that replaces tokens and secret values.
    public static let replacement = "[redacted]"

    /// The field names whose values ``Kinds/secretFields`` hides, longest first.
    static let secretFieldNames: [[UInt8]] = [
        "authorization", "client_secret", "refresh_token", "access_token", "private_key",
        "password", "id_token", "api-key", "api_key", "apikey", "passwd", "secret", "token", "pwd",
    ].map { Array($0.utf8) }

    /// The kinds this redactor looks for.
    public let kinds: Kinds

    /// Creates a redactor.
    ///
    /// - Parameter kinds: The kinds of data to look for; all of them by default.
    public init(kinds: Kinds = .all) {
        self.kinds = kinds
    }

    /// Returns the text with every match replaced.
    public func redact(_ text: String) -> String {
        let scalars = Array(text.unicodeScalars)
        let spans = findSpans(in: scalars)
        guard !spans.isEmpty else { return text }
        var output = String.UnicodeScalarView()
        var position = 0
        for span in spans {
            output.append(contentsOf: scalars[position..<span.start])
            output.append(contentsOf: span.replacement.unicodeScalars)
            position = span.end
        }
        output.append(contentsOf: scalars[position...])
        return String(output)
    }

    /// Returns the sensitive data found in a text, in order, without overlaps.
    public func matches(in text: String) -> [Match] {
        let scalars = Array(text.unicodeScalars)
        let spans = findSpans(in: scalars)
        var indices: [String.Index] = []
        indices.reserveCapacity(scalars.count + 1)
        var index = text.unicodeScalars.startIndex
        while index < text.unicodeScalars.endIndex {
            indices.append(index)
            index = text.unicodeScalars.index(after: index)
        }
        indices.append(text.unicodeScalars.endIndex)
        return spans.map { Match(kind: $0.kind, range: indices[$0.start]..<indices[$0.end]) }
    }

    // MARK: - Scanning

    /// A replacement, in offsets of the original scalars.
    struct Span {
        var start: Int
        var end: Int
        var kind: Kinds
        var replacement: String
    }

    private func findSpans(in scalars: [Unicode.Scalar]) -> [Span] {
        let text = NormalizedText(scalars)
        var found: [Span] = []
        if kinds.contains(.secretFields) { found += text.secretFieldSpans() }
        if kinds.contains(.bearerTokens) { found += text.bearerSpans() }
        if kinds.contains(.jsonWebTokens) { found += text.jsonWebTokenSpans() }
        if kinds.contains(.emailAddresses) { found += text.emailSpans() }
        if kinds.contains(.cardNumbers) { found += text.cardSpans() }

        found.sort { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var result: [Span] = []
        for span in found where span.start >= (result.last?.end ?? 0) {
            result.append(span)
        }
        return result
    }
}

/// The text the detectors read: invisible scalars removed, full-width ASCII and decimal digits of
/// every script mapped to ASCII, with the offset of each kept scalar in the original.
private struct NormalizedText {
    let bytes: [UInt8]
    let offsets: [Int]
    let isUppercase: [Bool]
    let originalCount: Int

    init(_ scalars: [Unicode.Scalar]) {
        var bytes: [UInt8] = []
        var offsets: [Int] = []
        var isUppercase: [Bool] = []
        bytes.reserveCapacity(scalars.count)
        offsets.reserveCapacity(scalars.count)
        isUppercase.reserveCapacity(scalars.count)
        for (offset, scalar) in scalars.enumerated() where !ScalarClass.isInvisible(scalar) {
            let byte = Self.ascii(scalar)
            bytes.append(byte)
            offsets.append(offset)
            isUppercase.append((UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte))
        }
        self.bytes = bytes
        self.offsets = offsets
        self.isUppercase = isUppercase
        self.originalCount = scalars.count
    }

    /// Byte used for matching: ASCII as is, full-width forms and other digits as ASCII, spaces as
    /// a space, anything else as 0xFF (never matches).
    private static func ascii(_ scalar: Unicode.Scalar) -> UInt8 {
        let value = scalar.value
        if value < 0x80 { return UInt8(value) }
        if (0xFF01...0xFF5E).contains(value) { return UInt8(value - 0xFEE0) }
        if let digit = ScalarClass.decimalDigit(scalar) { return UInt8(ascii: "0") + digit }
        switch value {
        case 0x00A0, 0x2007, 0x2009, 0x202F, 0x3000: return UInt8(ascii: " ")
        default: return 0xFF
        }
    }

    var count: Int { bytes.count }

    func span(_ range: Range<Int>, _ kind: SensitiveDataRedactor.Kinds, _ replacement: String) -> SensitiveDataRedactor.Span {
        SensitiveDataRedactor.Span(start: offsets[range.lowerBound], end: offsets[range.upperBound - 1] + 1, kind: kind, replacement: replacement)
    }

    func string(_ range: Range<Int>) -> String {
        String(decoding: bytes[range], as: UTF8.self)
    }

    // MARK: Character classes

    func isDigit(_ i: Int) -> Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[i]) }

    func isLetter(_ i: Int) -> Bool {
        let byte = bytes[i] | 0x20
        return (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
    }

    func isAlphanumeric(_ i: Int) -> Bool { isDigit(i) || isLetter(i) }

    func lowercased(_ i: Int) -> UInt8 { isLetter(i) ? bytes[i] | 0x20 : bytes[i] }

    func isBase64URL(_ i: Int) -> Bool { isAlphanumeric(i) || bytes[i] == UInt8(ascii: "-") || bytes[i] == UInt8(ascii: "_") }

    func isTokenCharacter(_ i: Int) -> Bool {
        isAlphanumeric(i) || [UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"), UInt8(ascii: "+"), UInt8(ascii: "/"), UInt8(ascii: "=")].contains(bytes[i])
    }

    func isSpace(_ i: Int) -> Bool { bytes[i] == UInt8(ascii: " ") || bytes[i] == UInt8(ascii: "\t") }

    /// Whether a word starts at `i`: after a non-alphanumeric character, or at a lowercase to
    /// uppercase change (`accessToken`).
    func isWordStart(_ i: Int) -> Bool {
        guard i > 0 else { return true }
        if !isAlphanumeric(i - 1) { return true }
        return isUppercase[i] && isLetter(i - 1) && !isUppercase[i - 1]
    }

    func isWordEnd(_ i: Int) -> Bool {
        guard i < count else { return true }
        return !isAlphanumeric(i) && bytes[i] != UInt8(ascii: "_") && bytes[i] != UInt8(ascii: "-")
    }

    func matches(_ word: [UInt8], at i: Int) -> Bool {
        guard i + word.count <= count else { return false }
        for (k, byte) in word.enumerated() where lowercased(i + k) != byte {
            return false
        }
        return true
    }

    // MARK: Card numbers

    func cardSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i < count {
            guard isDigit(i), i == 0 || !isAlphanumeric(i - 1) else {
                i += 1
                continue
            }
            // Digit groups separated by up to three spaces or hyphens.
            var groups: [Range<Int>] = []
            var groupStart = i
            var j = i
            while j < count {
                if isDigit(j) {
                    j += 1
                    continue
                }
                var separatorEnd = j
                while separatorEnd < count, separatorEnd - j < 3, bytes[separatorEnd] == UInt8(ascii: " ") || bytes[separatorEnd] == UInt8(ascii: "-") {
                    separatorEnd += 1
                }
                guard separatorEnd > j, separatorEnd < count, isDigit(separatorEnd) else { break }
                groups.append(groupStart..<j)
                groupStart = separatorEnd
                j = separatorEnd
            }
            groups.append(groupStart..<j)
            if j < count, isLetter(j) {
                // Digits that run into letters are an identifier, not a card number.
                groups.removeLast()
            }
            spans += cardCandidates(in: groups)
            i = max(j, i + 1)
        }
        return spans
    }

    /// The longest run of consecutive groups starting at each group that holds 13 to 19 digits and
    /// passes the Luhn check.
    private func cardCandidates(in groups: [Range<Int>]) -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var first = 0
        while first < groups.count {
            var digits: [UInt8] = []
            var best: Int?
            var last = first
            while last < groups.count {
                digits += groups[last].map { bytes[$0] - UInt8(ascii: "0") }
                if digits.count > 19 { break }
                if digits.count >= 13, Self.passesLuhn(digits) { best = last }
                last += 1
            }
            if let best {
                let range = groups[first].lowerBound..<groups[best].upperBound
                spans.append(span(range, .cardNumbers, Mask.cardNumber(string(range))))
                first = best + 1
            } else {
                first += 1
            }
        }
        return spans
    }

    static func passesLuhn(_ digits: [UInt8]) -> Bool {
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

    // MARK: Email addresses

    func emailSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        for at in 0..<count where bytes[at] == UInt8(ascii: "@") {
            var start = at
            while start > 0, isLocalPart(start - 1) { start -= 1 }
            while start < at, bytes[start] == UInt8(ascii: ".") { start += 1 }
            var end = at + 1
            while end < count, isAlphanumeric(end) || bytes[end] == UInt8(ascii: ".") || bytes[end] == UInt8(ascii: "-") { end += 1 }
            while end > at + 1, bytes[end - 1] == UInt8(ascii: ".") || bytes[end - 1] == UInt8(ascii: "-") { end -= 1 }
            guard start < at, end > at + 1, isDomain(at + 1..<end) else { continue }
            spans.append(span(start..<end, .emailAddresses, Mask.email(string(start..<end))))
        }
        return spans
    }

    private func isLocalPart(_ i: Int) -> Bool {
        isAlphanumeric(i) || [UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "%"), UInt8(ascii: "+"), UInt8(ascii: "-")].contains(bytes[i])
    }

    private func isDomain(_ range: Range<Int>) -> Bool {
        guard let lastDot = range.last(where: { bytes[$0] == UInt8(ascii: ".") }), lastDot > range.lowerBound else { return false }
        let topLevel = (lastDot + 1)..<range.upperBound
        return topLevel.count >= 2 && topLevel.allSatisfy(isLetter)
    }

    // MARK: JSON Web Tokens

    func jsonWebTokenSpans() -> [SensitiveDataRedactor.Span] {
        let prefix = Array("eyJ".utf8)
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i + 3 <= count {
            guard bytes[i] == prefix[0], bytes[i + 1] == prefix[1], bytes[i + 2] == prefix[2], i == 0 || !isBase64URL(i - 1) else {
                i += 1
                continue
            }
            var j = i
            var segments = 0
            var segmentLengths: [Int] = []
            while true {
                let segmentStart = j
                while j < count, isBase64URL(j) { j += 1 }
                segmentLengths.append(j - segmentStart)
                segments += 1
                guard segments < 5, j < count, bytes[j] == UInt8(ascii: ".") else { break }
                // The signature (third segment) is empty in unsecured tokens ("alg": "none").
                let nextIsSegment = j + 1 < count && isBase64URL(j + 1)
                guard nextIsSegment || segments == 2 else { break }
                j += 1
            }
            if segments >= 3, segmentLengths[0] >= 4, segmentLengths[1] >= 4 {
                spans.append(span(i..<j, .jsonWebTokens, SensitiveDataRedactor.replacement))
                i = j
            } else {
                i += max(segmentLengths[0], 1)
            }
        }
        return spans
    }

    // MARK: Bearer tokens

    func bearerSpans() -> [SensitiveDataRedactor.Span] {
        let word = Array("bearer".utf8)
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i < count {
            guard matches(word, at: i), isWordStart(i), i + word.count < count, isSpace(i + word.count) else {
                i += 1
                continue
            }
            var start = i + word.count
            while start < count, isSpace(start) { start += 1 }
            var end = start
            while end < count, isTokenCharacter(end) { end += 1 }
            if end - start >= 8 {
                spans.append(span(start..<end, .bearerTokens, SensitiveDataRedactor.replacement))
            }
            i = max(end, i + 1)
        }
        return spans
    }

    // MARK: Secret fields

    func secretFieldSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i < count {
            guard isLetter(i), isWordStart(i),
                  let name = SensitiveDataRedactor.secretFieldNames.first(where: { matches($0, at: i) && isWordEnd(i + $0.count) }),
                  let value = valueRange(after: i + name.count)
            else {
                i += 1
                continue
            }
            spans.append(span(value, .secretFields, SensitiveDataRedactor.replacement))
            i = value.upperBound
        }
        return spans
    }

    /// The value after a field name: `name: value`, `name=value`, `"name": "value"`.
    private func valueRange(after nameEnd: Int) -> Range<Int>? {
        var j = nameEnd
        if j < count, bytes[j] == UInt8(ascii: "\"") || bytes[j] == UInt8(ascii: "'") { j += 1 }
        while j < count, isSpace(j) { j += 1 }
        guard j < count, bytes[j] == UInt8(ascii: ":") || bytes[j] == UInt8(ascii: "=") else { return nil }
        j += 1
        if j < count, bytes[j] == UInt8(ascii: ">") { j += 1 }
        while j < count, isSpace(j) { j += 1 }
        guard j < count else { return nil }

        if bytes[j] == UInt8(ascii: "\"") || bytes[j] == UInt8(ascii: "'") {
            let quote = bytes[j]
            let start = j + 1
            var end = start
            while end < count, bytes[end] != quote, bytes[end] != UInt8(ascii: "\n") {
                end += bytes[end] == UInt8(ascii: "\\") ? 2 : 1
            }
            end = min(end, count)
            return end > start ? start..<end : nil
        }

        let start = j
        var end = start
        while end < count, !isValueTerminator(end) { end += 1 }
        guard end > start else { return nil }
        // "Authorization: Bearer <token>": the scheme is not the secret, the token after it is.
        let scheme = string(start..<end).lowercased()
        if ["bearer", "basic", "digest", "token"].contains(scheme) {
            var tokenStart = end
            while tokenStart < count, isSpace(tokenStart) { tokenStart += 1 }
            var tokenEnd = tokenStart
            while tokenEnd < count, !isValueTerminator(tokenEnd) { tokenEnd += 1 }
            if tokenEnd > tokenStart { return start..<tokenEnd }
        }
        return start..<end
    }

    private func isValueTerminator(_ i: Int) -> Bool {
        isSpace(i) || [
            UInt8(ascii: "\n"), UInt8(ascii: "\r"), UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "&"),
            UInt8(ascii: "}"), UInt8(ascii: "]"), UInt8(ascii: ")"), UInt8(ascii: "\""), UInt8(ascii: "'"),
            UInt8(ascii: "<"), UInt8(ascii: ">"),
        ].contains(bytes[i])
    }
}
