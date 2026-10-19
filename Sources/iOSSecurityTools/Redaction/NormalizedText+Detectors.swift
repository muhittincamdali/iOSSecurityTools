import Foundation

extension NormalizedText {
    // MARK: Card numbers

    func cardSpans() -> [SensitiveDataRedactor.Span] {
        var spans: [SensitiveDataRedactor.Span] = []
        var i = 0
        while i < count {
            guard isDigit(i), i == 0 || !isAlphanumeric(i - 1) else {
                i += 1
                continue
            }
            // Digit groups separated by up to three spaces, tabs or dashes.
            var groups: [Range<Int>] = []
            var groupStart = i
            var j = i
            while j < count {
                if isDigit(j) {
                    j += 1
                    continue
                }
                var separatorEnd = j
                while separatorEnd < count, separatorEnd - j < 3, isCardSeparator(separatorEnd) {
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

    private func isCardSeparator(_ i: Int) -> Bool {
        bytes[i] == UInt8(ascii: " ") || bytes[i] == UInt8(ascii: "-") || bytes[i] == UInt8(ascii: "\t")
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
            // In `user:password@host` the text before `@` is a password, hidden on its own.
            guard start < at, end > at + 1, isDomain(at + 1..<end), start == 0 || bytes[start - 1] != UInt8(ascii: ":") else { continue }
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
            // A token glued to a word by `_` or `-` (`id_eyJ…`) is still a token.
            guard bytes[i] == prefix[0], bytes[i + 1] == prefix[1], bytes[i + 2] == prefix[2], i == 0 || !isAlphanumeric(i - 1) else {
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
}
