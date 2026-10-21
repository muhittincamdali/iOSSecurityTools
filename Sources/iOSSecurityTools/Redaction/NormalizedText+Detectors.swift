import Foundation

/// Where a value detector puts what it finds. The detectors run twice: once into a sink that only
/// counts, then into one that keeps the findings in an array of exactly that capacity. An array
/// that grows while it is filled holds its old and its new storage at once, and a megabyte of
/// short findings (`1:2@`, `a@b.cd`) took most of 16 MB that way; the replacement of a finding,
/// such as the mask of an address, is made only when it is kept.
struct SpanSink {
    private(set) var spans: [SensitiveDataRedactor.Span] = []
    private(set) var count = 0
    private let keeps: Bool

    /// A sink that counts what it is given.
    init() {
        keeps = false
    }

    /// A sink that keeps what it is given, in an array of `capacity`.
    init(capacity: Int) {
        keeps = true
        spans.reserveCapacity(capacity)
    }

    mutating func add(_ span: @autoclosure () -> SensitiveDataRedactor.Span) {
        count += 1
        if keeps { spans.append(span()) }
    }
}

/// The value detectors. Each takes `startLimit`, the byte where free text is cut (``count`` when
/// it is not): no finding starts at or after it, since the cut hides what is there, and the text
/// after it is read only to complete a finding that starts before it. A megabyte of addresses
/// after a character that cuts the text at its start finds nothing and takes no memory for them.
extension NormalizedText {
    // MARK: Card numbers

    /// The most bytes a card number spans: 19 digits in groups of one or more, with up to three
    /// spaces, tabs or dashes between them.
    static let longestCard = 19 + 18 * 3

    func cardSpans(startLimit: Int = .max, into spans: inout SpanSink) {
                // No card number that starts before the limit runs past this byte.
        let chainLimit = startLimit >= count ? count : min(count, startLimit + Self.longestCard)
        var i = 0
        while i < min(count, startLimit) {
            guard isDigit(i), i == 0 || !gluesToWord(i - 1) else {
                i += 1
                continue
            }
            // Digit groups separated by up to three spaces, tabs or dashes, read through a window
            // of the groups a card number can still span: a megabyte of `4242 4242 …` is one chain
            // of groups, which an array of them all held in memory.
            var window = CardWindow()
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
                guard separatorEnd > j, separatorEnd < chainLimit, isDigit(separatorEnd) else { break }
                window.append(groupStart..<j, into: &spans, in: self)
                groupStart = separatorEnd
                j = separatorEnd
            }
            // Digits that run into letters are an identifier, not a card number.
            let runsIntoLetters = j < count && isLetter(j) && gluesToWord(j)
            window.finish(last: runsIntoLetters ? nil : groupStart..<j, into: &spans, in: self)
            i = max(j, i + 1)
        }
    }

    private func isCardSeparator(_ i: Int) -> Bool {
        bytes[i] == UInt8(ascii: " ") || bytes[i] == UInt8(ascii: "-") || bytes[i] == UInt8(ascii: "\t")
    }

    /// The digit groups of a chain that a card number may still start in. From each group on, the
    /// longest run of consecutive groups that holds 13 to 19 digits and passes the Luhn check is a
    /// card number, and the next run starts after it. A run is read once the groups after its start
    /// hold more than 19 digits without the newest group, which may still turn out to run into
    /// letters, so the window holds the groups of 19 digits at most and a few more.
    private struct CardWindow {
        private var groups: [Range<Int>] = []
        private var first = 0

        mutating func append(_ group: Range<Int>, into spans: inout SpanSink, in text: NormalizedText) {
            groups.append(group)
            while first < groups.count, digitCount(from: first, to: groups.count - 1) > 19 {
                read(into: &spans, in: text)
            }
            if first > 64 {
                groups.removeFirst(first)
                first = 0
            }
        }

        mutating func finish(last: Range<Int>?, into spans: inout SpanSink, in text: NormalizedText) {
            if let last { groups.append(last) }
            while first < groups.count { read(into: &spans, in: text) }
        }

        private func digitCount(from start: Int, to end: Int) -> Int {
            var digits = 0
            var k = start
            while k < end, digits <= 19 {
                digits += groups[k].count
                k += 1
            }
            return digits
        }

        /// The card number that starts in group `first`, if any, and the group the next one may
        /// start in. The Luhn sum of every run of groups from `first` is kept as it grows: the
        /// digits at even and at odd places from the start, each as written and doubled, so that
        /// either can be the last digit.
        private mutating func read(into spans: inout SpanSink, in text: NormalizedText) {
            var count = 0
            var even = (plain: 0, doubled: 0)
            var odd = (plain: 0, doubled: 0)
            var best: Int?
            var last = first
            groups: while last < groups.count {
                for k in groups[last] {
                    let digit = Int(text.bytes[k] - UInt8(ascii: "0"))
                    let doubled = digit < 5 ? digit * 2 : digit * 2 - 9
                    if count % 2 == 0 {
                        even.plain += digit
                        even.doubled += doubled
                    } else {
                        odd.plain += digit
                        odd.doubled += doubled
                    }
                    count += 1
                    if count > 19 { break groups }
                }
                // The last digit is never doubled, the one before it is, and so on.
                let sum = (count - 1) % 2 == 0 ? even.plain + odd.doubled : even.doubled + odd.plain
                if count >= 13, sum % 10 == 0 { best = last }
                last += 1
            }
            guard let best else {
                first += 1
                return
            }
            let range = groups[first].lowerBound..<groups[best].upperBound
            spans.add(text.span(range, .cardNumbers, Mask.cardNumber(text.string(range))))
            first = best + 1
        }
    }

    // MARK: Email addresses

    /// An address: a name of letters, marks and digits of any script and `.`, `_`, `%`, `+` and
    /// `-` (`ayşe.yılmaz`, `bjørn.dæhlie`, `张伟`), `@`, and a domain of such letters and digits,
    /// `.` and `-` that ends in a top-level domain of two or more letters (`example.com`,
    /// `例子.中国`). The whole address is one finding, shown with ``Mask/email(_:)``.
    func emailSpans(startLimit: Int = .max, into spans: inout SpanSink) {
                // An address whose `@` comes after the limit starts before it only when the name between
        // them runs over it.
        var reach = min(count, startLimit)
        while reach < count, isLocalPart(reach) { reach += 1 }
        for at in 0..<min(count, reach + 1) where bytes[at] == UInt8(ascii: "@") {
            var start = at
            while start > 0, isLocalPart(start - 1) { start -= 1 }
            while start < at, bytes[start] == UInt8(ascii: ".") { start += 1 }
            var end = at + 1
            while end < count, isAnyAlphanumeric(end) || bytes[end] == UInt8(ascii: ".") || bytes[end] == UInt8(ascii: "-") { end += 1 }
            while end > at + 1, bytes[end - 1] == UInt8(ascii: ".") || bytes[end - 1] == UInt8(ascii: "-") { end -= 1 }
            guard start < at, end > at + 1, isDomain(at + 1..<end) else { continue }
            // After a `:` the name may be the password of `user:password@host`: none of it is shown.
            let followsColon = start > 0 && bytes[start - 1] == UInt8(ascii: ":")
            spans.add(span(start..<end, .emailAddresses, followsColon ? Mask.email("x@" + shown((at + 1)..<end)) : Mask.email(shown(start..<end))))
        }
    }

    private func isLocalPart(_ i: Int) -> Bool {
        isAnyAlphanumeric(i) || [UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "%"), UInt8(ascii: "+"), UInt8(ascii: "-")].contains(bytes[i])
    }

    private func isDomain(_ range: Range<Int>) -> Bool {
        guard let lastDot = range.last(where: { bytes[$0] == UInt8(ascii: ".") }), lastDot > range.lowerBound else { return false }
        let topLevel = (lastDot + 1)..<range.upperBound
        return topLevel.count >= 2 && topLevel.allSatisfy(isAnyLetter)
    }

    // MARK: JSON Web Tokens

    func jsonWebTokenSpans(startLimit: Int = .max, into spans: inout SpanSink) {
        let prefix = Array("eyJ".utf8)
                var i = 0
        while i + 3 <= count, i < startLimit {
            // A token glued to a word by `_` or `-` (`id_eyJ…`) is still a token.
            guard bytes[i] == prefix[0], bytes[i + 1] == prefix[1], bytes[i + 2] == prefix[2], i == 0 || !gluesToWord(i - 1) else {
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
            // A header and a payload that are both JSON (`eyJ….eyJ…`) are a token whose last dot was
            // cut off, as a URL in a sentence loses it to the full stop after it.
            let payload = i + segmentLengths[0] + 1
            let isCutToken = segments == 2 && segmentLengths[1] >= 4 && bytes[payload..<(payload + 3)].elementsEqual(prefix)
            if segments >= 3 || isCutToken, segmentLengths[0] >= 4, segmentLengths[1] >= 4 {
                spans.add(span(i..<j, .jsonWebTokens, SensitiveDataRedactor.replacement))
                i = j
            } else {
                i += max(segmentLengths[0], 1)
            }
        }
    }

    // MARK: Bearer tokens

    func bearerSpans(startLimit: Int = .max, into spans: inout SpanSink) {
        let word = Array("bearer".utf8)
                var i = 0
        while i < min(count, startLimit) {
            guard matches(word, at: i), isWordStart(i), i + word.count < count, isSpace(i + word.count) else {
                i += 1
                continue
            }
            var start = i + word.count
            while start < count, isSpace(start) { start += 1 }
            var end = start
            while end < count, isTokenCharacter(end) { end += 1 }
            if end - start >= 8 {
                spans.add(span(start..<end, .bearerTokens, SensitiveDataRedactor.replacement))
            }
            i = max(end, i + 1)
        }
    }
}
