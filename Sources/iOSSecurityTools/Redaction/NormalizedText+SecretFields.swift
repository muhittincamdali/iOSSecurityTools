import Foundation

extension NormalizedText {
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
