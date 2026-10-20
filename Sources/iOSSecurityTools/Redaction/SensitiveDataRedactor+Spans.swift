/// Replacements: where findings are, how they join, and the text they make.
extension SensitiveDataRedactor {
    /// A replacement, in offsets of the original scalars, and the kinds of what it hides.
    struct Span {
        var start: Int
        var end: Int
        var kind: Kinds
        var replacement: String
    }

    /// The scalars with every span replaced; `spans` are in order and do not overlap.
    static func replacing(_ spans: [Span], in scalars: [Unicode.Scalar]) -> String {
        // Appending to a String.UnicodeScalarView piece by piece copies what is already there,
        // which made many matches take quadratic time; collect the UTF-8 and build the string
        // once. UTF-8 takes a quarter of the memory of the scalars for ASCII text.
        var output: [UInt8] = []
        output.reserveCapacity(scalars.count + spans.reduce(0) { $0 + $1.replacement.utf8.count })
        func append(_ range: Range<Int>) {
            for index in range {
                let scalar = scalars[index]
                if scalar.isASCII {
                    output.append(UInt8(scalar.value))
                } else {
                    UTF8.encode(scalar) { output.append($0) }
                }
            }
        }
        var position = 0
        for span in spans {
            append(position..<span.start)
            output.append(contentsOf: span.replacement.utf8)
            position = span.end
        }
        append(position..<scalars.count)
        return String(decoding: output, as: UTF8.self)
    }

    /// The spans in order and without overlaps. A span inside a mask (an address, a card number)
    /// turns the mask into ``replacement``, since the mask shows part of what it covers; spans that
    /// partly overlap are joined into one ``replacement``.
    ///
    /// The spans are sorted and joined in the array passed in, which a text of many findings (a
    /// megabyte of addresses) otherwise copied twice.
    static func merged(_ spans: consuming [Span]) -> [Span] {
        var spans = spans
        spans.sort { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var count = 0
        for index in spans.indices {
            let span = spans[index]
            guard count > 0, span.start < spans[count - 1].end else {
                spans[count] = span
                count += 1
                continue
            }
            let last = spans[count - 1]
            guard span.end > last.end else {
                if last.replacement != replacement, !span.kind.isEmpty, span.kind != last.kind {
                    spans[count - 1] = Span(start: last.start, end: last.end, kind: last.kind.union(span.kind), replacement: replacement)
                }
                continue
            }
            spans[count - 1] = Span(start: last.start, end: span.end, kind: last.kind.union(span.kind), replacement: replacement)
        }
        spans.removeLast(spans.count - count)
        return spans
    }
}
