/// Replacements: where findings are, how they join, and the text they make.
extension SensitiveDataRedactor {
    /// A replacement, in offsets of the original scalars. A span without a kind is no finding: it
    /// writes a line separator as a line feed.
    struct Span {
        var start: Int
        var end: Int
        var kind: Kinds
        var replacement: String
    }

    /// The scalars with every span replaced; `spans` are in order and do not overlap.
    static func replacing(_ spans: [Span], in scalars: [Unicode.Scalar]) -> String {
        // Appending to a String.UnicodeScalarView piece by piece copies what is already there,
        // which made many matches take quadratic time; collect the scalars and build the
        // string once.
        var output: [Unicode.Scalar] = []
        output.reserveCapacity(scalars.count)
        var position = 0
        for span in spans {
            output.append(contentsOf: scalars[position..<span.start])
            output.append(contentsOf: span.replacement.unicodeScalars)
            position = span.end
        }
        output.append(contentsOf: scalars[position...])
        return String(String.UnicodeScalarView(output))
    }

    /// The spans in order and without overlaps. A span inside a mask (an address, a card number)
    /// turns the mask into ``replacement``, since the mask shows part of what it covers; spans that
    /// partly overlap are joined into one ``replacement``.
    static func merged(_ spans: [Span]) -> [Span] {
        let sorted = spans.sorted { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var result: [Span] = []
        for span in sorted {
            guard let last = result.last, span.start < last.end else {
                result.append(span)
                continue
            }
            guard span.end > last.end else {
                if last.replacement != replacement, !span.kind.isEmpty, span.kind != last.kind {
                    result[result.count - 1] = Span(start: last.start, end: last.end, kind: last.kind.union(span.kind), replacement: replacement)
                }
                continue
            }
            result[result.count - 1] = Span(start: last.start, end: span.end, kind: last.kind.union(span.kind), replacement: replacement)
        }
        return result
    }
}
