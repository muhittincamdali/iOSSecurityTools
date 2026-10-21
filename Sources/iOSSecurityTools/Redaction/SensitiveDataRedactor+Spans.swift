/// Replacements: where findings are, how they join, and the text they make.
extension SensitiveDataRedactor {
    /// A replacement, in offsets of the original scalars, and the kinds of what it hides. The two
    /// offsets and the kinds are packed into 64 bits, so a span takes 24 bytes, not 40: a megabyte
    /// of short findings (`a@b.cd `, `1:2@`) holds up to a quarter of a million of them. Every
    /// text that is read has fewer than 2^28 scalars (see ``maximumTextLength``).
    struct Span {
        var replacement: String
        /// The start in the low 28 bits, the end in the next 28 and the kinds in the top 8.
        private var packed: UInt64

        init(start: Int, end: Int, kind: Kinds, replacement: String) {
            self.replacement = replacement
            packed = Self.offset(start) | Self.offset(end) << 28 | UInt64(UInt8(truncatingIfNeeded: kind.rawValue)) << 56
        }

        private static let offsetMask: UInt64 = (1 << 28) - 1

        private static func offset(_ value: Int) -> UInt64 {
            UInt64(clamping: value) & offsetMask
        }

        var start: Int {
            get { Int(packed & Self.offsetMask) }
            set { packed = packed & ~Self.offsetMask | Self.offset(newValue) }
        }

        var end: Int {
            get { Int(packed >> 28 & Self.offsetMask) }
            set { packed = packed & ~(Self.offsetMask << 28) | Self.offset(newValue) << 28 }
        }

        var kind: Kinds { Kinds(rawValue: Int(packed >> 56)) }
    }

    /// The scalars with every span replaced; `spans` are in order and do not overlap. The UTF-8 of
    /// the output is counted first and written once into the string, so the output is never held
    /// twice.
    static func replacing(_ spans: [Span], in scalars: [Unicode.Scalar]) -> String {
        // Appending to a String.UnicodeScalarView piece by piece copies what is already there,
        // which made many matches take quadratic time.
        func utf8Count(_ range: Range<Int>) -> Int {
            var count = 0
            for index in range { count += UTF8.width(scalars[index]) }
            return count
        }
        var length = 0
        var position = 0
        for span in spans {
            length += utf8Count(position..<span.start) + span.replacement.utf8.count
            position = span.end
        }
        length += utf8Count(position..<scalars.count)
        return String(unsafeUninitializedCapacity: length) { output in
            var written = 0
            func append(_ range: Range<Int>) {
                for index in range {
                    let scalar = scalars[index]
                    if scalar.isASCII {
                        output[written] = UInt8(scalar.value)
                        written += 1
                    } else {
                        UTF8.encode(scalar) { byte in
                            output[written] = byte
                            written += 1
                        }
                    }
                }
            }
            var position = 0
            for span in spans {
                append(position..<span.start)
                for byte in span.replacement.utf8 {
                    output[written] = byte
                    written += 1
                }
                position = span.end
            }
            append(position..<scalars.count)
            return written
        }
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
