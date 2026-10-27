/// Replacements: where findings are, how they join, and the text they make.
extension SensitiveDataRedactor {
    /// A replacement, in offsets of the original scalars, and the kinds of what it hides. The two
    /// offsets and the kinds are packed into 64 bits, so a span takes 24 bytes, not 40: a megabyte
    /// of short findings (`a@b.cd `, `1:2@`) holds up to a quarter of a million of them. A text
    /// longer than ``maximumTextLength`` is hidden before any span is made for it.
    ///
    /// A span that hides a whole text holds no offsets (see ``wholeText(kind:)``), and an offset
    /// that does not fit in 28 bits makes one: masked to 28 bits, the span that was to hide a text
    /// of 2^28 + 99 scalars ended at 99 and left the rest of the text written.
    struct Span {
        let replacement: String
        /// The start in the low 28 bits, the end in the next 28, the kinds in the next 7 and, in
        /// the top bit, whether the span hides the whole text.
        private let packed: UInt64

        /// The scalars from `start` to `end`, written as `replacement`; the whole text, written as
        /// ``SensitiveDataRedactor/replacement``, when an offset is not one a span holds.
        init(start: Int, end: Int, kind: Kinds, replacement: String) {
            guard Self.offsets.contains(start), Self.offsets.contains(end) else {
                self.init(wholeTextOf: kind)
                return
            }
            self.init(packed: UInt64(start) | UInt64(end) << 28 | Self.bits(of: kind), replacement: replacement)
        }

        private init(wholeTextOf kind: Kinds) {
            self.init(packed: Self.wholeTextBit | Self.bits(of: kind), replacement: SensitiveDataRedactor.replacement)
        }

        private init(packed: UInt64, replacement: String) {
            self.packed = packed
            self.replacement = replacement
        }

        /// A span that hides the whole text it is found in, however long: ``replacing(_:in:)``
        /// writes ``SensitiveDataRedactor/replacement`` alone for a text with one, and
        /// ``matches(in:)`` one match of the whole text. It starts at 0 and ends past every
        /// offset, so ``merged(_:)`` joins every other span into it.
        static func wholeText(kind: Kinds) -> Span { Span(wholeTextOf: kind) }

        /// The offsets a span holds: 0 to 2^28 − 1.
        static let offsets = 0...(1 << 28) - 1

        private static let offsetMask = UInt64(offsets.upperBound)
        /// The seven kinds of ``Kinds/all``.
        private static let kindMask: UInt64 = 0x7F
        private static let wholeTextBit: UInt64 = 1 << 63

        private static func bits(of kind: Kinds) -> UInt64 {
            (UInt64(truncatingIfNeeded: kind.rawValue) & kindMask) << 56
        }

        /// Whether the span hides the whole text it is found in (see ``wholeText(kind:)``).
        var hidesWholeText: Bool { packed & Self.wholeTextBit != 0 }

        var start: Int { hidesWholeText ? 0 : Int(packed & Self.offsetMask) }

        var end: Int { hidesWholeText ? .max : Int(packed >> 28 & Self.offsetMask) }

        var kind: Kinds { Kinds(rawValue: Int(packed >> 56 & Self.kindMask)) }
    }

    /// The scalars with every span replaced; `spans` are in order and do not overlap. The UTF-8 of
    /// the output is counted first and written once into the string, so the output is never held
    /// twice. A span that ends past the scalars — one that hides the whole text, or one made for
    /// another text — hides all of them: the output is ``replacement`` alone.
    static func replacing(_ spans: [Span], in scalars: [Unicode.Scalar]) -> String {
        guard spans.allSatisfy({ $0.end <= scalars.count }) else { return replacement }
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
    /// partly overlap are joined into one ``replacement``. A ``replacement`` that covers the same
    /// characters as another finding, or lies inside one, always wins: the cut of free text that
    /// starts and ends where a clean URL does (`(https://api.example.com/users/12345678`) hides the
    /// URL, which otherwise kept its `:id` form.
    ///
    /// The spans are sorted and joined in the array passed in, which a text of many findings (a
    /// megabyte of addresses) otherwise copied twice, and sorted without a buffer (see
    /// ``sortRuns(_:)``).
    static func merged(_ spans: consuming [Span]) -> [Span] {
        var spans = spans
        sortRuns(&spans)
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
                let hides = span.replacement == replacement || (!span.kind.isEmpty && span.kind != last.kind)
                if last.replacement != replacement, hides {
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

extension Array {
    /// Appends `element`, growing the capacity by a quarter when it is full instead of doubling it:
    /// the findings of the JSON in a megabyte of text would otherwise leave up to as much capacity
    /// unused as they take.
    mutating func appendGrowingByAQuarter(_ element: Element) {
        if count == capacity { reserveCapacity(count + count / 4 + 16) }
        append(element)
    }
}
