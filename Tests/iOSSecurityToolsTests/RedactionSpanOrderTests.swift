import Testing
@testable import iOSSecurityTools

/// The findings are sorted in place, without the buffer of half their size that the standard sort
/// takes, by merging the runs in which they come (see ``SensitiveDataRedactor/sortRuns(_:)``), and
/// joined so that a `[redacted]` span hides every finding it covers or lies inside
/// (see ``SensitiveDataRedactor/merged(_:)``).
@Suite("SensitiveDataRedactor order of findings")
struct RedactionSpanOrderTests {
    typealias Span = SensitiveDataRedactor.Span

    /// Spans as a few runs in order, as the detectors give them: random starts and lengths, some
    /// equal, with a replacement that tells each apart.
    static func runs(using random: inout SeededRandom) -> [Span] {
        var spans: [Span] = []
        for _ in 0..<Int.random(in: 1...6, using: &random) {
            var start = Int.random(in: 0...20, using: &random)
            for _ in 0..<Int.random(in: 0...40, using: &random) {
                start += Int.random(in: 0...3, using: &random)
                let end = start + Int.random(in: 1...5, using: &random)
                spans.append(Span(start: start, end: end, kind: .emailAddresses, replacement: "\(spans.count)"))
            }
        }
        return spans
    }

    @Test("merging the runs sorts the spans as a stable sort does", arguments: 0..<4)
    func sortsStably(seed: Int) {
        var random = SeededRandom(seed: 0x19_5000 + UInt64(seed))
        for _ in 0..<300 {
            let spans = Self.runs(using: &random)
            let expected = spans.enumerated().sorted { first, second in
                if SensitiveDataRedactor.isBefore(first.element, second.element) { return true }
                if SensitiveDataRedactor.isBefore(second.element, first.element) { return false }
                return first.offset < second.offset
            }.map(\.element.replacement)
            var sorted = spans
            SensitiveDataRedactor.sortRuns(&sorted)
            #expect(sorted.map(\.replacement) == expected)
        }
    }

    @Test("a [redacted] span over the same characters as another finding, or inside it, wins")
    func redactedSpanWins() {
        let redacted = SensitiveDataRedactor.replacement
        let url = Span(start: 1, end: 39, kind: .secretFields, replacement: "https://api.example.com/users/:id")
        let cut = Span(start: 1, end: 39, kind: .secretFields, replacement: redacted)
        let inside = Span(start: 30, end: 39, kind: .secretFields, replacement: redacted)
        for spans in [[url, cut], [cut, url], [url, inside]] {
            let merged = SensitiveDataRedactor.merged(spans)
            #expect(merged.map(\.replacement) == [redacted])
            #expect(merged.map(\.start) == [1] && merged.map(\.end) == [39])
        }
        // A finding of the mask's own kind inside it, other than [redacted], keeps the mask.
        let mask = Span(start: 0, end: 19, kind: .cardNumbers, replacement: "•••• •••• •••• 4242")
        let card = Span(start: 5, end: 19, kind: .cardNumbers, replacement: "•••• •••• 4242")
        #expect(SensitiveDataRedactor.merged([mask, card]).map(\.replacement) == [mask.replacement])
    }

    /// The nineteenth review: an unclosed bracket before a clean URL cuts the text where the URL
    /// starts, and the cut ends where the URL does. The URL's `:id` form showed until the cut won.
    @Test("free text cut where a clean URL starts hides the URL", arguments: [
        ("(https://api.example.com/users/12345678", "([redacted]"),
        ("see (https://api.example.com/users/12345678", "see ([redacted]"),
        ("see [https://api.example.com/users/12345678", "see [[redacted]"),
        ("see {https://api.example.com/users/12345678", "see {[redacted]"),
        ("see (https://api.example.com/users/12345678/orders/987654321", "see ([redacted]"),
        ("see (https://api.example.com/v1/users/550e8400-e29b-41d4-a716-446655440000", "see ([redacted]"),
        ("x [https://api.example.com/users/12345678]", "x [[redacted]"),
        ("(https://x.example/a", "([redacted]"),
        // A clean URL that no cut covers keeps its form.
        ("GET https://api.example.com/users/12345678 200", "GET https://api.example.com/users/:id 200"),
        ("see (https://api.example.com/users/12345678) ok", "see (https://api.example.com/users/:id) ok"),
    ])
    func cutCoveringURL(input: String, expected: String) {
        #expect(SensitiveDataRedactor().redact(input) == expected)
    }

    @Test("a span keeps its offsets and kinds in its 24 bytes")
    func packing() {
        let span = Span(start: SensitiveDataRedactor.maximumTextLength, end: 7, kind: .all, replacement: "x")
        #expect(span.start == SensitiveDataRedactor.maximumTextLength)
        #expect(span.end == 7)
        #expect(span.kind == .all)
        #expect(MemoryLayout<Span>.stride == 24)
        // The top bit marks a span of the whole text, so the kinds must fit in the seven below it.
        #expect(SensitiveDataRedactor.Kinds.all.rawValue < 1 << 7)
        let other = Span(start: 3, end: SensitiveDataRedactor.maximumTextLength, kind: .all, replacement: "x")
        #expect(other.start == 3 && other.end == SensitiveDataRedactor.maximumTextLength && other.kind == .all && !other.hidesWholeText)
    }
}
