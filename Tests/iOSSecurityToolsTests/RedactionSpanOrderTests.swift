import Testing
@testable import iOSSecurityTools

/// The findings are sorted in place, without the buffer of half their size that the standard sort
/// takes, by merging the runs in which they come (see ``SensitiveDataRedactor/sortRuns(_:)``).
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

    @Test("a span keeps its offsets and kinds in its 24 bytes")
    func packing() {
        let span = Span(start: SensitiveDataRedactor.maximumTextLength, end: 7, kind: .all, replacement: "x")
        #expect(span.start == SensitiveDataRedactor.maximumTextLength)
        #expect(span.end == 7)
        #expect(span.kind == .all)
        #expect(MemoryLayout<Span>.stride == 24)
        var moved = span
        moved.start = 3
        moved.end = SensitiveDataRedactor.maximumTextLength
        #expect(moved.start == 3 && moved.end == SensitiveDataRedactor.maximumTextLength && moved.kind == .all)
    }
}
