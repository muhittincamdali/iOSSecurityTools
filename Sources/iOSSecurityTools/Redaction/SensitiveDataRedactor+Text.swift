extension SensitiveDataRedactor {
    /// The findings in free text, in order and without overlaps.
    func textSpans(in scalars: [Unicode.Scalar], compatibility: CompatibilityText, role: FreeTextScanner.Role = .text) -> [Span] {
        guard !scalars.isEmpty, !kinds.isEmpty else { return [] }
        let text = NormalizedText(scalars, compatibility: compatibility)
        guard kinds.contains(.secretFields) else { return Self.merged(detectorSpans(in: text)) }
        var scanner = FreeTextScanner(source: scalars, text: text, redactor: self, compatibility: compatibility, role: role)
        scanner.run()
        // JSON and URLs were redacted by their own rules; the detectors do not read them again.
        let regions = scanner.regions
        let detectorText = regions.isEmpty ? text : NormalizedText(scalars, compatibility: compatibility, masked: regions)
        let folds = Self.lineSeparatorFolds(in: scalars, outside: regions)
        return Self.merged(scanner.spans + detectorSpans(in: detectorText) + folds)
    }

    /// The findings of the value detectors this redactor's kinds turn on.
    func detectorSpans(in text: NormalizedText) -> [Span] {
        var found: [Span] = []
        if kinds.contains(.secretFields) { found += text.userInfoPasswordSpans() }
        if kinds.contains(.bearerTokens) { found += text.bearerSpans() }
        if kinds.contains(.jsonWebTokens) { found += text.jsonWebTokenSpans() }
        if kinds.contains(.emailAddresses) { found += text.emailSpans() }
        if kinds.contains(.cardNumbers) { found += text.cardSpans() }
        if kinds.contains(.ibans) { found += text.ibanSpans() }
        if kinds.contains(.longTokens) { found += text.longTokenSpans() }
        return found
    }

    /// The text redacted as free text, and what was found in it; nil when nothing was.
    func redactedText(
        _ scalars: [Unicode.Scalar], compatibility: CompatibilityText, role: FreeTextScanner.Role = .text
    ) -> (text: String, kind: Kinds)? {
        let spans = textSpans(in: scalars, compatibility: compatibility, role: role)
        guard !spans.isEmpty else { return nil }
        let kind = spans.reduce(into: Kinds()) { $0.formUnion($1.kind) }
        return (Self.replacing(spans, in: scalars), kind)
    }

    /// A key that is written out (a form or multipart field name, a query parameter name) read as
    /// free text in the ``FreeTextScanner/Role/name`` role.
    func redactedName(_ name: String) -> String {
        redactedText(Array(name.unicodeScalars), compatibility: CompatibilityText(), role: .name)?.text ?? name
    }

    /// U+2028, U+2029, U+0085, vertical tab and form feed, written as line feeds, since the
    /// free-text rule ends a line at them. Inside JSON they are kept: a JSON string may hold them.
    private static func lineSeparatorFolds(in scalars: [Unicode.Scalar], outside regions: [Range<Int>]) -> [Span] {
        var folds: [Span] = []
        let sortedRegions = regions.sorted { $0.lowerBound < $1.lowerBound }
        var regionIndex = 0
        for (offset, scalar) in scalars.enumerated() where foldedLineSeparators.contains(scalar) {
            while regionIndex < sortedRegions.count, sortedRegions[regionIndex].upperBound <= offset { regionIndex += 1 }
            if regionIndex < sortedRegions.count, sortedRegions[regionIndex].contains(offset) { continue }
            folds.append(Span(start: offset, end: offset + 1, kind: [], replacement: "\n"))
        }
        return folds
    }

    private static let foldedLineSeparators: Set<Unicode.Scalar> = ["\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}"]
}
