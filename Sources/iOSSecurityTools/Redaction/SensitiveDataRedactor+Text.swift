extension SensitiveDataRedactor {
    /// The findings in free text, in order and without overlaps. `nesting` says which documents
    /// the text is in; a text inside one whose JSON or URL goes past a limit is one finding.
    func textSpans(in scalars: [Unicode.Scalar], compatibility: CompatibilityText, role: FreeTextScanner.Role = .text, nesting: Nesting) -> [Span] {
        guard !scalars.isEmpty, !kinds.isEmpty, !Self.isQuietWord(scalars) else { return [] }
        guard scalars.count <= Self.maximumTextLength else { return [Span(start: 0, end: scalars.count, kind: .secretFields, replacement: Self.replacement)] }
        return textSpans(in: scalars, text: NormalizedText(scalars, compatibility: compatibility), compatibility: compatibility, role: role, nesting: nesting)
    }

    /// ``textSpans(in:compatibility:role:nesting:)`` on a scanning copy that is already made.
    /// With `detectsInRegions` the value detectors also read the JSON and URLs in the text, which
    /// a path segment needs: a URL in one keeps its host, and a token in the host must still make
    /// the segment `:id`. A text inside a document found in the input that the reading budget no
    /// longer covers (see ``ReadingBudget``) is one finding, and so is a text longer than
    /// ``maximumTextLength``, whose offsets the scanning copy cannot hold.
    ///
    /// The free-text rule cuts the text at its first trigger (see ``FreeTextScanner``): what comes
    /// before the cut keeps the findings of the JSON, URLs and value detectors in it, and the cut
    /// hides the rest.
    func textSpans(
        in scalars: [Unicode.Scalar], text: NormalizedText, compatibility: CompatibilityText, role: FreeTextScanner.Role = .text,
        nesting: Nesting, detectsInRegions: Bool = false
    ) -> [Span] {
        guard !scalars.isEmpty, !kinds.isEmpty else { return [] }
        let whole = [Span(start: 0, end: scalars.count, kind: .secretFields, replacement: Self.replacement)]
        guard scalars.count <= Self.maximumTextLength else { return whole }
        guard kinds.contains(.secretFields) else { return Self.merged(detectorSpans(in: text)) }
        guard nesting.reads(scalars.count) else { return whole }
        var scanner = FreeTextScanner(source: scalars, text: text, redactor: self, compatibility: compatibility, role: role, nesting: nesting)
        scanner.run()
        if scanner.hidesWholeText { return whole }
        let cut = scanner.cut.flatMap { $0 < scalars.count ? [Span(start: $0, end: scalars.count, kind: .secretFields, replacement: Self.replacement)] : nil } ?? []
        // JSON and URLs were redacted by their own rules; the detectors do not read them again.
        let regions = scanner.regions
        // The findings are collected in the array of the value detectors, which is the largest:
        // a megabyte of addresses finds forty thousand of them.
        var found: [Span]
        if regions.isEmpty || detectsInRegions {
            found = detectorSpans(in: text)
        } else {
            found = detectorSpans(in: text.masking(regions))
            found += Self.crossing(detectorSpans(in: text), regions)
        }
        found += scanner.spans
        found += cut
        return Self.merged(found)
    }

    /// The longest text that is read: one whose scalar offsets fit in 32 bits (see
    /// ``ScalarOffsets``). A longer one is hidden whole.
    static let maximumTextLength = Int(UInt32.max)

    /// The findings that run over the edge of a JSON or URL region, hidden whole. A URL ends
    /// before the punctuation that ends a sentence, so `…?q=eyJ….eyJ….` keeps the dot of an
    /// unsigned token outside it, and a card number may start in a query and go on after it:
    /// neither the region nor the text outside it holds the finding, but the text as a whole does,
    /// as a body or a string holding the same text would.
    static func crossing(_ spans: [Span], _ regions: [Range<Int>]) -> [Span] {
        // Regions do not overlap: the scanner records each after the one before.
        let regions = regions.sorted { $0.lowerBound < $1.lowerBound }
        return spans.compactMap { span in
            var low = 0
            var high = regions.count
            while low < high {
                let middle = (low + high) / 2
                if regions[middle].lowerBound < span.end { low = middle + 1 } else { high = middle }
            }
            guard low > 0 else { return nil }
            let last = regions[low - 1]
            let crosses = last.lowerBound > span.start || (last.upperBound > span.start && span.end > last.upperBound)
            return crosses ? Span(start: span.start, end: span.end, kind: span.kind, replacement: replacement) : nil
        }
    }

    /// The longest text ``isQuietWord(_:)`` takes: the shortest card number has 13 digits, an
    /// IBAN 15 characters and a long token 32.
    static let quietWordLength = 12

    /// Whether a text is one word of at most ``quietWordLength`` ASCII letters and digits with no
    /// secret word in it, such as most JSON strings, path segments and query names. No rule and
    /// no detector finds anything in such a word, so it is not scanned; reading every one of them
    /// took most of the time of a JSON array of short strings and of a URL of many segments.
    static func isQuietWord(_ scalars: [Unicode.Scalar]) -> Bool {
        guard scalars.count <= quietWordLength else { return false }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(scalars.count)
        for scalar in scalars {
            guard scalar.isASCII, ASCII.isAlphanumeric(UInt8(scalar.value)) else { return false }
            bytes.append(UInt8(scalar.value))
        }
        return PlainName(bytes: bytes, maximumLength: nil)?.namesSecret == false
    }

    /// The findings of the value detectors this redactor's kinds turn on.
    func detectorSpans(in text: NormalizedText) -> [Span] {
        var found: [Span] = []
        // The first detector that finds anything hands over its array instead of a copy.
        func add(_ spans: [Span]) {
            if found.isEmpty { found = spans } else { found += spans }
        }
        if kinds.contains(.secretFields) { add(text.userInfoPasswordSpans()) }
        if kinds.contains(.bearerTokens) { add(text.bearerSpans()) }
        if kinds.contains(.jsonWebTokens) { add(text.jsonWebTokenSpans()) }
        if kinds.contains(.emailAddresses) { add(text.emailSpans()) }
        if kinds.contains(.cardNumbers) { add(text.cardSpans()) }
        if kinds.contains(.ibans) { add(text.ibanSpans()) }
        if kinds.contains(.longTokens) { add(text.longTokenSpans()) }
        return found
    }

    /// The text redacted as free text, and what was found in it; nil when nothing was.
    func redactedText(
        _ scalars: [Unicode.Scalar], compatibility: CompatibilityText, role: FreeTextScanner.Role = .text, nesting: Nesting
    ) -> (text: String, kind: Kinds)? {
        let spans = textSpans(in: scalars, compatibility: compatibility, role: role, nesting: nesting)
        guard !spans.isEmpty else { return nil }
        let kind = spans.reduce(into: Kinds()) { $0.formUnion($1.kind) }
        return (Self.replacing(spans, in: scalars), kind)
    }

    /// A text inside a document (a form value, a query value, a multipart header), redacted as
    /// free text with the document's nesting.
    func redact(_ text: String, nesting: Nesting) -> String {
        let scalars = Array(text.unicodeScalars)
        let spans = textSpans(in: scalars, compatibility: CompatibilityText(), nesting: nesting)
        return spans.isEmpty ? text : Self.replacing(spans, in: scalars)
    }

    /// A key that is written out (a form or multipart field name, a query parameter name) read as
    /// free text in the ``FreeTextScanner/Role/name`` role.
    func redactedName(_ name: String, nesting: Nesting) -> String {
        redactedText(Array(name.unicodeScalars), compatibility: CompatibilityText(), role: .name, nesting: nesting)?.text ?? name
    }
}
