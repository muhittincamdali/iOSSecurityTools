import Foundation
import Testing
@testable import iOSSecurityTools

/// A text longer than the longest one that is read, ``SensitiveDataRedactor/maximumTextLength``
/// (2^28 − 1 scalars), is hidden whole (shared redaction spec §7 L2, §8.1 #17c). A span keeps its
/// offsets in 28 bits; 2.1.1 masked an offset that did not fit to its low 28 bits, so the span
/// that was to hide such a text ended near its start (a length of 2^28 + 99 ended at 99) and the
/// rest of the text was written.
@Suite("SensitiveDataRedactor text length limit")
struct RedactionTextLengthLimitTests {
    typealias Span = SensitiveDataRedactor.Span
    static let limit = SensitiveDataRedactor.maximumTextLength
    static let replacement = SensitiveDataRedactor.replacement

    /// One past the limit, a hundred past it, and twice it and five more: masked to 28 bits they
    /// are 0, 99 and 3.
    static let pastTheLimit = [limit + 1, limit + 100, 2 * limit + 5]

    /// A text with secrets at its end, longer than any of those masked offsets, so that a masked
    /// span ends inside it.
    static let sample = Array((String(repeating: "status=200 ", count: 12) + "password=hunter2 card 4111111111111111").unicodeScalars)

    @Test("§8.1 #17c: a span to the end of a text longer than the limit hides all of it", arguments: pastTheLimit)
    func spanToTheEnd(length: Int) {
        let span = Span(start: 0, end: length, kind: .secretFields, replacement: Self.replacement)
        #expect(SensitiveDataRedactor.replacing([span], in: Self.sample) == Self.replacement)
        #expect(span.start == 0 && span.end >= length, "\(span.start)..<\(span.end)")
    }

    @Test("a span that starts past the limit hides the whole text", arguments: pastTheLimit)
    func spanPastTheLimit(start: Int) {
        let span = Span(start: start, end: start + 1, kind: .cardNumbers, replacement: "•••• 1111")
        #expect(SensitiveDataRedactor.replacing([span], in: Self.sample) == Self.replacement)
    }

    @Test("a span joined with one past the limit hides the whole text", arguments: pastTheLimit)
    func joinedPastTheLimit(length: Int) {
        let spans = SensitiveDataRedactor.merged([
            Span(start: 2, end: 9, kind: .secretFields, replacement: Self.replacement),
            Span(start: 5, end: length, kind: .secretFields, replacement: Self.replacement),
        ])
        #expect(SensitiveDataRedactor.replacing(spans, in: Self.sample) == Self.replacement)
    }

    @Test("offsets up to the limit are kept as they are")
    func offsetsAtTheLimit() {
        let span = Span(start: Self.limit - 1, end: Self.limit, kind: .ibans, replacement: Self.replacement)
        #expect(span.start == Self.limit - 1 && span.end == Self.limit && span.kind == .ibans && !span.hidesWholeText)
        let short = Span(start: 3, end: 7, kind: .emailAddresses, replacement: "x")
        #expect(SensitiveDataRedactor.replacing([short], in: Array("abc1234def".unicodeScalars)) == "abcxdef")
    }

    @Test("a negative offset hides the whole text, and so does a span of the whole text, whatever it replaces")
    func wholeTextSpans() {
        let negative = Span(start: -1, end: 4, kind: .cardNumbers, replacement: "•••• 1111")
        #expect(negative.hidesWholeText && negative.replacement == Self.replacement && negative.kind == .cardNumbers)
        let whole = Span.wholeText(kind: .secretFields)
        #expect(whole.start == 0 && whole.end == .max && whole.kind == .secretFields)
        #expect(SensitiveDataRedactor.replacing([whole], in: Self.sample) == Self.replacement)
        let merged = SensitiveDataRedactor.merged([Span(start: 3, end: 5, kind: .ibans, replacement: "x"), whole, Span(start: 9, end: 30, kind: .emailAddresses, replacement: "y")])
        #expect(merged.count == 1 && merged[0].hidesWholeText)
        #expect(SensitiveDataRedactor.replacing([Span(start: 0, end: Self.sample.count + 1, kind: .ibans, replacement: "x")], in: Self.sample) == Self.replacement)
    }

    // MARK: Every path, with a limit a test can reach

    /// The limit that the tests below give a redactor: texts past the real one take more than a
    /// gigabyte.
    static let testLimit = 64
    static let standard = SensitiveDataRedactor(allowedQueryParameters: ["q"])
    static let limited = SensitiveDataRedactor(standard, textLengthLimit: testLimit)

    /// The test limit plus one, plus a hundred, and twice it plus five.
    static let pastTheTestLimit = [testLimit + 1, testLimit + 100, 2 * testLimit + 5]

    /// A text of `length` scalars that ends with secrets that free text reads around: an allowed
    /// key, an address and a secret field.
    static func secretText(length: Int, filler: Character = "x") -> String {
        let secrets = "status=200 mail alice@example.com password=hunter2"
        return String(repeating: filler, count: length - secrets.count - 1) + " " + secrets
    }

    private static func showsNoSecret(_ output: String) -> Bool {
        !output.contains("hunter2") && !output.contains("alice") && !output.contains("example.com")
    }

    @Test("§8.1 #17c: free text past the limit is the replacement alone, and one match of the whole text", arguments: pastTheTestLimit)
    func freeTextPastTheLimit(length: Int) {
        let text = Self.secretText(length: length)
        #expect(Self.standard.redact(text) != Self.replacement)
        #expect(Self.limited.redact(text) == Self.replacement)
        let matches = Self.limited.matches(in: text)
        #expect(matches.count == 1 && matches.first?.range == text.startIndex..<text.endIndex && matches.first?.kind == .secretFields)
        for kinds: SensitiveDataRedactor.Kinds in [[.cardNumbers], [.emailAddresses, .longTokens]] {
            #expect(SensitiveDataRedactor(SensitiveDataRedactor(kinds: kinds), textLengthLimit: Self.testLimit).redact(text) == Self.replacement)
        }
    }

    @Test("a text up to the limit, counted in scalars, is read as before", arguments: [testLimit - 1, testLimit])
    func textUpToTheLimit(length: Int) {
        // `ş` and `ü` take two bytes each: the text has more UTF-8 bytes than the limit.
        for filler: Character in ["x", "ş", "ü"] {
            let text = Self.secretText(length: length, filler: filler)
            #expect(text.unicodeScalars.count == length)
            #expect(Self.limited.redact(text) == Self.standard.redact(text))
            #expect(Self.limited.redact(text).hasSuffix(" status=200 mail a•••@example.com password=[redacted]"))
            #expect(Self.limited.matches(in: text).map(\.kind) == Self.standard.matches(in: text).map(\.kind))
        }
    }

    @Test("a redactor that looks for nothing writes a long text as it is")
    func noKinds() {
        let text = Self.secretText(length: Self.testLimit + 100)
        let redactor = SensitiveDataRedactor(SensitiveDataRedactor(kinds: []), textLengthLimit: Self.testLimit)
        #expect(redactor.redact(text) == text && redactor.matches(in: text).isEmpty)
    }

    @Test("a string, a name and a value past the limit are hidden whole in every body", arguments: pastTheTestLimit)
    func bodiesPastTheLimit(length: Int) {
        let text = Self.secretText(length: length)
        func body(_ body: String, _ type: String) -> String { Self.limited.redact(body: Data(body.utf8), contentType: type) }
        #expect(body(#"{"note":"\#(text)","ok":"fine"}"#, "application/json") == #"{"note":"[redacted]","ok":"fine"}"#)
        #expect(body(#"{"\#(text)":"x","ok":"fine"}"#, "application/json") == #"{"[redacted]":"[redacted]","ok":"fine"}"#)
        #expect(body(#"["\#(text)"]"#, "application/json") == #"["[redacted]"]"#)
        #expect(body(text, "text/plain") == Self.replacement)
        let encoded = text.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        #expect(body("note=\(encoded)&ok=fine", "application/x-www-form-urlencoded") == "note=[redacted]&ok=fine")
        #expect(body("\(encoded)=x&ok=fine", "application/x-www-form-urlencoded") == "[redacted]=[redacted]&ok=fine")
        let multipart = "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n\(text)\r\n--B\r\n"
            + "Content-Disposition: form-data; name=\"\(text)\"\r\n\r\nx\r\n--B--"
        let output = body(multipart, "multipart/form-data; boundary=B")
        #expect(output == "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n[redacted]\r\n--B\r\n"
            + "Content-Disposition: form-data; name=\"[redacted]\"\r\n\r\n[redacted]\r\n--B--", "\(output.debugDescription)")
        #expect(Self.showsNoSecret(output))
    }

    @Test("a query value and a path segment past the limit are hidden", arguments: pastTheTestLimit)
    func urlPastTheLimit(length: Int) {
        let encoded = Self.secretText(length: length).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let query = URL(string: "https://example.com/a?q=\(encoded)&page=2")!
        #expect(Self.limited.redact(url: query) == "https://example.com/a?q=[redacted]&page=[redacted]")
        let segment = String(repeating: "x", count: length)
        let path = URL(string: "https://example.com/v1/\(segment)/next")!
        #expect(Self.standard.redact(url: path) == "https://example.com/v1/\(segment)/next")
        #expect(Self.limited.redact(url: path) == "https://example.com/v1/:id/:id")
    }
}
