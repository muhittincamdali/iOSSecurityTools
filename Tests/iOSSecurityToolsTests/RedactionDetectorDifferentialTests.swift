import Foundation
import Testing
@testable import iOSSecurityTools

/// Every value detector gives the same result on every path: the same text as a log line, after a
/// key on the allowlist, as a text/plain body, as a JSON string, name or array element, inside JSON
/// in a line, as a form value or name, as a multipart part, as a query value on the allowlist, as
/// a path segment and inside a URL in a line, with the punctuation that ends a sentence after it.
@Suite("SensitiveDataRedactor detector differential")
struct RedactionDetectorDifferentialTests {
    /// Keys on the allowlists, so the detectors and not the key rule decide.
    let redactor = SensitiveDataRedactor(allowedTextKeys: ["note"], allowedQueryParameters: ["note"])

    /// A value for each detector, and part of it that must never show.
    static let samples: [(value: String, part: String)] = [
        ("4242424242424242", "42424242"),
        ("4242 4242 4242 4242", "4242 4242 4242"),
        ("4242-4242-4242-4242", "4242-4242-4242"),
        ("4242\t4242\t4242\t4242", "4242\t4242\t4242"),
        ("３７８２８２２４６３１０００５", "８２２４６３"),
        ("4242\u{200B}4242\u{200B}4242\u{200B}4242", "4242\u{200B}4242\u{200B}4242"),
        ("DE89370400440532013000", "3704004405"),
        ("DE89 3704 0044 0532 0130 00", "3704 0044"),
        ("alice@example.com", "lice"),
        ("ayşe.yılmaz@gmail.com", "yılmaz"),
        ("bjørn.dæhlie@example.no", "dæhlie"),
        ("zażółć.gęślą@example.pl", "gęślą"),
        ("张伟@example.cn", "张伟"),
        ("王小明@例子.中国", "王小明"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "eyJzdWIiOiIxMjM0In0"),
        ("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "eyJzdWIiOiIxIn0"),
        ("id_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln", "eyJzdWIiOiIxMjM0In0"),
        ("Bearer abc.DEF-123_456", "abc.DEF-123_456"),
        ("0123456789abcdef0123456789abcdef01", "0123456789abcdef0123456789"),
        ("QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTA=", "QWxhZGRpbjpvcGVuIHNl"),
        ("redis://:pw7Hunter2x@cache.example.com:6379", "pw7Hunter2x"),
    ]

    static let contexts: [(before: String, after: String)] = [("", ""), ("x ", "."), ("(", ")"), ("é", " end")]

    static func encoded(_ text: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return text.addingPercentEncoding(withAllowedCharacters: allowed)!
    }

    static func json(_ object: Any) -> Data {
        try! JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
    }

    /// The text on every path, with the name of the path; written as text again where it was
    /// encoded, so a part that shows can be found.
    func paths(_ text: String) -> [(String, String)] {
        let encoded = Self.encoded(text)
        let multipart = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n\(text)\r\n--B0und--\r\n"
        var paths: [(String, String)] = [
            ("text", redactor.redact(text)),
            ("allowed key", redactor.redact("note=" + text)),
            ("text body", redactor.redact(body: Data(text.utf8), contentType: "text/plain")),
            ("JSON string", redactor.redact(body: Self.json(["note": text]), contentType: "application/json")),
            ("JSON name", redactor.redact(body: Self.json([text: 1]), contentType: "application/json")),
            ("JSON array", redactor.redact(body: Self.json(["a", text]), contentType: "application/json")),
            ("JSON in text", redactor.redact("log " + String(decoding: Self.json(["note": text]), as: UTF8.self))),
            ("form value", redactor.redact(body: Data(("note=" + encoded).utf8), contentType: "application/x-www-form-urlencoded")),
            ("form name", redactor.redact(body: Data((encoded + "=1").utf8), contentType: "application/x-www-form-urlencoded")),
            ("multipart", redactor.redact(body: Data(multipart.utf8), contentType: "multipart/form-data; boundary=B0und")),
            ("URL in text", redactor.redact("see https://h.example/p?note=" + encoded)),
            ("URL in text, end of sentence", redactor.redact("see https://h.example/p?note=" + encoded + ".")),
        ]
        if let url = URL(string: "https://h.example/p?note=" + encoded) { paths.append(("query", redactor.redact(url: url))) }
        if let url = URL(string: "https://h.example/a/" + encoded + "/b") { paths.append(("path", redactor.redact(url: url))) }
        return paths.map { ($0.0, ($0.1.removingPercentEncoding ?? $0.1).replacingOccurrences(of: "\\/", with: "/")) }
    }

    @Test("every detector hides its value on every path", arguments: samples.indices)
    func everyPath(index: Int) {
        let (value, part) = Self.samples[index]
        for context in Self.contexts {
            let text = context.before + value + context.after
            for (path, output) in paths(text) {
                #expect(!output.contains(part), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("a finding that runs past the end of a URL in a line is hidden", arguments: [
        // The URL ends before the dot that ends a sentence, and an unsigned token ends in a dot: the
        // token is found in the path without it and in the text with it, and both are hidden.
        ("see https://h.example/p/eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "see [redacted]"),
        // Two dots after a URL leave its end open, so the text is cut where it starts.
        ("see https://h.example/p/eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0..", "see [redacted]"),
        // A card number that starts in the path and goes on after the URL.
        ("see https://h.example/p/4242 4242 4242 4242 ok", "see https://h.example/p/[redacted] ok"),
        // A URL with a query is not clean: the text is cut where it starts.
        ("see https://h.example/p?note=4242 4242 4242 4242 ok", "see [redacted]"),
    ])
    func findingAcrossURLEnd(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }
}
