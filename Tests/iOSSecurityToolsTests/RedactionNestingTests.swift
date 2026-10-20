import Foundation
import Testing
@testable import iOSSecurityTools

/// The nesting budget: JSON objects and arrays open at once, counted across JSON written in
/// strings, and documents one inside another.
@Suite("SensitiveDataRedactor nesting budget")
struct RedactionNestingTests {
    let redactor = SensitiveDataRedactor()

    private func redact(_ body: String, _ contentType: String = "application/json") -> String {
        redactor.redact(body: Data(body.utf8), contentType: contentType)
    }

    private static func brackets(_ count: Int, around inner: String = "") -> String {
        String(repeating: "[", count: count) + inner + String(repeating: "]", count: count)
    }

    /// `{"note":"…"}` with the text as the string, escaped.
    private static func noted(_ text: String) -> String {
        "{\"note\":\"" + RedactionStackTests.escaped(text) + "\"}"
    }

    private static func noted(_ text: String, times: Int) -> String {
        (0..<times).reduce(text) { inner, _ in noted(inner) }
    }

    @Test("the limits are 64 objects and arrays and four documents")
    func limits() {
        #expect(Nesting.maximumDepth == 64)
        #expect(Nesting.maximumLevel == 4)
    }

    @Test("reads a body 64 objects and arrays deep and omits one a level deeper")
    func bodyDepth() {
        let read = Self.brackets(64, around: "\"password=hunter2\"")
        #expect(redact(read) == Self.brackets(64, around: "\"password=[redacted]\""))
        let tooDeep = Self.brackets(65, around: "\"password=hunter2\"")
        #expect(redact(tooDeep) == "[body omitted: \(tooDeep.utf8.count) bytes, application/json]")
    }

    // The string is inside one object, so the JSON in it may open 63 more.
    @Test("a string holds JSON as deep as the depth left, and is hidden whole when it holds deeper JSON")
    func depthAcrossStrings() {
        let fits = Self.noted(Self.brackets(63, around: "\"status=ok\""))
        #expect(redact(fits) == fits)
        #expect(redactor.redact("log " + fits) == "log " + fits)
        let tooDeep = Self.noted(Self.brackets(64, around: "\"status=ok\""))
        #expect(redact(tooDeep) == #"{"note":"[redacted]"}"#)
        #expect(redactor.redact("log " + tooDeep) == #"log {"note":"[redacted]"}"#)
    }

    @Test("reads four documents one inside another and hides the string that holds a fifth")
    func documentLevels() {
        let innermost = #"{"status":"ok"}"#
        let four = Self.noted(innermost, times: 3)
        #expect(redact(four) == four)
        #expect(redactor.redact("log " + four) == "log " + four)
        let five = Self.noted(innermost, times: 4)
        let fifthHidden = Self.noted(#"{"note":"[redacted]"}"#, times: 3)
        #expect(redact(five) == fifthHidden)
        #expect(redactor.redact("log " + five) == "log " + fifthHidden)
    }

    @Test("a URL counts as a document")
    func urlLevel() {
        let url = "see https://example.com/a?status=ok"
        #expect(redact(Self.noted(url, times: 3)) == Self.noted("see https://example.com/a?status=[redacted]", times: 3))
        #expect(redact(Self.noted(url, times: 4)) == Self.noted(#"{"note":"[redacted]"}"#, times: 3))
        // Each URL writes the redacted value of the next one encoded again; the fifth is hidden.
        let allowed = SensitiveDataRedactor(allowedQueryParameters: ["q"])
        let chain = String(repeating: "https://a.example/?q=", count: 5) + "x"
        #expect(
            allowed.redact(chain) == "https://a.example/?q=https%3A%2F%2Fa.example%2F%3Fq%3Dhttps%253A%252F%252Fa.example%252F%253Fq%253D"
                + "https%25253A%25252F%25252Fa.example%25252F%25253Fq%25253D[redacted]"
        )
        let four = String(repeating: "https://a.example/?q=", count: 4) + "x"
        #expect(allowed.redact(four) == four)
    }

    @Test("a multipart part is a document inside the body")
    func multipartLevel() {
        let content = Self.noted(#"{"status":"ok"}"#, times: 3)
        let body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: application/json\r\n\r\n\(content)\r\n--B--"
        let expected = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: application/json\r\n\r\n"
            + Self.noted(#"{"note":"[redacted]"}"#, times: 2) + "\r\n--B--"
        #expect(redact(body, "multipart/form-data; boundary=B") == expected)
    }

    @Test("the logging guide's examples of the limits")
    func guideExamples() {
        let deep = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
        #expect(redact(deep) == "[body omitted: 130 bytes, application/json]")
        let note = #"{"note":""# + String(repeating: "[", count: 64) + String(repeating: "]", count: 64) + #" ok"}"#
        #expect(redact(note) == #"{"note":"[redacted]"}"#)
    }

    @Test("JSON deeper than the limit in a log line hides the line from its first bracket")
    func deepJSONInFreeText() {
        let line = "note " + Self.brackets(65, around: "\"status=ok\"") + " status=200\nstatus=200"
        #expect(redactor.redact(line) == "note [redacted]\nstatus=200")
    }
}
