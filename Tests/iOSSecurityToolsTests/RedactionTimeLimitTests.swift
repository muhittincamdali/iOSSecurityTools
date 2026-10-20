import Foundation
import Testing
import iOSSecurityTools

/// Input of about a megabyte, made when the test runs, and the redaction to time on it.
struct TimedInput: Sendable, CustomTestStringConvertible {
    let testDescription: String
    let make: @Sendable () -> String
    let redact: @Sendable (String) -> String
}

private let redactor = SensitiveDataRedactor()

private func body(_ contentType: String) -> @Sendable (String) -> String {
    { redactor.redact(body: Data($0.utf8), contentType: contentType) }
}

/// Whether the tests run in an optimized build: a debug build runs the same code many times
/// slower, so the limit is only checked with `swift test -c release`.
private var isOptimized: Bool {
    #if DEBUG
    false
    #else
    true
    #endif
}

@Suite("SensitiveDataRedactor time limit", .serialized, .enabled(if: isOptimized, "time limits are checked in a release build: swift test -c release"))
struct RedactionTimeLimitTests {
    static let size = 1_000_000
    static let limit = Duration.seconds(1)

    static let nested: [TimedInput] = [
        TimedInput(testDescription: "JSON quoted in JSON 16, 17 and 18 times", make: {
            [16, 17, 18].map { RedactionStackTests.quotedSecret(levels: $0, brackets: 1) }.joined(separator: "\n")
        }, redact: redactor.redact),
        TimedInput(testDescription: "[ a million times", make: { String(repeating: "[", count: size) }, redact: redactor.redact),
        TimedInput(testDescription: "{\"a\": 200,000 times", make: { String(repeating: "{\"a\":", count: size / 5) }, redact: redactor.redact),
        TimedInput(testDescription: "a URL in the query value of a URL, with the value allowed", make: {
            String(repeating: "https://a.example/?q=", count: size / 21)
        }, redact: SensitiveDataRedactor(allowedQueryParameters: ["q"]).redact),
        TimedInput(testDescription: "log lines with JSON and pairs", make: {
            String(repeating: "user=bob password=hunter2 status=200 {\"token\":\"abc\",\"n\":[1,{\"pin\":2}]}\n", count: size / 72)
        }, redact: redactor.redact),
    ]

    static let bodies: [TimedInput] = [
        TimedInput(testDescription: "a JSON body of objects with secrets and JSON in strings", make: {
            let object = #"{"user":"bob","password":"hunter2","note":"status=200 {\"token\":\"x\"}"},"#
            return "[" + String(repeating: object, count: size / object.utf8.count) + "{}]"
        }, redact: body("application/json")),
        TimedInput(testDescription: "a JSON body of strings of JSON quoted 15, 16 and 17 times", make: {
            "[\"" + [15, 16, 17].map { RedactionStackTests.escaped(RedactionStackTests.quotedSecret(levels: $0, brackets: 1)) }
                .joined(separator: "\",\"") + "\"]"
        }, redact: body("application/json")),
        TimedInput(testDescription: "a form", make: {
            String(repeating: "user=bob&password=hunter2&note=status%3D200&", count: size / 44) + "z=1"
        }, redact: body("application/x-www-form-urlencoded")),
        TimedInput(testDescription: "a multipart body of 1,000 parts", make: {
            let part = "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n" + String(repeating: "status=200 ", count: 85) + "\r\n"
            return String(repeating: part, count: 1_000) + "--B--"
        }, redact: body("multipart/form-data; boundary=B")),
        TimedInput(testDescription: "a plain-text body", make: {
            String(repeating: "login user=bob password=hunter2 card 4242 4242 4242 4242\n", count: size / 57)
        }, redact: body("text/plain")),
    ]

    @Test("redacting a megabyte of text takes less than a second", arguments: RedactionScalingTests.manyFindings + RedactionScalingTests.adversarial)
    func text(input: RepeatedText) {
        let text = input.text(length: Self.size)
        expectFast(input.testDescription) { _ = redactor.redact(text) }
    }

    @Test("redacting a megabyte of nested input or a body of a megabyte takes less than a second", arguments: nested + bodies)
    func nestedOrBody(input: TimedInput) {
        let text = input.make()
        #expect(text.utf8.count >= Self.size * 9 / 10 && text.utf8.count <= SensitiveDataRedactor.maximumBodySize)
        expectFast(input.testDescription) { _ = input.redact(text) }
    }

    /// The first run, and the fastest of two more when it went over the limit, so a burst of load
    /// from other tests does not fail it; work that is too slow fails all three.
    private func expectFast(_ name: String, sourceLocation: SourceLocation = #_sourceLocation, _ work: () -> Void) {
        let clock = ContinuousClock()
        var fastest = clock.measure(work)
        for _ in 0..<2 where fastest >= Self.limit {
            fastest = min(fastest, clock.measure(work))
        }
        #expect(fastest < Self.limit, "\(name): \(fastest)", sourceLocation: sourceLocation)
    }
}
