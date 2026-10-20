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

/// Bodies of a megabyte are read with the limit raised to 1 MiB, as an app may raise it.
private func body(_ contentType: String) -> @Sendable (String) -> String {
    { RedactionTimeLimitTests.largeBodies.redact(body: Data($0.utf8), contentType: contentType) }
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

    /// A body limit of 1 MiB, above the default, for the bodies of a megabyte these tests time.
    static let mebibyte = 1_048_576
    static let largeBodies = SensitiveDataRedactor(maximumBodySize: mebibyte)

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

    /// `unit` repeated, `separator` between, to about a megabyte with `prefix` and `suffix`.
    private static func repeated(_ unit: String, separator: String = ",", prefix: String = "[", suffix: String = "]") -> String {
        let count = (size - prefix.utf8.count - suffix.utf8.count) / (unit.utf8.count + separator.utf8.count)
        return prefix + Array(repeating: unit, count: count).joined(separator: separator) + suffix
    }

    private static func url(_ text: String) -> String { redactor.redact(url: URL(string: text)!) }

    /// Ordinary shapes that a review timed at one to four seconds a megabyte in a release build:
    /// a redactor was made for every array element and path segment, and each segment was read
    /// three times.
    static let shapes: [TimedInput] = [
        TimedInput(testDescription: "a JSON array of one-letter strings", make: { repeated("\"a\"") }, redact: body("application/json")),
        TimedInput(testDescription: "a JSON array of one-letter strings in a log line", make: { repeated("\"a\"") }, redact: redactor.redact),
        TimedInput(testDescription: "a JSON array of empty strings", make: { repeated("\"\"") }, redact: body("application/json")),
        TimedInput(testDescription: "a JSON array of different strings of words", make: {
            "[" + (0..<(size / 12)).map { "\"a b \($0)\"" }.joined(separator: ",") + "]"
        }, redact: body("application/json")),
        TimedInput(testDescription: "a multipart body of 1,000 parts of 900-byte JSON arrays", make: {
            let array = Array(repeating: "\"a\"", count: 224).joined(separator: ",")
            let part = "--B\r\nContent-Disposition: form-data; name=\"p\"\r\nContent-Type: application/json\r\n\r\n[\(array)]\r\n"
            return String(repeating: part, count: 1_000) + "--B--"
        }, redact: body("multipart/form-data; boundary=B")),
        TimedInput(testDescription: "a URL of a megabyte of /a", make: { repeated("a", separator: "/", prefix: "https://a.example/", suffix: "") }, redact: url),
        TimedInput(testDescription: "a log line with a URL of a megabyte of /a", make: {
            repeated("a", separator: "/", prefix: "https://a.example/", suffix: "")
        }, redact: redactor.redact),
        TimedInput(testDescription: "a URL of a megabyte of /users", make: { repeated("users", separator: "/", prefix: "https://a.example/", suffix: "") }, redact: url),
        TimedInput(testDescription: "a log line with a URL of a megabyte of /pin/4831", make: {
            repeated("pin/4831", separator: "/", prefix: "https://a.example/", suffix: "")
        }, redact: redactor.redact),
        TimedInput(testDescription: "log lines of URLs with 60 different segments", make: {
            repeated("https://a.example/" + (0..<60).map { "a=\($0)" }.joined(separator: "/"), separator: " ", prefix: "", suffix: "")
        }, redact: redactor.redact),
        TimedInput(testDescription: "log lines of URLs with 100 query parameters", make: {
            repeated("https://a.example/?" + (0..<100).map { "k\($0)=v" }.joined(separator: "&"), separator: " ", prefix: "", suffix: "")
        }, redact: redactor.redact),
    ]

    /// Secret names written as values, which make the scanner read the markup around them, the
    /// lines below them and every word of a quoted value.
    static let namesAsValues: [TimedInput] = [
        TimedInput(testDescription: "lines of XML elements named by secret names", make: {
            repeated("<string name=\"api_key\">x</string>", separator: "\n", prefix: "", suffix: "")
        }, redact: redactor.redact),
        TimedInput(testDescription: "a property list of secret keys and values of two lines", make: {
            repeated("<key>password</key>\n<string>a\nb</string>", separator: "\n", prefix: "<dict>\n", suffix: "\n</dict>")
        }, redact: redactor.redact),
        TimedInput(testDescription: "log lines with a quoted secret name", make: {
            repeated("field name=\"password\" x status=200", separator: "\n", prefix: "", suffix: "")
        }, redact: redactor.redact),
        TimedInput(testDescription: "one start tag of a megabyte of attributes before a secret name", make: {
            repeated("a=\"1\"", separator: " ", prefix: "<input ", suffix: " name=\"password\">x")
        }, redact: redactor.redact),
        TimedInput(testDescription: "lines with a tag named by a secret name that never ends", make: {
            repeated("login <password> required", separator: "\n", prefix: "", suffix: "")
        }, redact: redactor.redact),
        TimedInput(testDescription: "an element named by a secret name over a megabyte of lines", make: {
            repeated("line", separator: "\n", prefix: "<string name=\"password\">\n", suffix: "\n</string>")
        }, redact: redactor.redact),
        TimedInput(testDescription: "lines of elements with different names", make: {
            "<a>" + (0..<(size / 27)).map { "<k\($0)>password</k\($0)>" }.joined(separator: "\n") + "</a>"
        }, redact: redactor.redact),
        TimedInput(testDescription: "a quoted value of a megabyte that names a secret", make: {
            repeated("word", separator: " ", prefix: "msg=\"password ", suffix: "\" x")
        }, redact: redactor.redact),
        TimedInput(testDescription: "a JSON array of objects that name secrets", make: {
            repeated(#"{"label":"Password","value":"x","op":"add"}"#)
        }, redact: body("application/json")),
    ]

    @Test("redacting a megabyte of an ordinary shape takes a 512 KiB thread less than a second", arguments: shapes + namesAsValues + nestedPayloads + namesInHiddenValues + attributeShapes)
    func shape(input: TimedInput) {
        let text = input.make()
        #expect(text.utf8.count >= Self.size * 9 / 10 && text.utf8.count <= Self.mebibyte)
        var fastest = Self.threadTime(input, text)
        for _ in 0..<2 where fastest >= Self.limit {
            fastest = min(fastest, Self.threadTime(input, text))
        }
        #expect(fastest < Self.limit, "\(input.testDescription): \(fastest)")
    }

    /// The CPU time a thread with a 512 KiB stack takes to redact the text, which other tests
    /// running at the same time do not add to.
    private static func threadTime(_ input: TimedInput, _ text: String) -> Duration {
        onThread(stackSize: RedactionStackTests.threadStack) {
            let start = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
            _ = input.redact(text)
            return Duration.nanoseconds(Int64(clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - start))
        }
    }

    @Test("redacting a megabyte of text takes less than a second", arguments: RedactionScalingTests.manyFindings + RedactionScalingTests.adversarial)
    func text(input: RepeatedText) {
        let text = input.text(length: Self.size)
        expectFast(input.testDescription) { _ = redactor.redact(text) }
    }

    @Test("redacting a megabyte of nested input or a body of a megabyte takes less than a second", arguments: nested + bodies)
    func nestedOrBody(input: TimedInput) {
        let text = input.make()
        #expect(text.utf8.count >= Self.size * 9 / 10 && text.utf8.count <= Self.mebibyte)
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
