import Foundation
import Testing
import iOSSecurityTools

/// Holds what a thread returns; the thread writes it before it signals, and the caller reads it
/// after the wait.
private final class ThreadResult<Value>: @unchecked Sendable {
    var result: Value?
}

/// Runs `work` on a thread of its own with a stack of `stackSize` bytes and returns its result.
func onThread<Value: Sendable>(stackSize: Int, _ work: @escaping @Sendable () -> Value) -> Value {
    let box = ThreadResult<Value>()
    let done = DispatchSemaphore(value: 0)
    let thread = Thread {
        box.result = work()
        done.signal()
    }
    thread.stackSize = stackSize
    thread.start()
    done.wait()
    return box.result!
}

/// Input that made a reader recurse once per level, and a way to redact it.
struct DeepInput: Sendable, CustomTestStringConvertible {
    let testDescription: String
    let redact: @Sendable () -> String
}

// Untrusted input must not crash the app. Every test redacts on a thread with 512 KiB of stack,
// the default of secondary threads, GCD queues and Swift concurrency, and runs in debug and in
// release builds (`swift test -c release`), whose frames differ in size.
@Suite("SensitiveDataRedactor stack use")
struct RedactionStackTests {
    static let secret = "hunter2"
    static let threadStack = 512 * 1024

    /// The text with `"` and `\` escaped, written here so the input does not depend on the code
    /// under test.
    static func escaped(_ text: String) -> String {
        var output = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if scalar == "\"" || scalar == "\\" { output.append("\\") }
            output.append(scalar)
        }
        return String(output)
    }

    /// `password=hunter2` as a JSON string inside `brackets` arrays, that again as a string inside
    /// `brackets` arrays, `levels` times.
    static func quotedSecret(levels: Int, brackets: Int) -> String {
        var text = "password=\(secret)"
        for _ in 0..<levels {
            text = String(repeating: "[", count: brackets) + "\"" + escaped(text) + "\"" + String(repeating: "]", count: brackets)
        }
        return text
    }

    private func expectHidden(_ text: String, sourceLocation: SourceLocation = #_sourceLocation) {
        let size = text.utf8.count
        let redacted = onThread(stackSize: Self.threadStack) { SensitiveDataRedactor().redact(text) }
        let body = onThread(stackSize: Self.threadStack) {
            SensitiveDataRedactor().redact(body: Data(text.utf8), contentType: "application/json")
        }
        #expect(!redacted.contains(Self.secret), "text of \(size) bytes", sourceLocation: sourceLocation)
        #expect(!body.contains(Self.secret), "body of \(size) bytes", sourceLocation: sourceLocation)
    }

    // The review of 2.1.0 found that 3.2 KB of JSON quoted in JSON crashed redact(_:) and
    // redact(body:contentType:) with SIGBUS in a release build on such a thread; 2.0.0 handled
    // the same shape up to 533 KB.
    @Test("password=hunter2 quoted in JSON six times inside 255 brackets each does not overflow the stack")
    func reviewInput() {
        let text = Self.quotedSecret(levels: 6, brackets: 255)
        #expect(text.utf8.count == 3_202)
        expectHidden(text)
    }

    @Test("JSON quoted in JSON up to twelve times does not overflow the stack", arguments: [1, 16, 63, 64, 65, 255])
    func quotedJSON(brackets: Int) {
        for levels in 1...12 {
            expectHidden(Self.quotedSecret(levels: levels, brackets: brackets))
        }
    }

    @Test("the largest quoted JSON under the body limit does not overflow the stack", arguments: [1, 255])
    func largestQuotedJSON(brackets: Int) {
        var levels = 1
        while Self.quotedSecret(levels: levels + 1, brackets: brackets).utf8.count <= SensitiveDataRedactor.defaultMaximumBodySize { levels += 1 }
        expectHidden(Self.quotedSecret(levels: levels, brackets: brackets))
    }

    static let deepInputs: [DeepInput] = [
        DeepInput(testDescription: "a megabyte of [ in text") { SensitiveDataRedactor().redact(String(repeating: "[", count: 1_000_000)) },
        DeepInput(testDescription: "a megabyte of [ as a JSON body") {
            RedactionTimeLimitTests.largeBodies.redact(body: Data(String(repeating: "[", count: 1_000_000).utf8), contentType: "application/json")
        },
        DeepInput(testDescription: "{\"a\": 200,000 times in text") { SensitiveDataRedactor().redact(String(repeating: "{\"a\":", count: 200_000)) },
        DeepInput(testDescription: "a URL in the query value of a URL, 20,000 times, with the value allowed") {
            SensitiveDataRedactor(allowedQueryParameters: ["q"])
                .redact(String(repeating: "https://a.example/?q=", count: 20_000) + "password=\(secret)")
        },
        DeepInput(testDescription: "a URL percent-encoded in a path segment of a URL, 100 times") {
            let url = (0..<100).reduce("password=\(secret)") { inner, _ in
                "https://a.example/" + inner.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
            }
            return SensitiveDataRedactor().redact(url)
        },
        DeepInput(testDescription: "quoted JSON in a form field") {
            let value = quotedSecret(levels: 10, brackets: 255).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
            return SensitiveDataRedactor().redact(body: Data(("note=" + value).utf8), contentType: "application/x-www-form-urlencoded")
        },
        DeepInput(testDescription: "quoted JSON in a plain-text and a JSON multipart part") {
            let content = quotedSecret(levels: 10, brackets: 255)
            let body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n\(content)\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"b\"\r\nContent-Type: application/json\r\n\r\n\(content)\r\n--B--"
            return SensitiveDataRedactor().redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B")
        },
        DeepInput(testDescription: "quoted JSON under a name of a JSON body") {
            let body = "{\"note\":\"" + escaped(quotedSecret(levels: 10, brackets: 255)) + "\"}"
            return SensitiveDataRedactor().redact(body: Data(body.utf8), contentType: "application/json")
        },
    ]

    @Test("no reader recurses without bound", arguments: deepInputs)
    func deepInput(input: DeepInput) {
        let redacted = onThread(stackSize: Self.threadStack, input.redact)
        #expect(!redacted.contains(Self.secret))
    }
}
