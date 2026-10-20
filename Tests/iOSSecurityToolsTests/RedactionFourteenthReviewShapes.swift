import Foundation
import iOSSecurityTools

/// The fourteenth review's shapes of a megabyte of free text: log lines of short JSON, whose
/// parsed trees `JSONSerialization` autoreleased and kept until the end of the redaction (19 MB
/// more for a megabyte), JSON quoted in JSON up to three levels, and lines of URLs whose
/// parameters are all allowed, which are read whole and keep the text after them.
enum FourteenthReviewShapes {
    private static func lines(_ line: String) -> String {
        String(repeating: line + "\n", count: max(1, RedactionTimeLimitTests.size / (line.utf8.count + 1)))
    }

    /// `{"status":"…"}` around a JSON text, its quotes and backslashes escaped, `levels` times.
    static func quoted(_ json: String, levels: Int) -> String {
        var text = json
        for _ in 0..<levels {
            text = #"{"status":""# + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + #""}"#
        }
        return text
    }

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let pages = SensitiveDataRedactor(allowedQueryParameters: ["page", "sort"])
        let shapes: [(String, @Sendable () -> String, @Sendable (String) -> String)] = [
            ("lines of [1]", { lines("[1]") }, redactor.redact),
            (#"lines of {"count":1}"#, { lines(#"{"count":1}"#) }, redactor.redact),
            (#"lines of {"count":1} quoted once"#, { lines(quoted(#"{"count":1}"#, levels: 1)) }, redactor.redact),
            (#"lines of {"count":1} quoted three times"#, { lines(quoted(#"{"count":1}"#, levels: 3)) }, redactor.redact),
            ("lines of URLs whose parameters are allowed", { lines("GET https://x.example/a/b?page=2&sort=name status=200") }, pages.redact),
            ("lines of times and addresses", { lines("12:30:45 10.0.0.1:8080 2026-10-19T12:30:45Z") }, redactor.redact),
        ]
        return shapes.map { name, make, redact in TimedInput(testDescription: name, make: make, redact: redact) }
    }()
}
