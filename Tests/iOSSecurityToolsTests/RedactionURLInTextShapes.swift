import Foundation
import iOSSecurityTools

/// A megabyte of free text full of URLs, which the clean-URL rule reads one at a time: lines of
/// clean URLs, with identifiers in their paths and with as many segments as a word may hold, the
/// shortest URLs there are, and URLs that are not clean, which cut the text at the first. Each
/// clean URL is parsed once, by ``SensitiveDataRedactor/redact(url:)``'s rules.
enum URLInTextShapes {
    private static func lines(_ line: String, separator: String = "\n") -> String {
        String(repeating: line + separator, count: max(1, RedactionTimeLimitTests.size / (line.utf8.count + separator.utf8.count)))
    }

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let shapes: [(String, @Sendable () -> String)] = [
            ("lines of clean URLs", { lines("GET https://api.example.com/v1/items/42 200") }),
            ("lines of clean URLs with identifiers", { lines("GET https://api.example.com/users/12345678/orders/550e8400-e29b-41d4-a716-446655440000 200") }),
            ("lines of clean URLs of 64 segments", { lines("see https://a.example" + String(repeating: "/ab", count: SensitiveDataRedactor.maximumPathSegments)) }),
            ("URLs of a one-letter host", { lines("a://b", separator: " ") }),
            ("URLs in a sentence", { lines("see https://x.example/docs/a.", separator: " ") }),
            ("URLs with a character outside the safe alphabet and a query", { lines("https://x.example/a\u{2192}b?q=1", separator: " ") }),
        ]
        return shapes.map { name, make in TimedInput(testDescription: name, make: make, redact: redactor.redact) }
    }()
}
