import Foundation
import iOSSecurityTools

/// The shapes the thirteenth review measured: long single words of free text, which the reading
/// of a word copied whole, and bodies of many small values, which their trees and fields held
/// several times over. Free text is made a megabyte long; bodies `size` bytes long, as large as
/// the redactor that reads them takes.
enum ThirteenthReviewShapes {
    private static let redactor = SensitiveDataRedactor()

    private static func repeated(_ unit: String, to total: Int, prefix: String = "") -> String {
        prefix + String(repeating: unit, count: max(1, (total - prefix.utf8.count) / unit.utf8.count))
    }

    private static func base64Word(_ bytes: Int) -> String {
        var data = Data(count: bytes * 3 / 4)
        data.withUnsafeMutableBytes { raw in
            for i in 0..<raw.count { raw[i] = UInt8(truncatingIfNeeded: i &* 2_654_435_761 >> 7) }
        }
        return data.base64EncodedString()
    }

    private static func deep(_ depth: Int, _ length: Int) -> String {
        String(repeating: "[", count: depth) + "\"" + String(repeating: "a", count: max(1, length - 2 * depth - 2)) + "\""
            + String(repeating: "]", count: depth)
    }

    /// A megabyte of free text in each shape.
    static let text: [TimedInput] = {
        let size = RedactionTimeLimitTests.size
        let shapes: [(String, @Sendable () -> String)] = [
            ("one word of a", { String(repeating: "a", count: size) }),
            ("one base64 word", { base64Word(size) }),
            ("one base64 word after status=", { "status=" + base64Word(size - 7) }),
            ("one word of %2570", { repeated("%2570", to: size) }),
            ("one word of backslashes", { repeated("\\\\", to: size) }),
            ("one word of &#97;", { repeated("&#97;", to: size) }),
            ("one word of \\u0070", { repeated("\\u0070", to: size) }),
            ("one word of %41", { repeated("%41", to: size) }),
            ("words of 1,000 letters", { repeated(String(repeating: "x", count: 999) + " ", to: size) }),
            ("log lines of allowed keys", { repeated("2026-10-20T10:00:00Z INFO GET /api/v1/items status=200 duration_ms=12 count=3\n", to: size) }),
            ("one word of 42-", { repeated("42-", to: size) }),
            ("one word of %25", { repeated("%25", to: size) }),
            ("card digits 4242 with spaces", { repeated("4242 ", to: size) }),
            ("one word of &#61;", { repeated("&#61;", to: size) }),
            ("one hex dump word", { repeated("0123456789abcdef", to: size) }),
            ("a look-alike separator after every key", { repeated("user\u{A789} v ", to: size) }),
            ("a line separator after every word", { repeated("status\u{2028}", to: size) }),
        ]
        return shapes.map { TimedInput(testDescription: "text: " + $0.0, make: $0.1, redact: redactor.redact) }
    }()

    /// The bodies of the review, `size` bytes long, read by `redactor`.
    static func bodies(size: Int, redactor: SensitiveDataRedactor) -> [TimedInput] {
        func body(_ type: String) -> @Sendable (String) -> String { { redactor.redact(body: Data($0.utf8), contentType: type) } }
        let json = body("application/json")
        let form = body("application/x-www-form-urlencoded")
        let shapes: [(String, @Sendable () -> String, @Sendable (String) -> String)] = [
            ("a plain-text base64 word", { base64Word(size) }, body("text/plain")),
            ("JSON subtrees 63 deep", { "[" + Array(repeating: deep(62, 200), count: size / 201).joined(separator: ",") + "]" }, json),
            ("JSON subtrees 8 deep", { "[" + Array(repeating: deep(8, 40), count: size / 41).joined(separator: ",") + "]" }, json),
            ("a JSON array of 1s", { "[" + Array(repeating: "1", count: size / 2).joined(separator: ",") + "]" }, json),
            ("a JSON array of empty arrays", { "[" + Array(repeating: "[]", count: size / 3).joined(separator: ",") + "]" }, json),
            ("a JSON array of empty objects", { "[" + Array(repeating: "{}", count: size / 3).joined(separator: ",") + "]" }, json),
            ("a JSON object of distinct keys", {
                "{" + (0..<(size / 21)).map { "\"key_\(String($0, radix: 36))x\":\"v\($0)\"" }.joined(separator: ",") + "}"
            }, json),
            ("a JSON string of allowed text", { "{\"m\":\"" + repeated("status=200 count=3 ", to: size - 20) + "\"}" }, json),
            ("a JSON string of base64", { "{\"m\":\"" + base64Word(size - 20) + "\"}" }, json),
            ("a JSON array of objects", {
                "[" + (0..<(size / 90)).map { "{\"id\":\($0),\"title\":\"Item number \($0)\",\"price\":\($0).99,\"tags\":[\"a\",\"b\"],\"active\":true}" }
                    .joined(separator: ",") + "]"
            }, json),
            ("a form of distinct names", { (0..<(size / 9)).map { "f\($0)=v" }.joined(separator: "&") }, form),
            ("a form of one field repeated", { Array(repeating: "a=1", count: size / 4).joined(separator: "&") }, form),
            ("JSON subtrees 60 deep", { "[" + Array(repeating: deep(60, 400), count: size / 401).joined(separator: ",") + "]" }, json),
        ]
        return shapes.map { TimedInput(testDescription: "body: " + $0.0, make: $0.1, redact: $0.2) }
    }
}
