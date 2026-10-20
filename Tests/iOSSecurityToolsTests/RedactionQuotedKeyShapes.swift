import Foundation
import iOSSecurityTools

/// A megabyte of free text held by quoted keys, as the sixteenth review measured it: a key that
/// takes the whole text, one inside another, and lines of keys that are allowed and that are not.
/// A `ﬁ` before them makes the scanning copy keep the offset of every byte, its largest form. The
/// reading of quoted keys that 2.1.0 had before copied each key longer than a word and made a
/// scanning copy of it, also of a key inside it: 17 MB for a key of a megabyte and 26 MB for one
/// inside another, with every offset kept. A quoted key is now compared where it is in the text,
/// so none is copied.
enum QuotedKeyShapes {
    private static func prose() -> String { String(repeating: "ab cd ", count: RedactionTimeLimitTests.size / 6) }

    private static func lines(_ line: String) -> String {
        String(repeating: line, count: max(1, RedactionTimeLimitTests.size / line.utf8.count))
    }

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let shapes: [(String, @Sendable () -> String)] = [
            ("one quoted key of a megabyte", { "\"" + prose() + "\": 1" }),
            ("one quoted key of a megabyte, every offset kept", { "\u{FB01}\"\u{FB01}" + prose() + "\": 1" }),
            ("a quoted key in a quoted key of a megabyte", { "\"\\\"" + prose() + "\\\":1\": 2" }),
            ("a quoted key in a quoted key of a megabyte, every offset kept", { "\u{FB01}\"\u{FB01}\\\"\u{FB01}" + prose() + "\\\":1\": 2" }),
            ("lines of allowed quoted keys", { lines("\"status\": \"ok\", \"count\": 3\n") }),
            ("lines of quoted keys in brackets", { lines("\"(status\": 1, ") }),
            ("lines of escaped quoted keys in quoted text", { lines("\"\\\"status\\\":1 \" ok, ") }),
        ]
        return shapes.map { name, make in TimedInput(testDescription: name, make: make, redact: redactor.redact) }
    }()
}
