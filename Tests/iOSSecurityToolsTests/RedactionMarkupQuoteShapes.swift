import Foundation
import iOSSecurityTools

/// A megabyte of free text of `<` and quotes, timed and measured as the other shapes are. Quotes
/// and brackets are read in one pass of their own, which keeps two positions: the seventeenth
/// review's shapes of quotes and escaped quotes (a quote before a megabyte of escaped ones, a
/// megabyte of backslash runs before quotes, quotes of every style) and comparisons, whose `<`
/// starts no markup, are read in time and memory linear in the text, also with every offset of the
/// scanning copy kept (`ﬁ` before them).
enum MarkupQuoteShapes {
    private static func lines(_ line: String) -> String {
        String(repeating: line, count: max(1, RedactionTimeLimitTests.size / line.utf8.count))
    }

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let shapes: [(String, @Sendable () -> String)] = [
            ("a quote before a megabyte of escaped quotes", { "\"" + lines("\\\" a ") }),
            ("an escaped quote before a megabyte of quotes", { "\\\"" + lines("\" a ") }),
            ("backslash runs before quotes", { lines(String(repeating: "\\", count: 200) + "\" ") }),
            ("quotes of every style", { lines("\"a\" 'b' `c` ") }),
            ("quotes of every style, every offset kept", { "\u{FB01}" + lines("\u{FB01}\"a\" 'b' `c` ") }),
            ("a quote that closes on the last line", { "\"" + lines("ab cd ") + "\"" }),
            ("lines that close their quotes", { lines("msg \"ok\" and 'fine'\n") }),
            ("comparisons", { lines("a < b and 1<2 ") }),
            ("comparisons, every offset kept", { "\u{FB01}" + lines("\u{FB01}a < b and 1<2 ") }),
            ("brackets that close", { lines("(a [b {c}]) ") }),
        ]
        return shapes.map { name, make in TimedInput(testDescription: name, make: make, redact: redactor.redact) }
    }()
}
