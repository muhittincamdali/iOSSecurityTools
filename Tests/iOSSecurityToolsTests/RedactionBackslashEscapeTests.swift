import Foundation
import Testing
@testable import iOSSecurityTools

/// The backslash rule of free text: a backslash cuts the text at the start of its word whatever
/// follows it, unless an ASCII space, tab or line break or the end of the text does. No list of
/// the forms of backslash escapes is kept, so a form that no list named (`\x{73}`, `\o{163}`,
/// `\N{…}`, `\q`) cuts the text as `\x3D` does, on every path that reads free text.
@Suite("SensitiveDataRedactor backslash escapes in free text")
struct RedactionBackslashEscapeTests {
    let redactor = SensitiveDataRedactor()

    /// Backslash escapes of C, C++23, Perl, PCRE, Python, JavaScript, CSS, shells and forms that
    /// none of them has.
    static let forms = [
        "\\x{73}", "\\X{73}", "\\o{163}", "\\O{163}", "\\N{LATIN SMALL LETTER S}", "\\N{U+73}", "\\u{73}", "\\u0073", "\\U00000073", "\\x73",
        "\\163", "\\0", "\\73 ", "\\q", "\\s", "\\\\", "\\\"", "\\'", "\\`", "\\=", "\\:", "\\cA", "\\e", "\\p{L}", "\\k<n>", "\\g{1}", "\\/",
        "\\.", "\\-", "\\ä", "\\ı", "\\\u{0301}", "\\\u{200B}", "\\\u{3000}", "\\\u{00A0}", "\\\u{2028}", "\\\u{85}",
    ]

    @Test("a backslash escape of any form cuts a line at the start of its word", arguments: forms)
    func everyFormCuts(form: String) {
        #expect(redactor.redact("login pa" + form + "sword Qx001Np7v") == "login [redacted]")
        #expect(redactor.redact("status=200 " + form + " Qx002Np7v") == "status=200 [redacted]")
        #expect(redactor.redact("done " + form) == "done [redacted]")
    }

    @Test("a backslash escape of any form cuts the text on every path", arguments: forms)
    func everyFormCutsOnEveryPath(form: String) {
        let value = "Qx003Np7vZ"
        for (path, output) in RedactionCutRuleTests.everyPath("login pa" + form + "sword " + value) {
            #expect(!output.contains(value), "\(path): \(form.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a backslash before an ASCII space, tab or line break, or at the end, keeps the text", arguments: [
        "a \\ b done", "a\\\tb done", "end \\\nnext line", "end \\\r\nnext line", "line ends in \\", "two \\ \\ done",
    ])
    func blanksAfterABackslashKeepTheText(text: String) {
        #expect(redactor.redact(text) == text)
        #expect(redactor.redact(body: Data(text.utf8), contentType: "text/plain") == text)
    }

    /// The fault of the twentieth review: braced escapes, which the list of forms left out.
    @Test("a secret name written with a braced escape hides the value after it", arguments: [
        "login pa\\x{73}sword Qx004Np7v", "pa\\o{163}sword Qx004Np7v", "\\x{70}\\x{69}\\x{6e} Qx004Np7v", "to\\x{6B}en: Qx004Np7v",
        "{\"msg\":\"pa\\\\x{73}sword Qx004Np7v\"}", "pa\\N{LATIN SMALL LETTER S}sword Qx004Np7v",
    ])
    func bracedEscapes(text: String) {
        #expect(!redactor.redact(text).contains("Qx004N"))
        #expect(!redactor.redact(body: Data(text.utf8), contentType: "text/plain").contains("Qx004N"))
    }

    /// Hiding a Windows path or a regular expression in free text is part of the rule: what
    /// follows a backslash is never read.
    @Test("text with a Windows path or a regular expression is cut at the backslash's word")
    func overHidingIsByDesign() {
        #expect(redactor.redact("copied to \\\\nas\\backup ok") == "copied to [redacted]")
        #expect(redactor.redact("saved to C:\\Users\\ayse\\notes.txt") == "saved to C:[redacted]")
        #expect(redactor.redact("pattern ^\\d+$ matched") == "pattern [redacted]")
    }

    @Test("a backslash before a character of any general category cuts the text on every path, unless it is ASCII white space", arguments: 0..<4)
    func backslashBeforeEveryCategory(seed: Int) {
        var random = SeededRandom(seed: 0x21_5C00 + UInt64(seed))
        let blanks = Set(" \t\n\r".unicodeScalars)
        #expect(RedactionMarkupQuotePropertyTests.scalarsByCategory.count == 29)
        for (category, scalars) in RedactionMarkupQuotePropertyTests.scalarsByCategory {
            for _ in 0..<4 {
                let scalar = scalars.randomElement(using: &random)!
                guard !blanks.contains(scalar) else { continue }
                let value = RedactionPropertyTests.value(using: &random)
                let before = ["", "pa", "x", "status=", "to"].randomElement(using: &random)!
                let after = ["", "sword", "{73}sword", "ken", "word"].randomElement(using: &random)!
                let separator = [" ", "=", ": ", "\n", " \"", "\t"].randomElement(using: &random)!
                let text = RedactionMarkupQuotePropertyTests.prefixes.randomElement(using: &random)! + before + "\\" + String(scalar) + after + separator
                    + value + ["", " done", "\nnext"].randomElement(using: &random)!
                for (path, output) in RedactionCutRuleTests.everyPath(text) {
                    #expect(!RedactionPropertyTests.leaks(value, in: output), "\(category) \(path): \(text.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }
}
