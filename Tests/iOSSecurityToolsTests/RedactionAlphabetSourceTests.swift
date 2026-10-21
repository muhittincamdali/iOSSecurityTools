import Foundation
import Testing
@testable import iOSSecurityTools

/// The safe alphabet is decided on the text the scanner reads. A letter or number whose
/// compatibility form holds punctuation, a space or a symbol (`🄁` is `0,`, `⒈` is `1.`, `⑴` is
/// `(1)`) cuts free text where it stands, and a quote glued to the word before it is not the start
/// of a quoted key. So no scalar put before or into an allowed key shows the value after it.
@Suite("SensitiveDataRedactor safe alphabet from one source")
struct RedactionAlphabetSourceTests {
    let redactor = SensitiveDataRedactor()

    /// Every scalar outside ASCII from U+0080 to U+3FFFF.
    static let scalars: [Unicode.Scalar] = (UInt32(0x80)...UInt32(0x3FFFF)).compactMap(Unicode.Scalar.init)

    /// Where a scalar is put into or before the allowed key `status`.
    static let layouts: [String] = ["{s}status=X", "x{s}status=X", "{s}\"status\": \"X\"", "\"{s}status\": X", "status{s}=X"]

    @Test("no scalar outside ASCII before or in an allowed key shows its value", arguments: layouts)
    func noScalarShowsTheValue(layout: String) {
        let redactor = SensitiveDataRedactor()
        let value = "Qz9Wv41ue7"
        var shown: [String] = []
        for scalar in Self.scalars {
            let text = layout.replacingOccurrences(of: "{s}", with: String(scalar)).replacingOccurrences(of: "X", with: value)
            if redactor.redact(text).contains(value) { shown.append(String(format: "U+%04X", scalar.value)) }
        }
        #expect(shown.isEmpty, "\(shown.count) scalars show the value: \(shown.prefix(20))")
    }

    @Test("a scalar the scanner reads as letters and digits only is in the alphabet, any other letter or number is not")
    func theAlphabetIsDecidedOnTheScannersReading() {
        let compatibility = CompatibilityText()
        var mismatches: [String] = []
        for scalar in Self.scalars {
            let text = NormalizedText([scalar], compatibility: compatibility)
            // The scanning copy and the alphabet read the scalar the same way.
            if text.firstUnsafeOffset != FreeTextScanner.firstUnsafeOffset(in: [scalar]) { mismatches.append(String(format: "U+%04X differs", scalar.value)) }
            guard text.firstUnsafeOffset == nil else { continue }
            // A scalar in the alphabet is never read as ASCII punctuation, a space or a line break.
            if text.bytes.contains(where: { $0 < 0x80 && !ASCII.isAlphanumeric($0) }) { mismatches.append(String(format: "U+%04X reads %@", scalar.value, text.string(0..<text.count))) }
        }
        #expect(mismatches.isEmpty, "\(mismatches.prefix(20))")
    }

    @Test("a letter or number with punctuation, a space or a symbol in its compatibility form cuts the text", arguments: [
        "\u{1F101}", "\u{1F10A}", "\u{2488}", "\u{249B}", "\u{2474}", "\u{2487}", "\u{00BD}", "\u{2153}", "\u{0149}", "\u{FDFA}", "\u{FE70}", "\u{3250}",
    ])
    func compatibilityPunctuationCuts(scalar: String) {
        #expect(redactor.redact("note " + scalar + " Qz9W1x") == "note [redacted]")
        #expect(redactor.redact(scalar + "status=Qz9W1x") == "[redacted]")
    }

    @Test("letters and numbers whose compatibility form is letters and digits stay", arguments: [
        "Kullanıcı giriş yaptı", "ﬁle saved", "step ① done", "chapter Ⅻ", "x² y³", "Ⅳ ok", "ＡＢＣ ok", "ayşe.yılmaz geldi", "東京 ok", "한국어 ok",
    ])
    func compatibilityLettersStay(text: String) {
        #expect(redactor.redact(text) == text)
    }

    @Test("a quote glued to a word is no quoted key", arguments: [
        ("x\"status\": \"Qz9W\"", "[redacted]"), ("À\"status\": 200", "[redacted]"), ("ok\"status\"= 200", "[redacted]"),
        ("a \u{0301}\"status\": 200", "a [redacted]"), ("\u{0300}\"status\": 1", "[redacted]"),
    ])
    func gluedQuotes(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a quoted allowed key after white space, a bracket or a comma stays", arguments: [
        "\"status\": 200 ok", "a \"status\": 200", "(\"status\": 200)", "[\"status\", 1]", "x,\"status\": 1", "{\"status\": 200} ok",
    ])
    func quotedKeysStay(text: String) {
        #expect(redactor.redact(text) == text)
    }
}
