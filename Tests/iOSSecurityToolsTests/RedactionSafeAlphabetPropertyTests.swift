import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated input for the rules of free text that replace every list of variants: the safe
/// alphabet, escapes and opaque words. Whatever the character, the escape or the word, no value
/// after it shows on any path that reads free text, and text written in the safe alphabet without
/// a trigger stays as it is.
@Suite("SensitiveDataRedactor safe alphabet properties")
struct RedactionSafeAlphabetPropertyTests {
    /// Every scalar outside the safe alphabet in the planes text is written in: punctuation,
    /// symbols, spaces and separators outside ASCII, control and format characters, private use
    /// and unassigned code points, and every default-ignorable code point, letters among them
    /// (U+3164). Modifier letters are left out: after ASCII they cut, after other letters not.
    static let unsafeScalars: [Unicode.Scalar] = {
        var scalars: [Unicode.Scalar] = (0x00...0x1F).compactMap(Unicode.Scalar.init).filter { !"\t\n\r".unicodeScalars.contains($0) }
        scalars.append("\u{7F}")
        for value in Array(0x80...0xFFFF) + Array(0x1F000...0x1FAFF) + Array(0xE0000...0xE007F) {
            guard let scalar = Unicode.Scalar(UInt32(value)), scalar.properties.generalCategory != .modifierLetter else { continue }
            if FreeTextScanner.firstUnsafeOffset(in: [scalar]) == 0 { scalars.append(scalar) }
        }
        return scalars
    }()

    static let unsafeLayouts: [@Sendable (String, String, String) -> String] = [
        { key, unsafe, value in key + unsafe + value },
        { key, unsafe, value in key + unsafe + " " + value },
        { key, unsafe, value in key + unsafe + "\n" + value },
        { key, unsafe, value in key + " " + unsafe + "\n" + value },
        { key, unsafe, value in key + unsafe + "\t\"" + value + "\"" },
        { key, unsafe, value in "[INFO] " + key + unsafe + " " + value + " done" },
        { key, unsafe, value in "'" + key + "'" + unsafe + " '" + value + "'" },
        { key, unsafe, value in "status=200 " + key + unsafe + value },
        { key, unsafe, value in key + "=" + unsafe + value },
        { key, unsafe, value in unsafe + key + "=" + value },
        // Inside a URL, which never runs past the character: the text is cut where it starts.
        { key, unsafe, value in key + " https://x.example/a" + unsafe + "b/" + value + "?q=1 tail" },
        { key, unsafe, value in key + " https://x.example/a" + unsafe + "b/" + value + " tail" },
        { key, unsafe, value in "path=https://x.example/" + unsafe + "/" + value + " " + key },
        { key, unsafe, value in key + " https://x.example/" + value + unsafe },
    ]

    static let keys = ["user", "status", "note", "x", "db_host", "Error", "count", "card_holder", "msg"]

    @Test("the safe alphabet lists every kind of character it leaves out")
    func unsafeScalarsCoverEveryKind() {
        let categories = Set(Self.unsafeScalars.map { "\($0.properties.generalCategory)" })
        for category in ["otherPunctuation", "mathSymbol", "modifierSymbol", "otherSymbol", "spaceSeparator", "lineSeparator", "control", "format",
                         "dashPunctuation", "currencySymbol", "privateUse", "unassigned"] {
            #expect(categories.contains(category), "\(category)")
        }
        #expect(Self.unsafeScalars.count > 10_000)
        for scalar in "\u{A789}\u{2254}\u{2192}\u{00B7}\u{2236}\u{0589}\u{05C3}\u{205A}\u{02F8}\u{2982}\u{1804}\u{21D2}\u{27F6}\u{2255}\u{2261}\u{2237}\u{22EE}\u{A78A}\u{1361}\u{16EC}\u{0703}\u{2E33}".unicodeScalars {
            #expect(Self.unsafeScalars.contains(scalar), "\(scalar.value)")
        }
    }

    @Test("no value after a character outside the safe alphabet shows, on any path that reads free text", arguments: 0..<4)
    func unsafeCharactersCut(seed: Int) {
        var random = SeededRandom(seed: 0x5AFE_0000 + UInt64(seed))
        for _ in 0..<250 {
            let unsafe = String(Self.unsafeScalars.randomElement(using: &random)!)
            let value = RedactionPropertyTests.value(using: &random)
            let text = Self.unsafeLayouts.randomElement(using: &random)!(Self.keys.randomElement(using: &random)!, unsafe, value)
            for (path, output) in RedactionCutRuleTests.everyPath(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    /// Escapes of `=`, `:` and of letters, as URLs, HTML, C, JavaScript, CSS, Python and MIME
    /// write them.
    static let escapes = [
        "%3D", "%3d", "%3A", "%u003D", "%U003a", "%253D", "%25253A", "&#61;", "&#61", "&#x3D;", "&#X3d", "&#0000061;", "&equals;", "&colon;",
        "&Colon;", "&coloneq;", "&amp;#61;", "&amp;equals;", "&nbsp;", "&lt;", "\\075", "\\072", "\\75", "\\x3D", "\\x3a", "\\u003D", "\\u{3D}",
        "\\U0000003D", "\\N{EQUALS SIGN}", "\\3D", "\\3a ", "\\\\u003D", "%E2%80%8B", "%70",
    ]

    static let escapeLayouts: [@Sendable (String, String, String) -> String] = [
        { key, escape, value in key + escape + value },
        { key, escape, value in key + escape + " " + value },
        { key, escape, value in "login " + key + escape + "\n" + value },
        { key, escape, value in String(key.prefix(2)) + escape + String(key.dropFirst(2)) + "=" + value },
        { key, escape, value in key + "=" + escape + value },
        { key, escape, value in "status=200&" + key + escape + value },
        { key, escape, value in "msg: \"" + key + escape + value + "\"" },
        // At the end of a URL, inside it and in its query.
        { key, escape, value in "see https://x.example/" + key + escape + " " + value },
        { key, escape, value in "see https://x.example/a/" + key + escape + value + " tail" },
        { key, escape, value in "see https://x.example/a?q=" + key + escape + " " + value },
    ]

    @Test("no value after an escape shows, on any path that reads free text", arguments: 0..<4)
    func escapesCut(seed: Int) {
        var random = SeededRandom(seed: 0xE5CA_0000 + UInt64(seed))
        for _ in 0..<250 {
            let value = RedactionPropertyTests.value(using: &random)
            let key = Self.keys.randomElement(using: &random)!
            let text = Self.escapeLayouts.randomElement(using: &random)!(key, Self.escapes.randomElement(using: &random)!, value)
            for (path, output) in RedactionCutRuleTests.everyPath(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("an escape cuts the text at the start of the word it is in, never later")
    func escapesCutAtTheirWord() {
        let redactor = SensitiveDataRedactor()
        for escape in Self.escapes {
            let output = redactor.redact("ok user" + escape + "bob tail")
            #expect(output == "ok [redacted]", "\(escape.debugDescription) -> \(output.debugDescription)")
        }
        #expect(redactor.redact("contact Qz384Wk7r%40example.com") == "contact [redacted]")
        #expect(redactor.redact("contact alice&commat;example.com") == "contact [redacted]")
        #expect(redactor.redact("count=50% done & more") == "count=50% done & more")
        #expect(redactor.redact("count=50% done &more") == "count=50% done [redacted]")
        #expect(redactor.redact("status=200&count=3 R&D") == "status=200&count=3 [redacted]")
    }

    @Test("no value after a word longer than 256 scalars shows, and no such word is read", arguments: [257, 300, 4_096, 100_000])
    func opaqueWordsCut(length: Int) {
        var random = SeededRandom(seed: 0x0A9E_0000 + UInt64(length))
        let redactor = SensitiveDataRedactor()
        for unit in ["a", "ab1", "\u{0131}", "a\u{0301}", "%41", "\\\\", "4242-", "x=", "password"] {
            let word = String(String(repeating: unit, count: length / unit.unicodeScalars.count + 1).unicodeScalars.prefix(length))
            let value = RedactionPropertyTests.value(using: &random)
            let text = "ok " + word + " " + value
            let output = redactor.redact(text)
            #expect(output.hasPrefix("ok "), "\(unit.debugDescription)")
            #expect(!RedactionPropertyTests.leaks(value, in: output), "\(unit.debugDescription) x \(length) -> \(output.prefix(80).debugDescription)")
        }
        // `g` is no hex digit, so no run of it is a long token.
        let longest = String(repeating: "g", count: FreeTextScanner.longestWord)
        #expect(redactor.redact("ok " + longest + " done") == "ok " + longest + " done")
        #expect(redactor.redact("ok " + longest + "g done") == "ok [redacted]")
    }

    /// Letters, marks and digits of several scripts, and ASCII punctuation that is neither a
    /// separator nor the start of an escape. A word in another script is read as letters that
    /// may stand for any one letter of a secret word, so no ASCII word here completes one
    /// (`東京 in` reads as `pin`).
    static let safeWords = [
        "Kullanıcı", "giriş", "yaptı", "Straße", "naïve", "заказ", "отправлен", "東京", "ログイン", "成功", "ユーザー", "ภาษาไทยๆ", "١٢٣", "e\u{0301}te\u{0301}",
        "request", "finished", "12", "ms", "GET", "/api/items", "(3 items)", "done.", "ok!", "why?", "a-b", "x/y", "#42", "[INFO]", "50%",
        "don't", "a,", "b;", "@home", "~/x", "*", "+1",
    ]

    @Test("text in the safe alphabet without a trigger stays as it is, on every path that reads it whole")
    func safeTextStays() {
        var random = SeededRandom(seed: 0x5AFE_0100)
        for _ in 0..<1_000 {
            let words = (0..<Int.random(in: 1...12, using: &random)).map { _ in Self.safeWords.randomElement(using: &random)! }
            let pairs = ["status=200", "method=GET", "path=/v1/items", "duration_ms=12", "count=3"].shuffled(using: &random).prefix(Int.random(in: 0...3, using: &random))
            var text = (words + pairs).shuffled(using: &random).joined(separator: [" ", " ", "\n", "\t", "  "].randomElement(using: &random)!)
            if Int.random(in: 0..<4, using: &random) == 0 { text += "\r\n" }
            for (path, output) in RedactionCutRuleTests.everyPath(text) where path == "line" || path == "text/plain" {
                #expect(output == text, "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }
}
