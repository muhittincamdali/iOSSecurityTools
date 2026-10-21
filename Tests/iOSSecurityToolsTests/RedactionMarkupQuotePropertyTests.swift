import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated markup and quoted keys in free text: whatever the tag, the quote around it, the
/// markup between the tag and the text and the line breaks in a quoted key, the value never shows
/// on any of the six free-text paths; and text whose `<` is a comparison and whose quotes close
/// on their lines stays as it is.
@Suite("SensitiveDataRedactor markup and quote properties")
struct RedactionMarkupQuotePropertyTests {
    let redactor = SensitiveDataRedactor()

    /// What follows `<` in a tag: a letter of any script, `/`, `!` or `?`.
    static let tagStarts = ["u", "P", "x", "\u{0130}", "\u{0131}", "\u{00E9}", "\u{0436}", "\u{540D}", "\u{03C0}", "/", "!", "?", "![CDATA[", "!--"]
    /// Markup between a tag and its text.
    static let between = ["", "<![CDATA[", "<!-- c -->", "<br/>", "<count/>", "<b>x</b>", "</x>", "<?pi?>", "<!x>", "\n<!-- c -->\n", "< ", "<1>"]
    static let wrappers = [("", ""), ("\"", "\""), ("'", "'"), ("`", "`"), ("\\\"", "\\\""), ("(", ")"), ("[", "]"), ("\"", "")]
    static let prefixes = ["", "msg ", "status=200 ", "user logged in ", "count=3 path=/a ", "a < b and "]

    @Test("no value after a tag shows on any path", arguments: 0..<4)
    func markup(seed: Int) {
        var random = SeededRandom(seed: 0x18_3A00 + UInt64(seed))
        for _ in 0..<150 {
            let value = RedactionPropertyTests.value(using: &random)
            let start = Self.tagStarts.randomElement(using: &random)!
            let name = String((0..<Int.random(in: 0...6, using: &random)).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement(using: &random)! })
            let (open, close) = Self.wrappers.randomElement(using: &random)!
            let element = "<\(start)\(name)>" + Self.between.randomElement(using: &random)! + value + "</\(start)\(name)>"
            let text = Self.prefixes.randomElement(using: &random)! + open + element + close + [" done", "", "\nnext"].randomElement(using: &random)!
            for (path, output) in RedactionCutRuleTests.everyPath(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    static let quotes = ["\"", "'", "`", "\\\""]
    static let lineBreaks = ["\n", "\r\n", "\r", "\n \n"]
    static let separators = [": ", "=", " = ", ":=", "=>", ":\n"]

    @Test("no quoted key with a line break in it shows on any path", arguments: 0..<4)
    func quotedKeys(seed: Int) {
        var random = SeededRandom(seed: 0x18_3B00 + UInt64(seed))
        for _ in 0..<150 {
            let value = RedactionPropertyTests.value(using: &random)
            let quote = Self.quotes.randomElement(using: &random)!
            let lineBreak = Self.lineBreaks.randomElement(using: &random)!
            let words = ["note", "a", "", "status", value].shuffled(using: &random)
            let split = Int.random(in: 0...words.count, using: &random)
            let key = words[..<split].joined(separator: " ") + lineBreak + words[split...].joined(separator: " ")
            let text = Self.prefixes.randomElement(using: &random)! + quote + key + quote + Self.separators.randomElement(using: &random)! + "1"
            for (path, output) in RedactionCutRuleTests.everyPath(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("comparisons and quotes that close on their lines keep the text")
    func plainTextStays() {
        var random = SeededRandom(seed: 0x18_3C00)
        let pieces = [
            "a < b", "count < 10", "1<2", "<3", "x << 1", "a <- b", "say \"hi there\"", "'quoted' word", "`cmd` ran", "don't", "we're",
            "status=200", "method=GET", "done", "ok", "\"a \\\" b\"",
        ]
        for _ in 0..<300 {
            let lines = (0..<Int.random(in: 1...3, using: &random)).map { _ in
                (0..<Int.random(in: 1...4, using: &random)).map { _ in pieces.randomElement(using: &random)! }.joined(separator: " ")
            }
            let text = lines.joined(separator: "\n")
            #expect(redactor.redact(text) == text, "\(text.debugDescription)")
        }
    }
}
