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

    /// What follows `<` in a tag: a letter of any script, `_`, `:`, `/`, `!`, `?`, other
    /// punctuation, a digit outside ASCII.
    static let tagStarts = [
        "u", "P", "x", "\u{0130}", "\u{0131}", "\u{00E9}", "\u{0436}", "\u{540D}", "\u{03C0}", "/", "!", "?", "![CDATA[", "!--", "_", "__", ":",
        "-", ".", "#", "@", "$", "%", "\u{0966}", "\u{0661}", "\u{2070}", "\u{0E50}",
    ]
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

    /// The scalars of the first four planes and of the tag, variation selector and private use
    /// ranges after them, by general category.
    static let scalarsByCategory: [(category: String, scalars: [Unicode.Scalar])] = {
        var found: [String: [Unicode.Scalar]] = [:]
        for value in Array(0...0x3FFFF) + Array(0xE0000...0xE01EF) + Array(0xF0000...0xF00FF) {
            guard let scalar = Unicode.Scalar(UInt32(value)) else { continue }
            found["\(scalar.properties.generalCategory)", default: []].append(scalar)
        }
        return found.keys.sorted().map { ($0, found[$0]!) }
    }()

    /// Whether `<` before a scalar is a comparison: an ASCII space, tab, line feed, carriage
    /// return or digit, or `=`.
    static func isComparison(_ scalar: Unicode.Scalar) -> Bool {
        scalar.isASCII && " \t\n\r0123456789=".unicodeScalars.contains(scalar)
    }

    @Test("a `<` before a character of any general category cuts the text on every path, unless it is a comparison", arguments: 0..<4)
    func lessThanBeforeEveryCategory(seed: Int) {
        var random = SeededRandom(seed: 0x19_3D00 + UInt64(seed))
        // Every category but the surrogates, which are no scalars.
        #expect(Self.scalarsByCategory.count == 29)
        for (category, scalars) in Self.scalarsByCategory {
            for _ in 0..<4 {
                let scalar = scalars.randomElement(using: &random)!
                guard !Self.isComparison(scalar) else { continue }
                let value = RedactionPropertyTests.value(using: &random)
                let name = ["", "x", "_id", "user"].randomElement(using: &random)!
                let text = Self.prefixes.randomElement(using: &random)! + "<" + String(scalar) + name + ">" + value
                    + ["", " done", "\nnext", "</\(name)>"].randomElement(using: &random)!
                for (path, output) in RedactionCutRuleTests.everyPath(text) {
                    #expect(!RedactionPropertyTests.leaks(value, in: output), "\(category) \(path): \(text.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    @Test("a `<` before an ASCII space, tab, line break, digit or the end of the text keeps the text")
    func comparisonsKeepTheText() {
        let redactor = SensitiveDataRedactor()
        for follower in " \t\n\r0123456789".unicodeScalars {
            let text = "count <" + String(follower) + "5 ok"
            #expect(redactor.redact(text) == text, "\(text.debugDescription)")
        }
        #expect(redactor.redact("count <") == "count <")
        // `<=` is a comparison, not markup, and `=` with no key before it is a separator.
        #expect(redactor.redact("count <=5 ok") == "count <=[redacted]")
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
            "a < b", "count < 10", "1<2", "<3", "count <5", "a <\tb", "say \"hi there\"", "'quoted' word", "`cmd` ran", "don't", "we're",
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
