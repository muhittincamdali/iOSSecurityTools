import Foundation
import Testing
@testable import iOSSecurityTools

/// The two rules of free text that keep no state while it is read: markup is not parsed, so the
/// first `<` that is not a comparison cuts the text there, whatever follows it; and a quote that
/// does not close on its line cuts the text at the quote. A `<` is a comparison only before an
/// ASCII space, tab or line break, an ASCII digit, `=` or the end of the text. Each is checked on the six paths
/// that read free text (see ``RedactionCutRuleTests/everyPath(_:)``).
@Suite("SensitiveDataRedactor markup and quotes in free text")
struct RedactionMarkupQuoteRuleTests {
    let redactor = SensitiveDataRedactor()
    static let secret = "QZ9WK7RXV"

    static func expectHidden(_ text: String, _ secret: String = secret, sourceLocation: SourceLocation = #_sourceLocation) {
        for (path, output) in RedactionCutRuleTests.everyPath(text) {
            #expect(!output.contains(secret), "\(path): \(text.debugDescription) -> \(output.debugDescription)", sourceLocation: sourceLocation)
        }
    }

    // MARK: Markup

    @Test("the first `<` that is not a comparison cuts the text there", arguments: [
        ("<user>bob</user>", "[redacted]"),
        ("msg <status>ok</status> done", "msg [redacted]"),
        ("closed </user> bob", "closed [redacted]"),
        ("x <!-- note --> bob", "x [redacted]"),
        ("x <![CDATA[bob]]>", "x [redacted]"),
        ("<?xml version=\"1.0\"?><a>bob</a>", "[redacted]"),
        ("<!DOCTYPE html>", "[redacted]"),
        ("status=200 <br/> bob", "status=200 [redacted]"),
        ("Optional<String>(bob)", "Optional[redacted]"),
        ("<\u{0130}sim>bob</\u{0130}sim>", "[redacted]"),
        ("<\u{0436}>bob", "[redacted]"),
        ("msg \"<user>bob</user>\" done", "msg \"[redacted]"),
        ("'<user>bob</user>'", "'[redacted]"),
        // The nineteenth review: a tag name may start with `_` or `:`, and a digit outside ASCII
        // is no digit of a comparison; what follows `<` is never listed.
        ("<_id>bob</_id>", "[redacted]"),
        ("login <_x>bob", "login [redacted]"),
        ("a <_user>bob</_user>", "a [redacted]"),
        ("<_csrf_x>bob</_csrf_x>", "[redacted]"),
        ("<__v>bob</__v>", "[redacted]"),
        ("<_>bob</_>", "[redacted]"),
        ("<:x>bob", "[redacted]"),
        ("<-x>bob", "[redacted]"),
        ("<.x>bob</.x>", "[redacted]"),
        ("login <#x>bob", "login [redacted]"),
        ("login <@x>bob", "login [redacted]"),
        ("login <$x>bob", "login [redacted]"),
        ("login <%x>bob", "login [redacted]"),
        ("<\u{0966}>bob</\u{0966}>", "[redacted]"),
        ("<\u{0E50}>bob</\u{0E50}>", "[redacted]"),
        ("<\u{2070}>bob</\u{2070}>", "[redacted]"),
        ("login <\u{0661}>bob", "login [redacted]"),
        ("msg \"<\" user>bob</user>", "msg \"[redacted]"),
        ("x << 1", "x [redacted]"),
        ("a <- b", "a [redacted]"),
        ("<<<", "[redacted]"),
        ("<>bob", "[redacted]"),
    ])
    func markupCuts(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a `<` before an ASCII space, tab or line break, an ASCII digit, `=` or the end of the text is a comparison", arguments: [
        "a < b", "if count < 10 then", "1<2 ok", "<3 love", "a<", "a <\tb", "a <\nb", "a <\r\nb", "<1x> bob", "a < b > c",
    ])
    func comparisonsStay(input: String) {
        #expect(redactor.redact(input) == input)
        #expect(redactor.redact(body: Data(input.utf8), contentType: "text/plain") == input)
    }

    /// The shapes the review found: element text after other markup, in every path.
    static let nestedShapes = [
        "<user><![CDATA[S]]></user>", "<phone><![CDATA[S]]></phone>", "<user><!-- c -->S</user>", "<user>\n<!-- c -->\nS\n</user>",
        "<user><br/>S</user>", "<user><count/>S</user>", "<address><line/>S</address>", "<user><count>1</count>S</user>",
        "<user><status>ok</status>S</user>", "<user></x>S", "<user><?pi?>S", "<user><!x>S", "<user>< S", "<user><1>S", "<user><_a>S",
        "<_x>S</_x>", "<_user>\nS\n</_user>", "<_x a='1'>S", "<\u{0966}>S</\u{0966}>", "<-x>S", "<.x>S</.x>",
    ]

    static let prefixes = ["", "msg ", "status=200 ", "note: ", "x=1 "]

    @Test("element text after other markup never shows, whatever comes before it", arguments: nestedShapes)
    func nestedMarkup(shape: String) {
        for prefix in Self.prefixes {
            Self.expectHidden(prefix + shape.replacingOccurrences(of: "S", with: Self.secret))
        }
    }

    @Test("element text in quotes never shows, for every quote and prefix", arguments: ["\"", "'", "`", "\\\"", ""])
    func quotedMarkup(quote: String) {
        for prefix in Self.prefixes {
            for tag in ["user", "phone", "status", "count"] {
                for suffix in ["", " done", "\nnext"] {
                    Self.expectHidden("\(prefix)\(quote)<\(tag)>\(Self.secret)</\(tag)>\(quote)\(suffix)")
                }
            }
        }
    }

    @Test("no tag is allowed: allowing a key never shows the text of an element of that name")
    func noTagIsAllowed() {
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["user", "phone"])
        #expect(allowing.redact("user=bob <user>bob</user>") == "user=bob [redacted]")
        #expect(allowing.redact("\"<phone>555</phone>\"") == "\"[redacted]")
    }

    // MARK: Quotes

    @Test("a quote that does not close on its line cuts the text at the quote", arguments: [
        ("say \"hunter2", "say [redacted]"),
        ("say \"hunter2\nnext\" line", "say [redacted]"),
        ("\"note\nQZ9WK7RXV\": 1", "[redacted]"),
        ("status=200 'a\nQZ9WK7RXV': 1", "status=200 [redacted]"),
        ("x `a\nQZ9WK7RXV`: 1", "x [redacted]"),
        ("x \\\"a\nQZ9WK7RXV\\\": 1", "x [redacted]"),
        ("\"note\rQZ9WK7RXV\": 1", "[redacted]"),
        // Where a character outside the safe alphabet cuts the text, a quote still open cuts it at the quote.
        ("x \"a \u{2254} b\" c", "x [redacted]"),
    ])
    func unclosedQuotes(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("quotes that close on their line, apostrophes and escaped quotes keep the text", arguments: [
        "say \"hello world\" done", "msg 'ok' and \"fine\"\nnext \"line\"", "don't stop\nwe're done", "it\\'s ok",
        "\"a \\\" b\" done", "status=200 count=3 `cmd` ran", "{\"status\":\"say \\\"hi\\\"\"} done",
    ])
    func closedQuotesStay(input: String) {
        #expect(redactor.redact(input) == input)
        #expect(redactor.redact(body: Data(input.utf8), contentType: "text/plain") == input)
    }

    @Test("a quoted key with a line break in it never shows, for every quote, line break and separator")
    func lineBreakInQuotedKeys() {
        for quote in ["\"", "'", "`", "\\\""] {
            for lineBreak in ["\n", "\r\n", "\r", "\n\n"] {
                for separator in [": ", "=", " => ", ":= "] {
                    for prefix in ["", "status=200 ", "log ", "a \"b\" "] {
                        let s = Self.secret
                        Self.expectHidden("\(prefix)\(quote)note\(lineBreak)\(s)\(quote)\(separator)1")
                        Self.expectHidden("\(prefix)\(quote)\(s)\(lineBreak)note\(quote)\(separator)1")
                        Self.expectHidden("\(prefix)\(quote)a\(lineBreak)\(quote) \(quote)\(s)\(quote)\(separator)1")
                    }
                }
            }
        }
    }
}
