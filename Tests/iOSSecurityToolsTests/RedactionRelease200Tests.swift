import Foundation
import Testing
@testable import iOSSecurityTools

/// The value-detector tests of release 2.0.0, unchanged, with the kinds 2.0.0 had: the detectors
/// alone give 2.0.0's output, and with every kind the values 2.0.0 hid stay hidden. The key rule
/// of 2.1.0 hides more in free text (`order 1234 card …` hides the rest after `card`), so with
/// every kind only what was hidden is compared, never what was shown.
@Suite("SensitiveDataRedactor detectors of release 2.0.0")
struct RedactionRelease200Tests {
    static let detectorKinds: SensitiveDataRedactor.Kinds = [.cardNumbers, .emailAddresses, .jsonWebTokens, .bearerTokens]
    let detectors = SensitiveDataRedactor(kinds: detectorKinds)
    let redactor = SensitiveDataRedactor()

    static let signed = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    /// 2.0.0's inputs and outputs, and the part of each input that its output hid.
    static let masked: [(input: String, expected: String, hidden: String)] = [
        ("paid with 4242424242424242 today", "paid with •••• 4242 today", "424242424242"),
        ("card 4242 4242 4242 4242.", "card •••• 4242.", "4242 4242 4242"),
        ("card 4242-4242-4242-4242", "card •••• 4242", "4242-4242-4242"),
        ("amex 3782 822463 10005", "amex •••• 0005", "822463"),
        ("order 1234 card 4242 4242 4242 4242 cvv 123", "order 1234 card •••• 4242 cvv 123", "4242 4242 4242"),
        ("order 98 4242 4242 4242 4242", "order 98 •••• 4242", "4242 4242 4242"),
        ("fullwidth ４２４２４２４２４２４２４２４２", "fullwidth •••• 4242", "４２４２４２４２"),
        ("zero width 4242\u{200B}4242\u{200B}4242\u{200B}4242", "zero width •••• 4242", "4242\u{200B}4242\u{200B}4242"),
        ("combining 4\u{301}242424242424242", "combining •••• 4242", "242424242424"),
        ("nbsp 4242\u{A0}4242\u{A0}4242\u{A0}4242", "nbsp •••• 4242", "4242\u{A0}4242\u{A0}4242"),
        ("contact alice@example.com.", "contact a•••@example.com.", "lice"),
        ("<bob.smith+news@mail.example.org>", "<b•••@mail.example.org>", "ob.smith"),
        ("fullwidth ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "fullwidth a•••@example.com", "ｌｉｃｅ"),
        ("hidden al\u{200D}ice@example.com", "hidden a•••@example.com", "ice"),
        ("token \(signed) end", "token [redacted] end", "eyJzdWIiOiIxMjM0In0"),
        ("jwt=\(signed)", "jwt=[redacted]", "eyJzdWIiOiIxMjM0In0"),
        ("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "[redacted]", "eyJzdWIiOiIxIn0"),
        ("curl -H 'Authorization: Bearer abc.DEF-123_456'", "curl -H 'Authorization: Bearer [redacted]'", "abc.DEF-123_456"),
        ("sent bearer  sk_live_0123456789 to server", "sent bearer  [redacted] to server", "sk_live_0123456789"),
    ]

    static let unchanged = [
        "order 4242424242424241", "timestamp 1700000000000", "id ab4242424242424242", "4242424242424242ab",
        "uuid 123456789012345678901234", "phone +90 555 123 45 67", "@mention", "user@localhost", "a @ b.com", "price 5@3.5", "@@@",
        "eyJ is not a token", "eyJabc.def", "bearer short", "Merhaba dünya 👋🏽 — заказ №42 отправлен; 東京 3:00", "",
    ]

    @Test("the detectors give 2.0.0's output", arguments: masked.indices)
    func detectorOutput(index: Int) {
        let (input, expected, _) = Self.masked[index]
        #expect(detectors.redact(input) == expected)
    }

    @Test("every value 2.0.0 hid stays hidden with every kind", arguments: masked.indices)
    func stillHidden(index: Int) {
        let (input, _, hidden) = Self.masked[index]
        #expect(!redactor.redact(input).contains(hidden))
    }

    @Test("text 2.0.0 left alone is left alone by the detectors", arguments: unchanged)
    func detectorsLeaveText(input: String) {
        #expect(detectors.redact(input) == input)
    }

    @Test("2.0.0's kinds and matches")
    func kindsAndMatches() {
        #expect(SensitiveDataRedactor(kinds: .emailAddresses).redact("alice@example.com password=x 4242424242424242")
            == "a•••@example.com password=x 4242424242424242")
        #expect(SensitiveDataRedactor(kinds: []).redact("password=x") == "password=x")
        let text = "mail bob@example.com, pin password=1234, card 4242424242424242"
        let found = detectors.matches(in: text)
        #expect(found.map(\.kind) == [.emailAddresses, .cardNumbers])
        #expect(found.map { String(text[$0.range]) } == ["bob@example.com", "4242424242424242"])
        // Every finding of 2.0.0 is inside a match of 2.1.0.
        let ranges = redactor.matches(in: text).map(\.range)
        for part in ["bob@example.com", "1234", "4242424242424242"] {
            let range = text.range(of: part)!
            #expect(ranges.contains { $0.contains(range.lowerBound) && $0.upperBound >= range.upperBound }, "\(part)")
        }
        #expect(redactor.redact(#"POST /login {"user":"alice@example.com","password":"hunter2"}"#)
            == #"POST /login {"user":"a•••@example.com","password":"[redacted]"}"#)
    }

    /// 2.0.0's samples with a character before and after them.
    static let samples: [(value: String, hidden: String, kind: SensitiveDataRedactor.Kinds)] = [
        ("4242424242424242", "42424242", .cardNumbers), ("4242 4242 4242 4242", "4242 4242 4242", .cardNumbers),
        ("378282246310005", "8282246", .cardNumbers), ("alice@example.com", "lice", .emailAddresses),
        ("bob.smith+news@mail.example.org", "ob.smith", .emailAddresses), ("x%y@example.com", "%y", .emailAddresses),
        (signed, "eyJzdWIiOiIxMjM0In0", .jsonWebTokens), ("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "eyJzdWIiOiIxIn0", .jsonWebTokens),
        ("Bearer abc.DEF-123_456", "abc.DEF-123_456", .bearerTokens), ("bearer  sk_live_0123456789", "sk_live_0123456789", .bearerTokens),
    ]
    static let before = [
        "", " ", "x ", ":", "=", "/", ".", "@", "\"", "'", "(", "<", "#", "+", "~", "%", "&", "*", "|", "\\", "x:", "mailto:", "id=",
        "\t", "\u{200B}", "é", "𝐚", "№", "→", "[", "{", ",", ";", "?", "!", "$", "^", "`",
    ]
    static let after = [
        "", " ", ".", ",", ":", ";", ")", ">", "\"", "/", "@", "\n", "?", "!", "]", "}", "'", "#", "=", "&", "é", "𝐚", "№", "\u{200B}",
    ]

    /// 2.0.0 hid each of these, alone and with every kind, unless an ASCII letter, digit, `_` or
    /// `-` glued the value to a word (checked against a build of 2.0.0 when this test was
    /// written); a letter written outside ASCII (`é`, `𝐚`, `№`) does not glue, and nor does `:`.
    @Test("each detector still finds its value next to any character that does not glue it to a word", arguments: samples.indices)
    func notGlued(index: Int) {
        let (value, hidden, kind) = Self.samples[index]
        for redactor in [SensitiveDataRedactor(kinds: kind), redactor] {
            for before in Self.before {
                for after in Self.after {
                    let output = redactor.redact(before + value + after)
                    #expect(!output.contains(hidden), "\((before + value + after).debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    @Test("an address after `:` shows no letter of its name, which may be a password")
    func addressAfterColon() {
        let emails = SensitiveDataRedactor(kinds: .emailAddresses)
        #expect(emails.redact("mailto:alice@example.com") == "mailto:•••@example.com")
        #expect(emails.redact("user:hunter2@example.com") == "user:•••@example.com")
        #expect(redactor.redact("db user:hunter2@example.com") == "db user:[redacted]")
    }
}
