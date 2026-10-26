import Foundation
import Testing
@testable import iOSSecurityTools

/// The required test set of the shared redaction spec (REDACTION-SPEC 2.1-r2, §8), ported to this
/// package's API: §8.5 the cut point of free text (§6), and the shape of the shared corpus (#65),
/// whose probes the review probe suites run.
@Suite("Redaction spec §8.5: the cut point of free text")
struct RedactionSpecSetFreeTextTests {
    let redactor = SensitiveDataRedactor()

    @Test("§8.5 #49–#64: free text is cut once, at its first trigger", arguments: [
        ("GET /api/items status=200 method=GET duration_ms=12", "GET /api/items status=200 method=GET duration_ms=12"),
        ("login user=bob status=401 password=hunter2", "login user=[redacted]"),
        ("Error: connection refused\nretrying in 5 s", "Error: [redacted]"),
        // C3: a URL is clean or cuts the text where it starts.
        ("see https://x.example/a. Next", "see https://x.example/a. Next"),
        ("see https://x.example/a, then", "see https://x.example/a, then"),
        ("see https://x.example/a! wow", "see https://x.example/a! wow"),
        ("see https://x.example/a). ok", "see [redacted]"),
        ("see https://x.example/a.. ok", "see [redacted]"),
        ("see https://x.example/a: ok", "see [redacted]"),
        ("see https://x.example/a; then", "see [redacted]"),
        ("see https://x.example/a]", "see [redacted]"),
        ("see https://x.example/a>", "see [redacted]"),
        ("see https://x.example/a\"", "see [redacted]"),
        ("see https://x.example/a'#token", "see [redacted]"),
        ("see \"https://x.example/a\" ok", "see \"[redacted]"),
        ("GET https://api.example.com/users/12345678 200", "GET https://api.example.com/users/:id 200"),
        ("GET https://api.example.com/items?page=2 done", "GET [redacted]"),
        ("see https://x.example:8080/a ok", "see [redacted]"),
        ("see https://pin.example/a ok", "see [redacted]"),
        ("https://x.example/to ken hunter2", "https://x.example/to ken [redacted]"),
        // C4: quoted keys cut at their opening quote.
        (#"cache miss for "session Qz9Wk7rX": refetching"#, "cache miss for [redacted]"),
        ("`status`: 200 and `x`: 1", "`status`: 200 and [redacted]"),
        ("'status'=200 'x'=1", "'status'=200 [redacted]"),
        (#"x"status": 200"#, "[redacted]"),
        (#"{"status":200,"user":"bob"} done"#, #"{"status":200,[redacted]"#),
        (#"log [["X-User","bob"]]"#, "log [[[redacted]"),
        // C5: the ASCII skeleton and one wildcard.
        ("login t\u{0366}ken hunter2", "login t\u{0366}ken [redacted]"),
        ("p\u{0251}ssword hunter2", "p\u{0251}ssword [redacted]"),
        ("passw\u{3007}rd hunter2", "passw\u{3007}rd [redacted]"),
        ("t\u{1040}ken hunter2", "t\u{1040}ken [redacted]"),
        ("yap\u{0131}n 1234", "yap\u{0131}n [redacted]"),
        ("pass word hunter2", "pass [redacted]"),
        ("PIN 1234", "PIN [redacted]"),
        ("bypass ok", "bypass ok"),
        // C6: markup.
        ("if a < b then", "if a < b then"),
        ("1<2 and <3 and a<=b", "1<2 and <3 and a<=[redacted]"),
        ("x << 1", "x [redacted]"),
        ("<_id>7</_id>", "[redacted]"),
        ("Optional<String>(x)", "Optional[redacted]"),
        ("<\u{0661}>", "[redacted]"),
        // C7: every backslash not followed by white space.
        (#"login pa\x{73}sword hunter2"#, "login [redacted]"),
        (#"copied to \\nas\backup"#, "copied to [redacted]"),
        (#"pattern ^\d+$ matched"#, "pattern [redacted]"),
        (#"path ends with \ here"#, #"path ends with \ here"#),
        (#"trailing backslash \"#, #"trailing backslash \"#),
        ("s\\\u{3000}t", "[redacted]"),
        // C8: other escapes.
        ("user&colon;hunter2", "[redacted]"),
        ("status=200&count=3", "status=200&count=3"),
        ("R&D team", "[redacted]"),
        // C10: a number and a colon.
        ("user1:2345678 at 12:30", "user1:[redacted]"),
        ("at 12:30 id 7:9hunter2", "at 12:30 id 7:[redacted]"),
        ("t 1:482913", "t 1:[redacted]"),
        ("at 10.0.0.1:8080 ok", "at 10.0.0.1:8080 ok"),
        ("at 2026-10-19T12:30:45.123+03:00 ok", "at 2026-10-19T12:30:45.123+03:00 ok"),
        ("line 42:10", "line 42:10"),
        // C11: the safe alphabet.
        ("user\u{A789} hunter2", "user[redacted]"),
        ("status=200 note\u{2192} hunter2", "status=200 note[redacted]"),
        ("Merhaba dünya 👋 bye", "Merhaba dünya [redacted]"),
        ("\u{1F101}status=200", "[redacted]"),
        ("a\u{00A0}b", "a[redacted]"),
        ("login pa\u{115F}ssword hunter2", "login [redacted]"),
        ("\u{2028}status=200", "[redacted]"),
        ("status=200\u{000B}ok", "status=200[redacted]"),
        // C12: quotes and brackets.
        ("note \"a\nhunter2\": 1", "note [redacted]"),
        ("password: 'abc\n  hunter2'", "password: [redacted]"),
        ("say (hello", "say ([redacted]"),
        ("say (hello) ok", "say (hello) ok"),
        // C13: held names.
        ("field name=\"password\" hunter2", "field name=[redacted]"),
        ("<key>password</key>\n<string>k-1</string>", "[redacted]"),
        // K2 in free text: a look-alike letter.
        ("p\u{0430}ssword=hunter2", "p\u{0430}ssword=[redacted]"),
        ("t\u{043E}ken hunter2", "[redacted]"),
    ])
    func cut(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("§8.5 #50: a key on allowedTextKeys reads on")
    func allowedKey() {
        #expect(SensitiveDataRedactor(allowedTextKeys: ["user"]).redact("login user=bob status=401 password=hunter2") == "login user=bob status=401 password=[redacted]")
    }

    @Test("§8.5 #65: the shared corpus has the lines and claims the spec counts")
    func corpusShape() {
        let probes = ReviewProbes.all
        #expect(probes.count == 7_866)
        let claims = Dictionary(grouping: probes, by: \.claim).mapValues(\.count)
        #expect(claims == ["C": 7_234, "X": 476, "K": 78, "D": 78])
    }
}
