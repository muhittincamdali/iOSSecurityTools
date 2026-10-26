import Foundation
import Testing
import iOSSecurityTools

/// The required test set of the shared redaction spec (REDACTION-SPEC 2.1-r2, §8), ported to this
/// package's API: §8.3 value detectors (§3) and §8.4 URLs (§5). §8.3 #37, the exponent JSON number
/// detector, belongs to another package only and is not part of this one (spec §3 D8, §9.3).
@Suite("Redaction spec §8.3–8.4: detectors and URLs")
struct RedactionSpecSetDetectorURLTests {
    let redactor = SensitiveDataRedactor()

    func url(_ text: String, _ redactor: SensitiveDataRedactor = SensitiveDataRedactor()) throws -> String {
        redactor.redact(url: try #require(URL(string: text), "\(text)"))
    }

    @Test("§8.3 #25–#33, #35–#36: detectors in free text", arguments: [
        ("paid 4111 1111 1111 1111 ok", "paid •••• 1111 ok"),
        ("ok 4111-1111-1111-1111 ok", "ok •••• 1111 ok"),
        ("٤٢٤٢ ٤٢٤٢ ٤٢٤٢ ٤٢٤٢", "•••• 4242"),
        ("ref DE89 3704 0044 0532 0130 00 ok", "ref •••• 3000 ok"),
        ("de89370400440532013000 lowercase", "de89370400440532013000 lowercase"),
        ("mail alice@example.com ok", "mail a•••@example.com ok"),
        ("contact alice%40example.com", "contact [redacted]"),
        ("tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U ok", "tok [redacted] ok"),
        ("hdr Bearer abcdefgh12345678 ok", "hdr Bearer [redacted] ok"),
        ("hdr bearer abcdefgh12345678 ok", "hdr bearer [redacted] ok"),
        ("hex 0123456789abcdef0123456789abcdef ok", "hex [redacted] ok"),
        ("uuid 123e4567-e89b-12d3-a456-426614174000 ok", "uuid 123e4567-e89b-12d3-a456-426614174000 ok"),
        ("git clone https://bob:hunter2@github.com/x/y.git", "git clone [redacted]"),
        ("redis://:hunter2@host", "[redacted]"),
        ("paid with 4111 1111 1111\u{2028}1111", "paid with [redacted]"),
        ("paid with 4111 1111 1111\u{000B}1111", "paid with [redacted]"),
        ("paid 4111\u{000C}1111\u{0085}1111\u{2029}1111", "paid [redacted]"),
        ("mail ali\u{2028}ce@example.com ok", "mail [redacted]"),
        ("4111 1111 1111\n1111", "4111 1111 1111\n1111"),
    ])
    func detectors(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("§8.3 #34: detectors run on JSON names")
    func detectorsInNames() {
        let body = Data(#"{"4111111111111111":1,"alice@example.com":2}"#.utf8)
        #expect(redactor.redact(body: body, contentType: "application/json") == #"{"•••• 1111":1,"a•••@example.com":"[redacted]"}"#)
    }

    @Test("§8.4 #38–#47: URLs", arguments: [
        ("https://bob:pw@example.com/users/12345678/reset?code=x#y", "https://example.com/users/:id/reset?code=[redacted]"),
        ("https://example.com/v1/cards/4242/pin/4831", "https://example.com/v1/cards/:id/pin/:id"),
        ("https://example.com/pin/./4831", "https://example.com"),
        ("https://example.com/token/x/../4831", "https://example.com"),
        ("https://example.com/a;pin/4831", "https://example.com"),
        ("https://example.com/a%2Fb/c", "https://example.com"),
        ("https://example.com/a%25/x", "https://example.com"),
        ("https://example.com/a%5Cb/x", "https://example.com"),
        ("https://example.com/a%3Bb/x", "https://example.com"),
        ("https://example.com" + String(repeating: "/a", count: 65), "https://example.com"),
        ("https://h.example;password=hunter2/db", "https://[redacted]"),
        ("https://4111111111111111.example.com/a", "https://[redacted]"),
        ("https://example.com/caf%C3%A9/menu", "https://example.com/caf%C3%A9/:id"),
        ("https://example.com/p%0Ain/4831", "https://example.com/p%0Ain/:id"),
        ("https://example.com/a,b/c", "https://example.com/a,b/:id"),
        ("https://example.com/users/:id/x", "https://example.com/users/:id/x"),
        ("https://example.com/a?page=2&flag", "https://example.com/a?page=[redacted]&[redacted]"),
        ("https://example.com/a?a=1;b=2", "https://example.com/a?[redacted]"),
        ("mailto:ada@example.com", "<unparsed URL>"),
    ])
    func urls(input: String, expected: String) throws {
        #expect(try url(input) == expected)
    }

    /// §5 U4 as the spec's §9.2 G1 tightens it: a host that names a secret may hold the value
    /// itself, so the host is hidden too, with its port, path and query (`scheme://[R]`).
    @Test("§8.4 #43, §9.2 G1: a host that names a secret is hidden with everything after it", arguments: [
        ("myapp://pin/4831", "myapp://[redacted]"),
        ("myapp://user@pin/Qz743Wk5m", "myapp://[redacted]"),
        ("myapp://password.hunter2", "myapp://[redacted]"),
        ("myapp://pin-4831", "myapp://[redacted]"),
        ("https://pin-4831.example.com", "https://[redacted]"),
        ("https://pin-4831.example.com/a", "https://[redacted]"),
        ("myapp://pin:4831", "myapp://[redacted]"),
        ("myapp://pin:4831/a", "myapp://[redacted]"),
        ("https://auth.example.com/oauth/authorize?client_id=x", "https://[redacted]"),
    ])
    func hostNamesSecret(input: String, expected: String) throws {
        #expect(try url(input) == expected)
        #expect(try url(input, SensitiveDataRedactor(urlDetail: .hostOnly)) == expected)
        #expect(try url(input, SensitiveDataRedactor(allowedQueryParameters: ["client_id"])) == expected)
    }

    /// Spec §9.3: what the URL rules do not find, by design.
    @Test("§9.3: a host that names no secret and a short ordinary path segment are shown")
    func documentedURLLimits() throws {
        #expect(try url("https://hunter2.example.com/a") == "https://hunter2.example.com/a")
        #expect(try url("https://example.com/reset/abc123") == "https://example.com/reset/abc123")
    }

    @Test("§8.4 #48: without secret fields the URL is read by the detectors alone, and the user info and fragment still drop")
    func withoutSecretFields() throws {
        let cardsOnly = SensitiveDataRedactor(kinds: [.cardNumbers])
        #expect(try url("myapp://pin/4831", cardsOnly) == "myapp://pin/4831")
        #expect(try url("https://bob:pw@example.com/a#frag", cardsOnly) == "https://example.com/a")
        #expect(cardsOnly.redact("see https://bob:pw@example.com/a#frag ok") == "see https://bob:pw@example.com/a#frag ok")
        let body = #"{"password":"hunter2"}"#
        #expect(cardsOnly.redact(body: Data(body.utf8), contentType: "application/json") == body)
    }
}
