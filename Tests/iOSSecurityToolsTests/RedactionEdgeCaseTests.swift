import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor edge cases")
struct RedactionEdgeCaseTests {
    let redactor = SensitiveDataRedactor()

    // A value that runs into a card number used to keep the first finding and drop the second,
    // which showed 12 of the 16 digits.
    @Test("findings that partly overlap are hidden together", arguments: [
        ("token=abc_4111 1111 1111 1111", "token=[redacted]"),
        ("pwd=x-4111 1111 1111 1111 end", "pwd=[redacted] end"),
        ("Bearer abcdefgh-4111 1111 1111 1111", "Bearer [redacted]"),
        ("Authorization: Bearer abcdefgh-4111 1111 1111 1111", "Authorization: [redacted]"),
        ("jwt eyJhbGciOi.eyJzdWIiOi.sig_4111 1111 1111 1111", "jwt [redacted]"),
    ])
    func partialOverlap(input: String, expected: String) {
        let output = redactor.redact(input)
        #expect(output == expected)
        #expect(!output.contains("1111"))
    }

    @Test("a finding inside another keeps the outer replacement")
    func containedFinding() {
        #expect(redactor.redact("password=alice@example.com next") == "password=[redacted] next")
        #expect(redactor.redact("card 4111 1111 1111 1111 and a@example.com") == "card •••• 1111 and •••@example.com")
    }

    @Test("a joined match reports every kind it covers and the whole range")
    func joinedMatch() throws {
        let text = "token=abc_4111 1111 1111 1111"
        let found = redactor.matches(in: text)
        let match = try #require(found.first)
        #expect(found.count == 1)
        #expect(match.kind == [.secretFields, .cardNumbers])
        #expect(String(text[match.range]) == "abc_4111 1111 1111 1111")
    }

    @Test("findings that only touch stay separate")
    func adjacentFindings() {
        let found = redactor.matches(in: "a@example.com,4111 1111 1111 1111")
        #expect(found.map(\.kind) == [.emailAddresses, .cardNumbers])
    }

    @Test("finds secret fields in form, XML and percent-encoded syntax", arguments: [
        ("password[]=hunter2", "password[]=[redacted]"),
        ("password[0]=a&password[1]=b", "password[0]=[redacted]&password[1]=[redacted]"),
        ("user[password]=hunter2&user[name]=bob", "user[password]=[redacted]&user[name]=bob"),
        ("user[password][confirmation]=x", "user[password][confirmation]=[redacted]"),
        ("<password>hunter2</password><user>bob</user>", "<password>[redacted]</password><user>bob</user>"),
        ("<ApiKey>\nk-1\n</ApiKey>", "<ApiKey>[redacted]</ApiKey>"),
        ("<token>unclosed\nnext line", "<token>[redacted]\nnext line"),
        ("password%3Dhunter2", "password%3D[redacted]"),
        ("q=password%3dhunter2", "q=password%3d[redacted]"),
        ("secret%3Ax", "secret%3A[redacted]"),
    ])
    func otherSyntaxes(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("pass and session names hold secrets", arguments: [
        ("pass=hunter2", "pass=[redacted]"),
        ("DB_PASS=hunter2", "DB_PASS=[redacted]"),
        ("smtpPass: hunter2", "smtpPass: [redacted]"),
        ("session=abc123", "session=[redacted]"),
        ("Session: abc123", "Session: [redacted]"),
        ("sessionId=abc123", "sessionId=[redacted]"),
        ("SESSION_KEY=abc123", "SESSION_KEY=[redacted]"),
    ])
    func passAndSessionNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves names and syntax that only look like a secret field", arguments: [
        "passport=X1234",
        "bypass=true",
        "compass=north",
        "passed=12",
        "pass_count=3",
        "session_start=2026-10-15",
        "sessionCount: 3",
        "<passwordHint>dog</passwordHint>",
        "</password>",
        "password[=x",
        "password%3x",
        "password%",
    ])
    func lookalikes(input: String) {
        #expect(redactor.redact(input) == input)
    }
}
