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
        ("user[password]=hunter2&user[name]=bob", "user[password]=[redacted]&user[name]=[redacted]"),
        ("user[password][confirmation]=x", "user[password][confirmation]=[redacted]"),
        ("<password>hunter2</password><user>bob</user>", "<password>[redacted]</password><user>bob</user>"),
        ("<ApiKey>\nk-1\n</ApiKey>", "<ApiKey>[redacted]</ApiKey>"),
        ("<token>unclosed\nnext line", "<token>[redacted]\nnext line"),
        ("<password type=\"text\">hunter2</password>", "<password type=\"text\">[redacted]</password>"),
        ("<password >hunter2</password>", "<password >[redacted]</password>"),
        ("<Token\n  kind=\"a>b\">abc</Token>", "<Token\n  kind=\"a>b\">[redacted]</Token>"),
        ("<ns:password>hunter2</ns:password>", "<ns:password>[redacted]</ns:password>"),
        ("<wsse:Password Type=\"PasswordText\">hunter2</wsse:Password>", "<wsse:Password Type=\"PasswordText\">[redacted]</wsse:Password>"),
        ("password%3Dhunter2", "password%3D[redacted]"),
        ("q=password%3dhunter2", "q=password%3d[redacted]"),
        ("secret%3Ax", "secret%3A[redacted]"),
        ("user%5Bpassword%5D=hunter2&user%5Bname%5D=bob", "user%5Bpassword%5D=[redacted]&user%5Bname%5D=[redacted]"),
        ("password%5B%5D=hunter2", "password%5B%5D=[redacted]"),
        ("user%5bpassword%5d%3dhunter2", "user%5bpassword%5d%3d[redacted]"),
        ("user%5Bpassword%5D%5Bconfirmation%5D=x", "user%5Bpassword%5D%5Bconfirmation%5D=[redacted]"),
        ("password%20%3D%20hunter2", "password%20%3D[redacted]"),
        ("password+%3D+hunter2", "password+%3D[redacted]"),
        ("q=password%20%3A%20hunter2&x=1", "q=password%20%3A[redacted]&x=1"),
        ("password%20=%20hunter2", "password%20=[redacted]"),
        ("password: <hunter2>", "password: [redacted]"),
        ("token=<abc 123>; next", "token=[redacted]; next"),
        ("password: <hunter2", "password: [redacted]"),
        ("password=<hunter2\n>", "password=[redacted]"),
        ("password:<a password:<b>", "password:[redacted]"),
    ])
    func otherSyntaxes(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("hides the value after assignment and comparison operators", arguments: [
        ("PASSWORD := hunter2", "PASSWORD := [redacted]"),
        ("password:=hunter2", "password:=[redacted]"),
        ("apiKey := \"k-1\"", "apiKey := \"[redacted]\""),
        ("API_TOKEN ?= abc123", "API_TOKEN ?= [redacted]"),
        ("SECRET += abc123", "SECRET += [redacted]"),
        ("password=>hunter2", "password=>[redacted]"),
        ("password == \"hunter2\"", "password == \"[redacted]\""),
        ("token!=abc123", "token!=[redacted]"),
        ("password === hunter2", "password === [redacted]"),
        ("password === \"hunter2\"", "password === \"[redacted]\""),
        ("password=== hunter2", "password=== [redacted]"),
        ("password!==hunter2", "password!==[redacted]"),
        ("password :== hunter2", "password :== [redacted]"),
        ("password ::= hunter2", "password ::= [redacted]"),
        ("password = = hunter2", "password = = [redacted]"),
        ("password%3D%3Dhunter2", "password%3D%3D[redacted]"),
        ("password == hunter2 && token === abc123", "password == [redacted] && token === [redacted]"),
        ("password \u{2254} hunter2", "password \u{2254} [redacted]"),
        ("password \u{2A74} hunter2", "password \u{2A74} [redacted]"),
        ("password\u{2A75}hunter2", "password\u{2A75}[redacted]"),
        ("password\u{2A76}hunter2", "password\u{2A76}[redacted]"),
        ("password\u{FE66}hunter2", "password\u{FE66}[redacted]"),
        ("password\u{FE55} hunter2", "password\u{FE55} [redacted]"),
        ("password \u{2236} hunter2", "password \u{2236} [redacted]"),
    ])
    func assignmentOperators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("reads every Unicode space as a space", arguments: [
        "\u{A0}", "\u{1680}", "\u{2000}", "\u{2001}", "\u{2002}", "\u{2003}", "\u{2004}", "\u{2005}",
        "\u{2006}", "\u{2007}", "\u{2008}", "\u{2009}", "\u{200A}", "\u{202F}", "\u{205F}", "\u{3000}",
    ])
    func unicodeSpaces(space: String) {
        #expect(redactor.redact("password\(space)=\(space)hunter2") == "password\(space)=\(space)[redacted]")
        #expect(redactor.redact("Bearer\(space)abc.DEF-123") == "Bearer\(space)[redacted]")
        #expect(redactor.redact(["4242", "4242", "4242", "4242"].joined(separator: space)) == "•••• 4242")
    }

    @Test("pass and session names hold secrets", arguments: [
        ("pass=hunter2", "pass=[redacted]"),
        ("DB_PASS=hunter2", "DB_PASS=[redacted]"),
        ("smtpPass: hunter2", "smtpPass: [redacted]"),
        ("session=abc123", "session=[redacted]"),
        ("Session: abc123", "Session: [redacted]"),
        ("sessionId=abc123", "sessionId=[redacted]"),
        ("SESSION_KEY=abc123", "SESSION_KEY=[redacted]"),
        ("Cookie: PHPSESSID=abc123; lang=en", "Cookie: PHPSESSID=[redacted]; lang=en"),
        ("Set-Cookie: JSESSIONID=abc123; Path=/", "Set-Cookie: JSESSIONID=[redacted]; Path=/"),
        ("jsessionid=abc123", "jsessionid=[redacted]"),
        ("ASP.NET_SessionId=abc123", "ASP.NET_SessionId=[redacted]"),
    ])
    func passAndSessionNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves plain names and syntax that only look like a secret field", arguments: [
        "passport=X1234",
        "bypass=true",
        "compass=north",
        "passed=12",
        "pass_count=3",
        "session_start=2026-10-15",
        "sessionCount: 3",
        "PHPSESSID_NAME=x",
        "<passwordHint>dog</passwordHint>",
        "</password>",
        "<password/>",
        "<password />",
        "<password type=\"text\"/>",
        "<password type=\"text\"",
        "<password a<b>c",
        "a:password>b",
        "password%3x",
        "password%",
        "user%5Bpassword%5D",
    ])
    func lookalikes(input: String) {
        #expect(redactor.redact(input) == input)
    }
}

extension RedactionEdgeCaseTests {
    // Brackets, `%` escapes and an empty prefix make a name that is not plain ASCII, whatever it
    // spells, so its value is hidden.
    @Test("hides the value of form and XML names that are not plain", arguments: [
        ("password[=x", "password[=[redacted]"),
        ("user%5Bpassport%5D=X1234", "user%5Bpassport%5D=[redacted]"),
        ("%5B=x", "%5B=[redacted]"),
        ("<\u{540D}\u{524D}>bob</\u{540D}\u{524D}>", "<\u{540D}\u{524D}>[redacted]</\u{540D}\u{524D}>"),
    ])
    func namesThatAreNotPlain(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves HTML and comparisons that are not fields", arguments: [
        "<br/> <p>hi</p> <a href=\"x\">y</a>",
        "if a<b && c>d then",
        "count>=5",
        "a <= b",
        "x == y",
        "time: 12:30:45",
        "Error: connection refused",
        "<a:b:c>x</a:b:c>",
        "finished: <NSHTTPURLResponse: 0x600> { URL: https://example.com/v2/items?id=7 } { Status Code: 200 }",
        "<UIView: 0x7f8; frame = (0 0; 375 812); layer = <CALayer: 0x600>>",
        "<private>",
    ])
    func notFields(input: String) {
        #expect(redactor.redact(input) == input)
    }
}
