import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor edge cases")
struct RedactionEdgeCaseTests {
    let redactor = SensitiveDataRedactor()

    // A value that runs into a card number used to keep the first finding and drop the second,
    // which showed 12 of the 16 digits.
    @Test("findings that partly overlap are hidden together", arguments: [
        ("token=abc_4111 1111 1111 1111", "token=[redacted]"),
        ("pwd=x-4111 1111 1111 1111 end", "pwd=[redacted]"),
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
        #expect(redactor.redact("password=alice@example.com next=1") == "password=[redacted]")
        #expect(redactor.redact("paid 4111 1111 1111 1111 and a@example.com") == "paid •••• 1111 and •••@example.com")
    }

    @Test("a joined match reports every kind it covers and the whole range")
    func joinedMatch() throws {
        let text = "jwt eyJhbGciOi.eyJzdWIiOi.sig_4111 1111 1111 1111"
        let found = redactor.matches(in: text)
        let match = try #require(found.first)
        #expect(found.count == 1)
        #expect(match.kind == [.jsonWebTokens, .cardNumbers])
        #expect(String(text[match.range]) == "eyJhbGciOi.eyJzdWIiOi.sig_4111 1111 1111 1111")
    }

    @Test("findings that only touch stay separate")
    func adjacentFindings() {
        let found = redactor.matches(in: "a@example.com,4111 1111 1111 1111")
        #expect(found.map(\.kind) == [.emailAddresses, .cardNumbers])
    }

    // A secret name hides the rest of its line from where its value may start, whatever
    // brackets, markup or escapes follow it; free text has no grammar to tell where the value
    // ends.
    @Test("finds secret fields in form, XML and percent-encoded syntax", arguments: [
        ("password[]=hunter2", "password[redacted]"),
        ("password[0]=a&password[1]=b", "password[redacted]"),
        ("user[password]=hunter2&user[name]=bob", "user[password]=[redacted]"),
        ("user[password][confirmation]=x", "user[password][redacted]"),
        ("<password>hunter2</password><user>bob</user>", "<password>[redacted]"),
        ("<ApiKey>\nk-1\n</ApiKey>", "<ApiKey>[redacted]"),
        ("<token>unclosed\nnext line", "<token>[redacted]"),
        ("<password type=\"text\">hunter2</password>", "<password [redacted]"),
        ("<password >hunter2</password>", "<password >[redacted]"),
        ("<Token\n  kind=\"a>b\">abc</Token>", "<Token[redacted]"),
        ("<ns:password>hunter2</ns:password>", "<ns:[redacted]"),
        ("<wsse:Password Type=\"PasswordText\">hunter2</wsse:Password>", "<wsse:[redacted]"),
        ("password%3Dhunter2", "password[redacted]"),
        ("q=password%3dhunter2", "q=[redacted]"),
        ("secret%3Ax", "secret[redacted]"),
        ("user%5Bpassword%5D=hunter2&user%5Bname%5D=bob", "user%5Bpassword%5D=[redacted]"),
        ("password%5B%5D=hunter2", "password%5B%5D=[redacted]"),
        ("user%5bpassword%5d%3dhunter2", "user%5bpassword[redacted]"),
        ("user%5Bpassword%5D%5Bconfirmation%5D=x", "user%5Bpassword%5D%5Bconfirmation%5D=[redacted]"),
        ("password+%3D+hunter2", "password+[redacted]"),
        ("q=password+%3A+hunter2&x=1", "q=[redacted]"),
        ("password%20%3D%20hunter2", "password[redacted]"),
        ("q=password%20%3A%20hunter2&x=1", "q=[redacted]"),
        ("password%20=%20hunter2", "password%20=[redacted]"),
        ("password: <hunter2>", "password: [redacted]"),
        ("token=<abc 123>; next", "token=[redacted]"),
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
        ("apiKey := \"k-1\"", "apiKey := [redacted]"),
        ("API_TOKEN ?= abc123", "API_TOKEN [redacted]"),
        ("SECRET += abc123", "SECRET [redacted]"),
        ("password=>hunter2", "password=>[redacted]"),
        ("password == \"hunter2\"", "password == [redacted]"),
        ("token!=abc123", "token!=[redacted]"),
        ("password === hunter2", "password === [redacted]"),
        ("password === \"hunter2\"", "password === [redacted]"),
        ("password=== hunter2", "password=== [redacted]"),
        ("password!==hunter2", "password!==[redacted]"),
        ("password :== hunter2", "password :== [redacted]"),
        ("password ::= hunter2", "password ::= [redacted]"),
        ("password = = hunter2", "password = [redacted]"),
        ("password%3D%3Dhunter2", "password[redacted]"),
        ("password == hunter2 && token === abc123", "password == [redacted]"),
        ("password \u{2254} hunter2", "password [redacted]"),
        ("password \u{2A74} hunter2", "password \u{2A74} [redacted]"),
        ("password\u{2A75}hunter2", "password\u{2A75}[redacted]"),
        ("password\u{2A76}hunter2", "password\u{2A76}[redacted]"),
        ("password\u{FE66}hunter2", "password\u{FE66}[redacted]"),
        ("password\u{FE55} hunter2", "password\u{FE55} [redacted]"),
        ("password \u{2236} hunter2", "password [redacted]"),
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

    // An unquoted value in free text goes to the end of its line: `;` does not end it.
    @Test("pass and session names hold secrets", arguments: [
        ("pass=hunter2", "pass=[redacted]"),
        ("DB_PASS=hunter2", "DB_PASS=[redacted]"),
        ("smtpPass: hunter2", "smtpPass: [redacted]"),
        ("session=abc123", "session=[redacted]"),
        ("Session: abc123", "Session: [redacted]"),
        ("sessionId=abc123", "sessionId=[redacted]"),
        ("SESSION_KEY=abc123", "SESSION_KEY=[redacted]"),
        ("PHPSESSID=abc123; lang=en", "PHPSESSID=[redacted]"),
        ("JSESSIONID=abc123; Path=/", "JSESSIONID=[redacted]"),
        ("Cookie: PHPSESSID=abc123; lang=en", "Cookie: [redacted]"),
        ("Set-Cookie: JSESSIONID=abc123; Path=/", "Set-Cookie: [redacted]"),
        ("jsessionid=abc123", "jsessionid=[redacted]"),
        ("ASP.NET_SessionId=abc123", "ASP.NET_SessionId=[redacted]"),
    ])
    func passAndSessionNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("names that only look like a secret name keep their value in structured input", arguments: [
        "passport", "bypass", "compass", "passed", "session_start", "sessionCount",
    ])
    func lookalikeNames(name: String) {
        let json = "{\"\(name)\":\"x\"}"
        #expect(redactor.redact(body: Data(json.utf8), contentType: "application/json") == json)
        #expect(SensitiveDataRedactor(allowedTextKeys: [name]).redact("\(name)=x") == "\(name)=x")
        #expect(redactor.redact("\(name)=x") == "\(name)=[redacted]")
    }

    @Test("leaves markup without a secret name", arguments: ["</password>", "<private>", "<br/> <p>hi</p>", "if a<b && c>d then"])
    func markup(input: String) {
        #expect(redactor.redact(input) == input)
    }
}

extension RedactionEdgeCaseTests {
    // Brackets, `%` escapes and an empty prefix make a name that is not plain ASCII, whatever it
    // spells, so its value is hidden.
    @Test("hides the value of form names that are not plain", arguments: [
        ("password[=x", "password[redacted]"),
        ("user%5Bpassport%5D=X1234", "user%5Bpassport%5D=[redacted]"),
        ("%5B=x", "%5B=[redacted]"),
    ])
    func namesThatAreNotPlain(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // Free text is not parsed as XML: an element is not a pair, so only a secret name or a word
    // that cannot be read in it hides what follows.
    @Test("an XML element is not read as a pair")
    func xmlElements() {
        #expect(redactor.redact("<\u{540D}\u{524D}>bob</\u{540D}\u{524D}>") == "<\u{540D}\u{524D}>bob</\u{540D}\u{524D}>")
        #expect(redactor.redact("<p\u{0430}ssword>bob</p\u{0430}ssword>") == "<[redacted]")
    }

    // Free text keeps a value only after an allowed key, so comparisons, times and object
    // descriptions written as `key: value` are hidden unless the app allows their keys.
    @Test("pairs in free text keep their value only after an allowed key", arguments: [
        ("<a href=\"x\">y</a>", "<a href=[redacted]"),
        ("count>=5", "count>=[redacted]"),
        ("a <= b", "a <= [redacted]"),
        ("x == y", "x == [redacted]"),
        ("time: 12:30:45", "time: [redacted]"),
        ("Error: connection refused", "Error: [redacted]"),
        ("<a:b:c>x</a:b:c>", "<a:[redacted]"),
        ("finished: <NSHTTPURLResponse: 0x600> { URL: https://example.com/v2/items?id=7 } { Status Code: 200 }", "finished: [redacted]"),
        ("<UIView: 0x7f8; frame = (0 0; 375 812); layer = <CALayer: 0x600>>", "<UIView: [redacted]"),
    ])
    func pairsInText(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("keys the app allows keep their value in free text")
    func allowedKeys() {
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["time", "error", "href"])
        #expect(allowing.redact("time: 12:30:45") == "time: 12:30:45")
        #expect(allowing.redact("Error: connection refused") == "Error: connection refused")
        #expect(allowing.redact("<a href=\"x\">y</a>") == "<a href=\"x\">y</a>")
        // The value of an allowed key is still read: a secret name in it hides the rest.
        #expect(allowing.redact("error: wrong password hunter2") == "error: wrong password [redacted]")
    }
}
