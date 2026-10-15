import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("Redacted")
struct RedactedTests {
    struct LoginRequest: Codable, Equatable {
        var username: String
        @Redacted var password: String
    }

    let request = LoginRequest(username: "alice", password: "hunter2-secret")

    @Test("no printing or reflection path shows the wrapped value")
    func everyDescriptionHidesTheValue() {
        let value = Redacted("hunter2-secret")
        var dumpedValue = ""
        dump(value, to: &dumpedValue)
        var dumpedRequest = ""
        dump(request, to: &dumpedRequest)
        let optional: Redacted<String>? = value
        let outputs = [
            "\(value)",
            String(describing: value),
            String(reflecting: value),
            "\(optional as Any)",
            "\([value])",
            "\(["key": value])",
            dumpedValue,
            "\(request)",
            String(reflecting: request),
            dumpedRequest,
            (value as AnyObject).description ?? "",
            String(describing: Mirror(reflecting: value).children.map(\.value)),
        ]
        for output in outputs {
            #expect(!output.contains("hunter2"), "Leaked in: \(output)")
        }
        #expect("\(value)" == "<redacted>")
        #expect("\(request)".contains("<redacted>"))
        #expect(Mirror(reflecting: value).children.isEmpty)
    }

    @Test("the value is available when read explicitly")
    func explicitAccess() {
        #expect(request.password == "hunter2-secret")
        #expect(Redacted(42).wrappedValue == 42)
    }

    @Test("Codable is transparent, so request bodies keep their shape")
    func codable() throws {
        let json = try JSONEncoder().encode(request)
        let object = try JSONSerialization.jsonObject(with: json) as? [String: String]
        #expect(object == ["username": "alice", "password": "hunter2-secret"])
        #expect(try JSONDecoder().decode(LoginRequest.self, from: json) == request)
    }

    @Test("equality and hashing use the wrapped value")
    func equality() {
        #expect(Redacted("a") == Redacted("a"))
        #expect(Redacted("a") != Redacted("b"))
        #expect(Set([Redacted("a"), Redacted("a")]).count == 1)
    }
}

@Suite("Mask")
struct MaskTests {
    @Test("card numbers keep the last four digits", arguments: [
        ("4242 4242 4242 4242", "•••• 4242"),
        ("4242-4242-4242-4242", "•••• 4242"),
        ("378282246310005", "•••• 0005"),
        ("４２４２４２４２４２４２４２４２", "•••• 4242"),
        ("٤٢٤٢٤٢٤٢٤٢٤٢٤٢٤٢", "•••• 4242"),
        ("12345678901", "••••"),
        ("", "••••"),
        ("not a card", "••••"),
    ])
    func cardNumbers(input: String, expected: String) {
        #expect(Mask.cardNumber(input) == expected)
    }

    @Test("emails hide the name and keep the domain", arguments: [
        ("alice@example.com", "a•••@example.com"),
        ("al@example.com", "•••@example.com"),
        ("a@example.com", "•••@example.com"),
        ("first.last+tag@mail.example.co.uk", "f•••@mail.example.co.uk"),
        ("alice", "••••"),
        ("@example.com", "••••"),
        ("alice@localhost", "••••"),
        ("alice@.com", "••••"),
        ("alice@example.com.", "••••"),
        ("al ice@example.com", "••••"),
        ("alice@example.com\nERROR forged line", "••••"),
        ("al\u{202E}ice@example.com", "••••"),
        ("a@b@example.com", "••••"),
    ])
    func emails(input: String, expected: String) {
        #expect(Mask.email(input) == expected)
    }

    @Test("trailing keeps at most a third of the value", arguments: [
        ("DE89370400440532013000", 4, "•••• 3000"),
        ("123456789012", 4, "•••• 9012"),
        ("12345678901", 4, "••••"),
        ("1234", 4, "••••"),
        ("12345", 4, "••••"),
        ("123456", 2, "•••• 56"),
        ("123456", 0, "••••"),
        ("123456", -3, "••••"),
        ("123456789012345678901234567890", 10, "•••• 7890"),
        ("123456789012345678901234567890", Int.max, "•••• 7890"),
        ("123456789012345678901234567890", Int.min, "••••"),
        ("+90 555 123 45 67", 4, "•••• 5 67"),
    ])
    func trailing(input: String, visible: Int, expected: String) {
        #expect(Mask.trailing(input, visibleCount: visible) == expected)
    }

    @Test("trailing does not show line breaks or invisible characters")
    func trailingUnsafeCharacters() {
        #expect(Mask.trailing("1234567890\n123", visibleCount: 4) == "••••")
        #expect(Mask.trailing("12345678901\u{200B}23", visibleCount: 4) == "••••")
    }

    @Test("the mask does not depend on the length of the hidden part")
    func fixedLength() {
        #expect(Mask.trailing("1234") == Mask.trailing("12345678901"))
        #expect(Mask.cardNumber("4242424242424242") == Mask.cardNumber("4242 4242 4242 4242 4242"))
    }
}

@Suite("SensitiveDataRedactor")
struct SensitiveDataRedactorTests {
    let redactor = SensitiveDataRedactor()

    @Test("redacts the README example")
    func readmeExample() {
        let input = #"POST /login {"user":"alice@example.com","password":"hunter2"}"#
        #expect(redactor.redact(input) == #"POST /login {"user":"a•••@example.com","password":"[redacted]"}"#)
    }

    @Test("finds card numbers that pass the Luhn check", arguments: [
        ("paid with 4242424242424242 today", "paid with •••• 4242 today"),
        ("card 4242 4242 4242 4242.", "card •••• 4242."),
        ("card 4242-4242-4242-4242", "card •••• 4242"),
        ("amex 3782 822463 10005", "amex •••• 0005"),
        ("order 1234 card 4242 4242 4242 4242 cvv 123", "order 1234 card •••• 4242 cvv 123"),
        ("order 98 4242 4242 4242 4242", "order 98 •••• 4242"),
        ("fullwidth ４２４２４２４２４２４２４２４２", "fullwidth •••• 4242"),
        ("zero width 4242\u{200B}4242\u{200B}4242\u{200B}4242", "zero width •••• 4242"),
        ("combining 4\u{301}242424242424242", "combining •••• 4242"),
        ("nbsp 4242\u{A0}4242\u{A0}4242\u{A0}4242", "nbsp •••• 4242"),
    ])
    func cards(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves numbers that are not card numbers", arguments: [
        "order 4242424242424241",
        "timestamp 1700000000000",
        "id ab4242424242424242",
        "4242424242424242ab",
        "uuid 123456789012345678901234",
        "phone +90 555 123 45 67",
    ])
    func notCards(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("finds email addresses", arguments: [
        ("contact alice@example.com.", "contact a•••@example.com."),
        ("<bob.smith+news@mail.example.org>", "<b•••@mail.example.org>"),
        ("fullwidth ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "fullwidth a•••@example.com"),
        ("hidden al\u{200D}ice@example.com", "hidden a•••@example.com"),
    ])
    func emails(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves text with @ that is not an address", arguments: ["@mention", "user@localhost", "a @ b.com", "price 5@3.5", "@@@"])
    func notEmails(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("replaces JSON Web Tokens, including unsigned ones")
    func jsonWebTokens() {
        let signed = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        #expect(redactor.redact("token \(signed) end") == "token [redacted] end")
        #expect(redactor.redact("jwt=\(signed)") == "jwt=[redacted]")
        #expect(redactor.redact("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.") == "[redacted]")
        #expect(redactor.redact("eyJ is not a token") == "eyJ is not a token")
        #expect(redactor.redact("eyJabc.def") == "eyJabc.def")
    }

    @Test("replaces bearer tokens wherever they appear")
    func bearerTokens() {
        #expect(redactor.redact("curl -H 'Authorization: Bearer abc.DEF-123_456'") == "curl -H 'Authorization: [redacted]'")
        #expect(redactor.redact("sent bearer  sk_live_0123456789 to server") == "sent bearer  [redacted] to server")
        #expect(redactor.redact("bearer short") == "bearer short")
    }

    @Test("replaces the values of secret fields in common formats", arguments: [
        (#"{"password": "p@ss w0rd"}"#, #"{"password": "[redacted]"}"#),
        (#"{"Password":"x\"y","next":1}"#, #"{"Password":"[redacted]","next":1}"#),
        ("/login?user=bob&password=hunter2&next=/", "/login?user=bob&password=[redacted]&next=/"),
        ("api_key=AKIA1234; region=eu", "api_key=[redacted]; region=eu"),
        ("X-API-Key: 0123abcd", "X-API-Key: [redacted]"),
        ("accessToken = abc123", "accessToken = [redacted]"),
        ("refresh_token:'r-1'", "refresh_token:'[redacted]'"),
        ("client_secret => s3cr3t", "client_secret => [redacted]"),
        ("Authorization: Basic dXNlcjpwYXNz", "Authorization: [redacted]"),
        ("session_token=abc&csrf_token=def", "session_token=[redacted]&csrf_token=[redacted]"),
        ("ｐａｓｓｗｏｒｄ=hunter2", "ｐａｓｓｗｏｒｄ=[redacted]"),
        ("pass\u{200B}word=hunter2", "pass\u{200B}word=[redacted]"),
        ("PASSWORD=hunter2", "PASSWORD=[redacted]"),
    ])
    func secretFields(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("finds the secret word among the other words of a field name", arguments: [
        ("SECRET_KEY=abc", "SECRET_KEY=[redacted]"),
        ("secret_key: abc", "secret_key: [redacted]"),
        ("aws_secret_access_key=abc", "aws_secret_access_key=[redacted]"),
        ("AWSSecretKey=abc", "AWSSecretKey=[redacted]"),
        ("password_confirmation=x", "password_confirmation=[redacted]"),
        ("passwordConfirm: x", "passwordConfirm: [redacted]"),
        ("password2=x", "password2=[redacted]"),
        ("new-password=x", "new-password=[redacted]"),
        ("--password=x", "--password=[redacted]"),
        ("privateKey=abc", "privateKey=[redacted]"),
        ("PRIVATE-KEY: abc", "PRIVATE-KEY: [redacted]"),
        ("password_reset_token=abc", "password_reset_token=[redacted]"),
    ])
    func secretWordsInFieldNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("replaces secret values in JSON escaped inside another string", arguments: [
        (#"{\"password\":\"x\"}"#, #"{\"password\":\"[redacted]\"}"#),
        (#"log: "{\"user\":\"bob\",\"api_key\": \"k-1\"}""#, #"log: "{\"user\":\"bob\",\"api_key\": \"[redacted]\"}""#),
        (#"{\"password\":\"a\\\"b\",\"next\":1}"#, #"{\"password\":\"[redacted]\",\"next\":1}"#),
        (#"{\"password\":\"a\\\\\",\"next\":1}"#, #"{\"password\":\"[redacted]\",\"next\":1}"#),
    ])
    func escapedJSON(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves fields that only contain a secret name", arguments: [
        "passwordHint=dog's name",
        "tokenizer=bpe",
        "token_type=bearer",
        "token_expires_in=3600",
        "passwordLength: 12",
        "password_policy=strict",
        "secretary=bob",
        "TOKENIZER=bpe",
        "password reset requested",
        "the token expired",
        "password=",
    ])
    func notSecretFields(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("an unterminated quoted value is hidden up to the end of the line")
    func unterminatedQuote() {
        #expect(redactor.redact("password=\"abc\nnext line") == "password=\"[redacted]\nnext line")
        #expect(redactor.redact("password=\"abc\\") == "password=\"[redacted]")
    }

    @Test("kinds limit what is redacted")
    func kinds() {
        let emailsOnly = SensitiveDataRedactor(kinds: .emailAddresses)
        #expect(emailsOnly.redact("alice@example.com password=x 4242424242424242") == "a•••@example.com password=x 4242424242424242")
        #expect(SensitiveDataRedactor(kinds: []).redact("password=x") == "password=x")
    }

    @Test("matches report kind and range in the original text")
    func matches() {
        let text = "mail bob@example.com, pin password=1234, card 4242424242424242"
        let found = redactor.matches(in: text)
        #expect(found.map(\.kind) == [.emailAddresses, .secretFields, .cardNumbers])
        #expect(found.map { String(text[$0.range]) } == ["bob@example.com", "1234", "4242424242424242"])
    }

    @Test("leaves text without sensitive data unchanged, including emoji and other scripts")
    func unchangedText() {
        let text = "Merhaba dünya 👋🏽 — заказ №42 отправлен; 東京 3:00"
        #expect(redactor.redact(text) == text)
        #expect(redactor.redact("") == "")
    }

    @Test("scans adversarial inputs in linear time", .timeLimit(.minutes(1)))
    func adversarialInputs() {
        let size = 200_000
        let inputs = [
            String(repeating: "eyJ", count: size / 3),
            String(repeating: "eyJa.", count: size / 5),
            String(repeating: "@", count: size),
            String(repeating: "a.", count: size / 2) + "@",
            "@" + String(repeating: "a.", count: size / 2),
            String(repeating: "1 ", count: size / 2),
            String(repeating: "password", count: size / 8),
            "password=\"" + String(repeating: "\\", count: size),
            "password=\\\"" + String(repeating: "\\", count: size),
            String(repeating: "p_a_s_s_w_o_r_d_", count: size / 16),
            "a" + String(repeating: "_", count: size) + "=x",
            String(repeating: "bearer ", count: size / 7),
            String(repeating: "\u{200B}", count: size),
        ]
        for input in inputs {
            #expect(!redactor.redact(input).isEmpty || input.isEmpty)
        }
    }
}
