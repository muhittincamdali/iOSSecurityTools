import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor")
struct SensitiveDataRedactorTests {
    let redactor = SensitiveDataRedactor()

    @Test("redacts the documentation examples")
    func documentationExamples() {
        let body = #"{"user":"alice@example.com","password":"hunter2"}"#
        #expect(redactor.redact(body: Data(body.utf8), contentType: "application/json") == #"{"user":"a•••@example.com","password":"[redacted]"}"#)
        #expect(redactor.redact("login failed user=alice status=401") == "login failed user=[redacted]")
        #expect(redactor.redact("sent receipt to alice@example.com") == "sent receipt to a•••@example.com")
        #expect(redactor.redact("GET /orders status=200 duration_ms=41") == "GET /orders status=200 duration_ms=41")
    }

    @Test("finds card numbers that pass the Luhn check", arguments: [
        ("paid with 4242424242424242 today", "paid with •••• 4242 today"),
        ("paid 4242 4242 4242 4242.", "paid •••• 4242."),
        ("paid 4242-4242-4242-4242", "paid •••• 4242"),
        ("amex 3782 822463 10005", "amex •••• 0005"),
        ("order 1234 paid 4242 4242 4242 4242 ok", "order 1234 paid •••• 4242 ok"),
        ("fullwidth ４２４２４２４２４２４２４２４２", "fullwidth •••• 4242"),
        // A word with an invisible character in it cannot be read with certainty: it goes whole.
        ("zero width 4242\u{200B}4242\u{200B}4242\u{200B}4242", "zero width [redacted]"),
        ("combining 4\u{301}242424242424242", "combining •••• 4242"),
        // A space outside ASCII cuts the text there, and the card number is hidden whole with it.
        ("nbsp 4242\u{A0}4242\u{A0}4242\u{A0}4242", "nbsp [redacted]"),
    ])
    func cards(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("leaves numbers that are not card numbers", arguments: [
        "order 4242424242424241", "timestamp 1700000000000", "id ab4242424242424242", "4242424242424242ab",
        "uuid 123456789012345678901234", "phone +90 555 123 45 67",
    ])
    func notCards(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("finds email addresses", arguments: [
        ("contact alice@example.com.", "contact a•••@example.com."),
        ("<bob.smith+news@mail.example.org>", "<b•••@mail.example.org>"),
        ("fullwidth ａｌｉｃｅ@ｅｘａｍｐｌｅ.ｃｏｍ", "fullwidth a•••@example.com"),
        // `＠` is punctuation outside ASCII, which cuts the text: the address is hidden whole.
        ("fullwidth ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "fullwidth [redacted]"),
        ("hidden al\u{200D}ice@example.com", "hidden [redacted]"),
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
        #expect(redactor.redact("sent \(signed) end") == "sent [redacted] end")
        #expect(redactor.redact("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.") == "[redacted]")
        #expect(redactor.redact("eyJ is not a token") == "eyJ is not a token")
        #expect(redactor.redact("eyJabc.def") == "eyJabc.def")
    }

    @Test("replaces bearer tokens wherever they appear")
    func bearerTokens() {
        #expect(redactor.redact("sent bearer  sk_live_0123456789 to server") == "sent bearer  [redacted] to server")
        #expect(redactor.redact("bearer short") == "bearer short")
        #expect(SensitiveDataRedactor(kinds: .bearerTokens).redact("Authorization: Bearer abc.DEF-123_456") == "Authorization: Bearer [redacted]")
    }

    @Test("kinds limit what is redacted")
    func kinds() {
        let emailsOnly = SensitiveDataRedactor(kinds: .emailAddresses)
        #expect(emailsOnly.redact("alice@example.com password=x 4242424242424242") == "a•••@example.com password=x 4242424242424242")
        #expect(SensitiveDataRedactor(kinds: []).redact("password=x") == "password=x")
        #expect(SensitiveDataRedactor(kinds: []).redact("a\u{2028}b") == "a\u{2028}b")
    }

    @Test("matches report kind and range in the original text")
    func matches() {
        let text = "mail bob@example.com, paid=4242424242424242 ok"
        let found = redactor.matches(in: text)
        #expect(found.map(\.kind) == [.emailAddresses, .secretFields])
        #expect(found.map { String(text[$0.range]) } == ["bob@example.com", "4242424242424242 ok"])
        #expect(redactor.matches(in: "a b").isEmpty)
        // A line separator outside ASCII cuts the text: the cut is a match of its own.
        let separated = "a\u{2028}b"
        #expect(redactor.matches(in: separated).map { String(separated[$0.range]) } == ["\u{2028}b"])
    }

    @Test("leaves text in other scripts unchanged; an emoji, a dash or a symbol outside ASCII cuts it")
    func unchangedText() {
        let text = "Merhaba dünya, заказ 42 отправлен; 東京 3:00 iPhoneで決済しました"
        #expect(redactor.redact(text) == text)
        #expect(redactor.redact("") == "")
        #expect(redactor.redact("Merhaba dünya 👋🏽 bye") == "Merhaba dünya [redacted]")
        #expect(redactor.redact("заказ — №42") == "заказ [redacted]")
        #expect(redactor.redact("заказ №42") == "заказ [redacted]")
    }

    @Test("the allowlists are folded, and secret or non-ASCII names cannot be added")
    func allowlists() {
        let custom = SensitiveDataRedactor(allowedTextKeys: ["Request-ID", "api_key", "ｓｔａｔｅ"], allowedQueryParameters: ["Page", "token"])
        #expect(custom.allowedTextKeys == ["status", "method", "path", "durationms", "count", "requestid"])
        #expect(!custom.allowedTextKeys.contains("apikey"))
        #expect(custom.allowedTextKeys.allSatisfy { $0.unicodeScalars.allSatisfy(\.isASCII) })
        #expect(custom.allowedQueryParameters == ["page"])
        #expect(custom.redact("request_id=42 api_key=k1") == "request_id=42 api_key=[redacted]")
        #expect(SensitiveDataRedactor().allowedQueryParameters.isEmpty)
    }
}
