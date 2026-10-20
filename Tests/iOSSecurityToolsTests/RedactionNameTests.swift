import Foundation
import Testing
@testable import iOSSecurityTools

/// The secret names: the list the redaction spec shares between the packages, this library's
/// extensions and plural forms, disguised and plain, and the names that only look like them.
@Suite("SensitiveDataRedactor secret names")
struct RedactionNameTests {
    let redactor = SensitiveDataRedactor()

    private func json(_ body: String) -> String { redactor.redact(body: Data(body.utf8), contentType: "application/json") }

    static let sharedNames = [
        "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token", "id_token", "api_key", "apikey",
        "key", "auth", "authorization", "cookie", "set-cookie", "session", "sid", "otp", "pin", "cvv", "card", "iban",
        "ssn", "private_key", "client_secret", "signature",
    ]

    static let extendedNames = [
        "passphrase", "passcode", "credential", "credentials", "cvc", "sessid", "PHPSESSID", "JSESSIONID", "pinCode",
        "otpCode", "verification_code", "security_code", "card_number", "tokens", "secrets", "pwds", "keys", "pins",
        "api_keys", "x-auth-token", "X-Api-Key", "Proxy-Authorization", "X-Amz-Signature", "laravel_session", "userPin",
        "licensekey", "access_key_id", "db.password", "first password",
    ]

    static let value = "Q7kZ2wX9pL"

    /// The field written as free text, JSON, a form and a multipart body.
    private func outputs(name: String) -> [String] {
        let quoted = JSONDocument.escaped(name)
        let form = name.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? name
        return [
            redactor.redact("\(name)=\(Self.value)"),
            redactor.redact("\(name): \(Self.value) next"),
            redactor.redact("log {\"\(quoted)\": \"\(Self.value)\"}"),
            redactor.redact(body: Data("{\"\(quoted)\":{\"v\":[\"\(Self.value)\"]}}".utf8), contentType: "application/json"),
            redactor.redact(body: Data("a=1&\(form)=\(Self.value)".utf8), contentType: "application/x-www-form-urlencoded"),
            redactor.redact(
                body: Data("--B\r\nContent-Disposition: form-data; name=\"\(quoted)\"\r\n\r\n\(Self.value)\r\n--B--".utf8),
                contentType: "multipart/form-data; boundary=B"
            ),
        ]
    }

    @Test("every shared and extended name hides its value", arguments: sharedNames + extendedNames)
    func namesHideTheirValue(name: String) {
        for output in outputs(name: name) {
            #expect(!output.contains("wX9p"), "\(name): \(output)")
        }
    }

    @Test("the new names hide their value however they are disguised", arguments: [
        "\u{043E}tp", "c\u{0441}v", "cv\u{200B}v", "s\u{00AD}sn", "\u{FF50}\u{FF49}\u{FF4E}", "pi\u{0301}n", "%6Bey", "k&#101;y",
        "\u{0430}uth", "co\u{043E}kie", "s\u{0456}d", "ib\u{0430}n", "c\u{0430}rd", "sign\u{0430}ture", "c.v.v", "PIN_code",
        "o t p", "\u{1D41C}\u{1D42F}\u{1D42F}",
    ])
    func disguisedNewNames(name: String) {
        for output in outputs(name: name) {
            #expect(!output.contains("wX9p"), "\(name.debugDescription): \(output)")
        }
    }

    @Test("the inputs that got past the first fix after 2.0.0", arguments: [
        ("{\"otp\":\"123456\",\"cvv\":\"123\",\"ssn\":\"078-05-1120\",\"auth\":\"a\",\"key\":\"k\",\"signature\":\"s\"}",
         "{\"otp\":[redacted]"),
        // In free text an unquoted value goes to the end of its line: `;`, `&` and spaces do not
        // end it, so the pairs after it are hidden with it.
        ("Cookie: session=x; sid=SECRET", "Cookie: [redacted]"),
        ("Set-Cookie: sid=SECRET", "Set-Cookie: [redacted]"),
        ("otp=123456&cvv=123", "otp=[redacted]"),
        ("tokens=a secrets=b pwds=c passcode=d pinCode=e otpCode=f cvc=g credential=h", "tokens=[redacted]"),
        ("pin code: 1234", "pin [redacted]"),
        ("verification code: 123456", "verification code: [redacted]"),
    ])
    func roundTwoInputs(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a form with the new names hides their values")
    func formWithNewNames() {
        let body = Data("otp=123456&cvv=123&user=bob".utf8)
        #expect(redactor.redact(body: body, contentType: "application/x-www-form-urlencoded") == "otp=[redacted]&cvv=[redacted]&user=bob")
    }

    // Short secret words count as a word or at the end of a name, not inside a longer word.
    @Test("names that only hold the letters of a secret word keep their value in structured input", arguments: [
        "keyboard", "pinned", "spinner", "author", "authenticated", "session_start", "sessionCount", "inside", "president",
        "sidebar", "description", "bypass", "passport", "tokenizer", "secretary", "discard_count",
    ])
    func lettersOfSecretWords(name: String) {
        #expect(json("{\"\(name)\":\"bob\"}") == "{\"\(name)\":\"bob\"}")
        let form = Data("\(name)=bob".utf8)
        #expect(redactor.redact(body: form, contentType: "application/x-www-form-urlencoded") == "\(name)=bob")
        // Free text keeps a value only after an allowed key.
        #expect(redactor.redact("\(name)=bob") == "\(name)=[redacted]")
        #expect(SensitiveDataRedactor(allowedTextKeys: [name]).redact("\(name)=bob") == "\(name)=bob")
    }

    // A name that holds a secret word as a word may only describe the secret, but telling the
    // two apart would take a list of exceptions: its value is hidden.
    @Test("names that hold a secret word as a word hide their value", arguments: [
        "keyPath", "key_name", "pin_length", "card_type", "card_brand", "otp_enabled", "auth_method", "authState",
        "signature_version", "cookie_policy", "token_type", "secret_name",
    ])
    func describingNames(name: String) {
        #expect(json("{\"\(name)\":\"bob\"}") == "{\"\(name)\":\"[redacted]\"}")
        let form = Data("\(name)=bob".utf8)
        #expect(redactor.redact(body: form, contentType: "application/x-www-form-urlencoded") == "\(name)=[redacted]")
        #expect(SensitiveDataRedactor(allowedTextKeys: [name]).redact("\(name)=bob") == "\(name)=[redacted]")
    }

    // A name of more than 256 characters is not plain, so its value is hidden; as a word of
    // free text it is longer than the longest word read, so it goes with its value.
    @Test("a long name is compared in time linear in its length and hidden past 256 characters")
    func longNames() {
        let plain = String(repeating: "user", count: 64)
        #expect(json("{\"\(plain)\":\"bob\"}") == "{\"\(plain)\":\"bob\"}")
        #expect(json("{\"\(plain)x\":\"bob\"}") == "{\"[redacted]\":\"[redacted]\"}")
        #expect(SensitiveDataRedactor(allowedTextKeys: [plain]).redact("\(plain)=bob") == "\(plain)=bob")
        #expect(SensitiveDataRedactor(allowedTextKeys: [plain + "x"]).redact("\(plain)x=bob") == "[redacted]")
        let form = Data("\(plain)x=bob".utf8)
        #expect(SensitiveDataRedactor().redact(body: form, contentType: "application/x-www-form-urlencoded") == "[redacted]=[redacted]")
    }
}
