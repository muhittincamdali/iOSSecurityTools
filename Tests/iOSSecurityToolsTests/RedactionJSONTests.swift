import Foundation
import Testing
@testable import iOSSecurityTools

/// JSON read with the parser, as a body, as a whole text and inside a log line. Redacted JSON is
/// still JSON.
@Suite("SensitiveDataRedactor JSON")
struct RedactionJSONTests {
    let redactor = SensitiveDataRedactor()

    static let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    /// Documents where a detector finds something inside a hidden value or in a number. Before
    /// 2.0.1 the hidden value lost its quotes (`{"credentials":[redacted]}`) and numbers became
    /// masks (`{"amount":•••• 1111}`).
    static let documents: [(String, String)] = [
        (#"{"credentials":{"email":"alice@example.com"}}"#, #"{"credentials":"[redacted]"}"#),
        (#"{"otp":[4111111111111111]}"#, #"{"otp":"[redacted]"}"#),
        (#"{"password":["\#(jwt)"]}"#, #"{"password":"[redacted]"}"#),
        (#"{"pin":{"x":"0123456789abcdef0123456789abcdef"}}"#, #"{"pin":"[redacted]"}"#),
        (#"{"amount":4111111111111111}"#, #"{"amount":"•••• 1111"}"#),
        (#"{"a":-4111111111111111}"#, #"{"a":"-•••• 1111"}"#),
        (#"{"n":12345678901234567890123456789012345}"#, #"{"n":"[redacted]"}"#),
        (#"{"note":"paid 4111 1111 1111 1111","user":"bob"}"#, #"{"note":"paid •••• 1111","user":"bob"}"#),
        (#"[{"token":"\#(jwt)"},{"id":7}]"#, #"[{"token":"[redacted]"},{"id":7}]"#),
        (#"{"a":{"b":[{"api_key":true}]},"c":null}"#, #"{"a":{"b":[{"api_key":"[redacted]"}]},"c":null}"#),
    ]

    @Test("hidden values and masked numbers keep a body valid JSON", arguments: documents)
    func bodiesStayJSON(input: String, expected: String) throws {
        let output = redactor.redact(body: Data(input.utf8), contentType: "application/json")
        #expect(output == expected)
        #expect(try JSONSerialization.jsonObject(with: Data(output.utf8), options: .fragmentsAllowed) is NSObject)
    }

    @Test("a text that is JSON stays valid JSON too", arguments: documents)
    func textStaysJSON(input: String, expected: String) throws {
        let output = redactor.redact(input)
        #expect(output == expected)
        #expect(try JSONSerialization.jsonObject(with: Data(output.utf8), options: .fragmentsAllowed) is NSObject)
    }

    @Test("JSON inside a line stays valid JSON", arguments: documents)
    func embeddedStaysJSON(input: String, expected: String) throws {
        let output = redactor.redact("response \(input) done")
        #expect(output == "response \(expected) done")
    }

    @Test("names are compared at every depth, after their escapes are decoded, for every repetition")
    func names() {
        #expect(redactor.redact(#"{"pass\u0077ord":"x","user":"bob"}"#) == #"{"pass\u0077ord":"[redacted]","user":"bob"}"#)
        #expect(redactor.redact(#"{"a":{"b":{"c":{"token":"x"}}}}"#) == #"{"a":{"b":{"c":{"token":"[redacted]"}}}}"#)
        #expect(redactor.redact(#"{"password":"a","password":"b"}"#) == #"{"password":"[redacted]","password":"[redacted]"}"#)
        #expect(redactor.redact(#"{"p\u0430ssword":"x"}"#) == #"{"p\u0430ssword":"[redacted]"}"#)
        #expect(redactor.redact("{\"p\u{0430}ssword\":\"x\"}") == "{\"p\u{0430}ssword\":\"[redacted]\"}")
        #expect(redactor.redact(#"{"user name":"bob","user.id":7,"user-role":"admin"}"#) == #"{"user name":"bob","user.id":7,"user-role":"admin"}"#)
        #expect(redactor.redact(#"{"user[name]":"bob","café":"x"}"#) == #"{"user[name]":"[redacted]","café":"[redacted]"}"#)
    }

    @Test("a pair written as an array or as a name and value object hides its value", arguments: [
        (#"req {"headers":[["X-Api-Key","k125"]]}"#, #"req {"headers":[["X-Api-Key","[redacted]"]]}"#),
        (#"login ["password","e11"]"#, #"login ["password","[redacted]"]"#),
        (#"["user","bob","token","abc","next"]"#, #"["user","bob","token","[redacted]","[redacted]"]"#),
        (#"[{"name":"Authorization","value":"Basic x"},{"name":"Accept","value":"*/*"}]"#,
         #"[{"name":"Authorization","value":"[redacted]"},{"name":"Accept","value":"*/*"}]"#),
        ("{\"key\":\"p\u{0430}ss\",\"value\":\"x\"}", "{\"key\":\"[redacted]\",\"value\":\"[redacted]\"}"),
        ("{\"key\":\"p\u{0430}ss word\",\"value\":\"x\"}", "{\"key\":\"[redacted]\",\"value\":\"[redacted]\"}"),
    ])
    func pairs(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("JSON in a line is parsed with the parser; a key before it hides it whole", arguments: [
        (#"headers=[["X-Api-Key","k123"]]"#, "headers=[redacted]"),
        (#"data={"user":"bob"} status=1"#, "data=[redacted] status=1"),
        (#"got {"user":"bob","password":"x"} and [{"pin":1}]"#, #"got {"user":"bob","password":"[redacted]"} and [{"pin":"[redacted]"}]"#),
        ("log {\n  \"token\": \"abc\",\n  \"user\": \"bob\"\n} status=1", "log {\n  \"token\": \"[redacted]\",\n  \"user\": \"bob\"\n} status=1"),
        (#"{"wrapper":"{\"password\":\"x\"}"}"#, #"{"wrapper":"{\"password\":\"[redacted]\"}"}"#),
        (#"{"msg":"user=bob status=1"}"#, #"{"msg":"user=[redacted]"}"#),
    ])
    func embedded(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("JSON that does not parse hides the rest of the line, and on until its brackets close", arguments: [
        (#"login {"pass" "word":"e8"}"#, "login [redacted]"),
        (#"login {"pass" "word":"e8"} next"#, "login [redacted]"),
        ("x {\"a\":1,\n\"password\" \"e9\"}\nstatus=1", "x [redacted]\nstatus=1"),
        ("x {\"a\":1,\n\"password\":\"e9\"}\nstatus=1", "x {\"a\":1,\n\"password\":\"[redacted]\"}\nstatus=1"),
        ("x {\"a\":1,\n\"password\":\"e9\"", "x [redacted]"),
        (#"x ["a" "b"] y"#, "x [redacted]"),
        (#"x {"a":1,} y"#, "x [redacted]"),
        (#"x {"a":"\ud800"} y"#, "x [redacted]"),
    ])
    func unparsed(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("brackets that do not open JSON are text", arguments: ["[INFO] ok", "[1/3] done", "{x} done", "user[0] ok", "[] {} ok"])
    func notJSON(input: String) {
        #expect(redactor.redact(input) == input)
    }
}
