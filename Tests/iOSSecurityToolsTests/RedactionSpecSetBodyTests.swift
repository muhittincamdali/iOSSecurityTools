import Foundation
import Testing
import iOSSecurityTools

/// The required test set of the shared redaction spec (REDACTION-SPEC 2.1-r2, §8), ported to this
/// package's API: §8.1 keys and bodies (§2, §4) and §8.2 control characters and held names (§2 K11).
/// Each case is the spec's input and the output this package writes for it (`[R]` is
/// ``SensitiveDataRedactor/replacement``). The numbers are the spec's. §8.1 #17c, a text past the
/// reading limit of 2^28 − 1 scalars, is in ``RedactionTextLengthLimitTests``: its texts are made
/// with a limit lowered for the test, and its spans at the real limit.
@Suite("Redaction spec §8.1–8.2: keys, bodies and held names")
struct RedactionSpecSetBodyTests {
    let redactor = SensitiveDataRedactor()

    func json(_ text: String) -> String { redactor.redact(body: Data(text.utf8), contentType: "application/json") }
    func form(_ text: String) -> String { redactor.redact(body: Data(text.utf8), contentType: "application/x-www-form-urlencoded") }
    func omitted(_ text: String, _ type: String) -> String { "[body omitted: \(text.utf8.count) bytes, \(type)]" }

    @Test("§8.1 #1–#10: JSON names are compared after decoding, at every repetition, and held names hide their values", arguments: [
        (#"{"user":"bob","password":"hunter2"}"#, #"{"user":"bob","password":"[redacted]"}"#),
        (#"{"password":"hunter2","id":"7"}"#, #"{"password":"[redacted]","id":"7"}"#),
        (#"{"PASS-WORD":"a","pass.word":"b","created_at":"c"}"#, #"{"PASS-WORD":"[redacted]","pass.word":"[redacted]","created_at":"c"}"#),
        (
            #"{"p\#u{0430}ssword":"x","şifre":"y","user[id]":"z","ok":"1"}"#,
            #"{"p\#u{0430}ssword":"[redacted]","şifre":"[redacted]","user[id]":"[redacted]","ok":"1"}"#
        ),
        (#"{"token":"a","token":"b"}"#, #"{"token":"[redacted]","token":"[redacted]"}"#),
        (#"{"password":{"a":[1,2]},"x":1}"#, #"{"password":"[redacted]","x":1}"#),
        (#"{"note":"password=hunter2","ok":"fine"}"#, #"{"note":"password=[redacted]","ok":"fine"}"#),
        (
            #"[{"op":"replace","path":"/user/password","value":"hunter2"},{"op":"replace","path":"/status","value":"active"}]"#,
            #"[{"op":"replace","path":"/user/password","value":"[redacted]"},{"op":"replace","path":"/status","value":"active"}]"#
        ),
        (
            #"[{"label":"Şifre","value":"hunter2"},{"label":"ⓟⓘⓝ","value":"1234"},{"label":"status","value":"ok"}]"#,
            #"[{"label":"Şifre","value":"[redacted]"},{"label":"[redacted]","value":"[redacted]"},{"label":"status","value":"ok"}]"#
        ),
        (#"[["Authorization","Bearer abc"],["Accept","x"]]"#, #"[["Authorization","[redacted]"],["Accept","x"]]"#),
    ])
    func names(input: String, expected: String) {
        #expect(json(input) == expected)
    }

    @Test("§8.1 #11–#13: JSON that JSONSerialization would read differently, another type, or too deep, is omitted")
    func omittedBodies() {
        for text in [#"{"a":1,}"#, #"{"a":NaN}"#, #"{"a":1}{"b":2}"#] {
            #expect(json(text) == omitted(text, "application/json"), "\(text)")
        }
        let xml = "<password>hunter2</password>"
        #expect(redactor.redact(body: Data(xml.utf8), contentType: "application/xml") == "[body omitted: 28 bytes, application/xml]")
        let deep = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
        #expect(json(deep) == "[body omitted: 130 bytes, application/json]")
        let deepInString = #"{"note":""# + String(repeating: "[", count: 64) + String(repeating: "]", count: 64) + #" ok"}"#
        #expect(json(deepInString) == #"{"note":"[redacted]"}"#)
    }

    @Test("§8.1 #14–#16: a strict form is read with the key and held-name rules; any other is omitted")
    func forms() {
        #expect(
            form("p%D0%B0ssword=a&pass.word=b&user%5Bname%5D=c&user.name=bob")
                == "p%D0%B0ssword=[redacted]&pass.word=[redacted]&user%5Bname%5D=[redacted]&user.name=bob")
        for text in ["a=1;b=2", "a=100%&b=2", "a.b=1&a_b=2"] {
            #expect(form(text) == omitted(text, "application/x-www-form-urlencoded"), "\(text)")
        }
        #expect(form("label=Password&value=hunter2&x=1") == "label=Password&value=[redacted]&x=[redacted]")
    }

    @Test("§8.1 #17–#18: a multipart part header is a key, and a delimiter after a bare LF omits the body")
    func multipart() {
        let type = "multipart/form-data; boundary=B0und"
        let part = "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\nX-4111111111111111: 1\r\nContent-Length: 1\r\n\r\nx\r\n--B0und--"
        let output = redactor.redact(body: Data(part.utf8), contentType: type)
        #expect(output.contains("[redacted]: [redacted]"), "\(output)")
        #expect(output.contains("Content-Length: 1"), "\(output)")
        #expect(!output.contains("4111"), "\(output)")
        let bareLineFeed = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\n--B0und\r\n"
            + "Content-Disposition: form-data; name=\"pin\"\r\n\r\n4831\r\n--B0und--"
        #expect(redactor.redact(body: Data(bareLineFeed.utf8), contentType: type) == omitted(bareLineFeed, "multipart/form-data"))
    }

    @Test("§8.1 #17b: the value of a kept part header is written by its shape, not read as free text", arguments: [
        ("Content-Length: pin-4831", "Content-Length: [redacted]"),
        ("Content-Length: 12 hunter2", "Content-Length: [redacted]"),
        ("Content-Length: \u{0661}\u{0662}", "Content-Length: [redacted]"),
        ("Content-Transfer-Encoding: hunter2", "Content-Transfer-Encoding: [redacted]"),
        ("Content-Transfer-Encoding: BASE64", "Content-Transfer-Encoding: base64"),
        ("Content-Length: 1", "Content-Length: 1"),
    ])
    func partHeaderValues(header: String, expected: String) {
        let part = "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\n\(header)\r\n\r\nx\r\n--B0und--"
        let output = redactor.redact(body: Data(part.utf8), contentType: "multipart/form-data; boundary=B0und")
        #expect(output.components(separatedBy: "\r\n").dropFirst(2).first == expected, "\(output.debugDescription)")
    }

    @Test("§8.1 #19: a content type with a second type is unreadable")
    func contentType() {
        #expect(redactor.redact(body: Data(#"{"a":1}"#.utf8), contentType: "application/json, text/plain") == "[body omitted: 7 bytes, unreadable content type]")
    }

    @Test("§8.2 #20–#24: a control character in a held name, and a string of control characters alone, name a secret", arguments: [
        (#"{"name":"Hello\nWorld","value":"x"}"#, #""value":"[redacted]""#),
        (#"{"note":"pass\nword","id":"7"}"#, #""id":"[redacted]""#),
        (#"{"title":"\n","data":"x"}"#, #""data":"[redacted]""#),
        (#"{"ParameterKey":"\t","ParameterValue":"x"}"#, #"{"ParameterKey":"[redacted]","ParameterValue":"[redacted]"}"#),
        (#"{"ParameterKey":"DbPassword\n","ParameterValue":"x"}"#, #""ParameterValue":"[redacted]""#),
        (#"{"OptionName":"pa\nssword","Value":"x"}"#, #""Value":"[redacted]""#),
    ])
    func controlCharacters(input: String, expected: String) {
        #expect(json(input).contains(expected), "\(json(input))")
    }

    @Test("§8.2 #22–#23: the form of a control character alone hides both values; a message with a line break hides nothing")
    func controlCharacterFormAndMessage() {
        #expect(form("ParameterKey=%0A&ParameterValue=x") == "ParameterKey=[redacted]&ParameterValue=[redacted]")
        let message = #"{"message":"Hello\nWorld","id":"7"}"#
        #expect(json(message) == message)
    }
}
