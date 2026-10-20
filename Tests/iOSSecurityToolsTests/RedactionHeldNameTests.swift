import Foundation
import Testing
@testable import iOSSecurityTools

/// Names are classified by default too: where a name is held — the value of `name`, `key`,
/// `field`, `label`, `type`, `header`, `param`, `path`, `id`, the first element of a pair,
/// `name=`, `key=` and `label=` in free text — a name that is not plain ASCII counts as secret,
/// as a key does, and the value beside it is hidden. One function (``WrittenName``) decides this
/// for every path.
@Suite("SensitiveDataRedactor names held by fields")
struct RedactionHeldNameTests {
    let redactor = SensitiveDataRedactor()
    static let secret = "S3CR3Tq"

    func json(_ text: String) -> String { redactor.redact(body: Data(text.utf8), contentType: "application/json") }

    @Test("a held name that is not plain ASCII hides the value beside it", arguments: [
        #"{"label":"Şifre","value":"S3CR3Tq"}"#,
        #"{"label":"Пароль","value":"S3CR3Tq"}"#,
        #"{"label":"ⓟⓘⓝ","value":"S3CR3Tq"}"#,
        #"{"label":"🄿🄸🄽","value":"S3CR3Tq"}"#,
        #"{"label":"🔑","value":"S3CR3Tq"}"#,
        #"{"label":"★★","value":"S3CR3Tq"}"#,
        #"{"label":"","value":"S3CR3Tq"}"#,
        #"{"type":"𝐩𝐢𝐧","input":"S3CR3Tq"}"#,
        #"{"id":"ⓢⓣⓐⓣⓤⓢ","answer":"S3CR3Tq"}"#,
        #"{"label":"Password (required)","value":"S3CR3Tq"}"#,
        #"{"label":"Your password, please","value":"S3CR3Tq"}"#,
        #"{"label":"pass&#119;ord","value":"S3CR3Tq"}"#,
        #"{"label":{"en":"Password"},"input":"S3CR3Tq"}"#,
        #"{"label":["Password"],"value":"S3CR3Tq"}"#,
        #"{"lab​el":"Пароль","value":"S3CR3Tq"}"#,
        #"[["ⓟⓘⓝ","S3CR3Tq"]]"#,
        #"[["🔑",["S3CR3Tq"]]]"#,
        #"{"op":"replace","path":"/ⓟⓘⓝ","value":"S3CR3Tq"}"#,
    ])
    func heldNamesInJSON(input: String) {
        let output = json(input)
        #expect(!output.contains(Self.secret), "\(input) -> \(output)")
        #expect((try? JSONSerialization.jsonObject(with: Data(output.utf8))) != nil)
    }

    @Test("a member whose value is a name in symbols hides the others, also outside the held fields")
    func symbolNameInAnyMember() {
        // `ParameterKey` ends in the secret word `key`, so its own value is hidden too.
        #expect(json(#"{"ParameterKey":"ⓣⓞⓚⓔⓝ","ParameterValue":"S3CR3Tq"}"#) == #"{"ParameterKey":"[redacted]","ParameterValue":"[redacted]"}"#)
        // The name itself is free text in symbols outside the safe alphabet, so it goes too.
        #expect(json(#"{"Parameter":"ⓣⓞⓚⓔⓝ","ParameterValue":"S3CR3Tq"}"#) == #"{"Parameter":"[redacted]","ParameterValue":"[redacted]"}"#)
        #expect(json(#"{"title":"ⓟⓘⓝ:","x":"S3CR3Tq"}"#) == #"{"title":"[redacted]","x":"[redacted]"}"#)
        #expect(WrittenName.isName(Array("ⓟⓘⓝ".unicodeScalars), compatibility: CompatibilityText()))
        #expect(WrittenName.isName(Array("ⒶⓅⒾ ⓀⒺⓎ".unicodeScalars), compatibility: CompatibilityText()))
        #expect(!WrittenName.isName(Array("🔑".unicodeScalars), compatibility: CompatibilityText()))
    }

    @Test("plain names that are not secret keep the value beside them", arguments: [
        #"{"label":"status","value":"ok"}"#, #"{"type":"text","input":"hello"}"#, #"{"id":"user-42","value":"x"}"#,
        #"{"name":"Display Name","value":"Bob"}"#, #"[["Content-Type","text/plain"]]"#, #"{"op":"add","path":"/tags/-","value":"a"}"#,
    ])
    func plainNamesKeepValues(input: String) {
        #expect(json(input) == input)
    }

    @Test("a field whose own name is not plain ASCII is read as one that holds a name")
    func disguisedHoldingField() {
        // The name is cut at its format character, which is outside the safe alphabet.
        #expect(json(#"{"lab\u200Bel":"x","value":"kept"}"#) == #"{"lab[redacted]":"[redacted]","value":"kept"}"#)
        #expect(json(#"{"lab\u200Bel":"Пароль","value":"S3CR3Tq"}"#) == #"{"lab[redacted]":"[redacted]","value":"[redacted]"}"#)
    }

    /// The cost of the default, named in the documentation: a name in another script hides the
    /// members beside it whatever they hold.
    @Test("a held name in another script hides the members beside it")
    func nonASCIINamesHideOthers() {
        #expect(json(#"{"id":1,"name":"Ayşe","role":"admin"}"#) == #"{"id":"[redacted]","name":"Ayşe","role":"[redacted]"}"#)
        #expect(json(#"{"type":"image/png","data":"AAAA"}"#) == #"{"type":"image/png","data":"[redacted]"}"#)
    }

    @Test("forms, URL queries and multipart bodies follow the same rule")
    func flatFields() {
        let form = { (body: String) in self.redactor.redact(body: Data(body.utf8), contentType: "application/x-www-form-urlencoded") }
        #expect(form("label=Password&value=S3CR3Tq") == "label=Password&value=[redacted]")
        #expect(form("label=%C5%9Eifre&value=S3CR3Tq&name=x") == "label=%C5%9Eifre&value=[redacted]&name=x")
        #expect(form("label=status&value=ok") == "label=status&value=ok")
        let allowing = SensitiveDataRedactor(allowedQueryParameters: ["label", "value"])
        #expect(allowing.redact(url: URL(string: "https://x.example/a?label=Password&value=S3CR3Tq")!) == "https://x.example/a?label=Password&value=[redacted]")
        #expect(allowing.redact(url: URL(string: "https://x.example/a?label=status&value=ok")!) == "https://x.example/a?label=status&value=ok")
        let part = { (name: String, value: String) in "--B\r\nContent-Disposition: form-data; name=\"\(name)\"\r\n\r\n\(value)\r\n" }
        let body = part("label", "\u{24DF}\u{24D8}\u{24DD}") + part("value", "S3CR3Tq") + "--B--"
        let output = redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B")
        #expect(!output.contains(Self.secret), "\(output)")
    }

    // Review probes 184–186 and 189 of the eleventh review: a name the redactor cannot read as
    // text cannot be told not to be secret.
    @Test("a multipart part that holds a name it cannot read as text hides the other parts", arguments: [
        "Content-Transfer-Encoding: base64\r\n\r\nc2VjcmV0",
        "Content-Transfer-Encoding: base64\r\n\r\nxZ5pZnJl",
        "Content-Transfer-Encoding: quoted-printable\r\n\r\nPass=77ord",
        "Content-Type: application/json\r\n\r\n\"password\"",
        "Content-Type: text/plain; charset=iso-8859-9\r\n\r\nSifre",
        "\r\n\u{FFFD}ifre",
    ])
    func unreadableMultipartName(headersAndContent: String) {
        var label = Array("--B\r\nContent-Disposition: form-data; name=\"label\"\r\n\(headersAndContent)\r\n".utf8)
        // The last case carries a byte that is not UTF-8 in place of the replacement character.
        if let replacement = headersAndContent.range(of: "\u{FFFD}") {
            let prefix = Array("--B\r\nContent-Disposition: form-data; name=\"label\"\r\n".utf8) + Array(headersAndContent[..<replacement.lowerBound].utf8)
            label = prefix + [0xDE] + Array(headersAndContent[replacement.upperBound...].utf8) + Array("\r\n".utf8)
        }
        let body = label + Array("--B\r\nContent-Disposition: form-data; name=\"value\"\r\n\r\nS3CR3Tq\r\n--B--".utf8)
        let output = redactor.redact(body: Data(body), contentType: "multipart/form-data; boundary=B")
        #expect(!output.contains(Self.secret), "\(output)")
    }

    @Test("a multipart part that holds a plain name that is not secret, or names nothing, keeps the other parts")
    func readableMultipartParts() {
        let part = { (name: String, headers: String, value: String) in
            "--B\r\nContent-Disposition: form-data; name=\"\(name)\"\r\n\(headers)\r\n\(value)\r\n"
        }
        let plain = part("label", "", "status") + part("value", "", "ok") + "--B--"
        #expect(redactor.redact(body: Data(plain.utf8), contentType: "multipart/form-data; boundary=B").contains("\r\n\r\nok\r\n"))
        let json = part("data", "Content-Type: application/json\r\n", #"{"a":1}"#) + part("note", "", "ok") + "--B--"
        #expect(redactor.redact(body: Data(json.utf8), contentType: "multipart/form-data; boundary=B").contains("\r\n\r\nok\r\n"))
    }

    @Test("in free text, a name after name=, key=, label= that is not plain ASCII hides what follows", arguments: [
        #"label="Пароль" S3CR3Tq"#, #"label="パスワード" S3CR3Tq"#, #"label="Şifre" S3CR3Tq"#, "key=\"🔑\" S3CR3Tq",
        "name='ⓟⓘⓝ' S3CR3Tq", #"name=["pin"] S3CR3Tq"#, #"<string name="Пароль">S3CR3Tq</string>"#, #"<field id="🔑">S3CR3Tq</field>"#,
        "<key>Пароль</key>\n<string>S3CR3Tq</string>", "<string name=\"password\" />\nS3CR3Tq", "<key>password</key><string/>\nS3CR3Tq",
        "passꞏword S3CR3Tq",
    ])
    func heldNamesInText(input: String) {
        let output = redactor.redact(input)
        #expect(!output.contains(Self.secret), "\(input.debugDescription) -> \(output.debugDescription)")
    }

    @Test("the logging guide's examples of names held by fields")
    func guideExamples() {
        let fields = #"[{"label":"Şifre","value":"hunter2"},{"label":"ⓟⓘⓝ","value":"1234"},{"label":"status","value":"ok"}]"#
        #expect(json(fields) == #"[{"label":"Şifre","value":"[redacted]"},{"label":"[redacted]","value":"[redacted]"},{"label":"status","value":"ok"}]"#)
        #expect(json(#"{"name":"Ayşe","role":"admin"}"#) == #"{"name":"Ayşe","role":"[redacted]"}"#)
        #expect(redactor.redact("<string name=\"password\" />\nhunter2") == "<string name=[redacted]")
    }

    @Test("an allowed key that holds a name is read too, and a route under path stays")
    func allowedKeys() {
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["type"])
        #expect(allowing.redact("type=Пароль S3CR3Tq") == "type=[redacted]")
        #expect(allowing.redact("type=status kept") == "type=status kept")
        #expect(redactor.redact("method=GET path=/v1/users/me status=200") == "method=GET path=/v1/users/me status=200")
        #expect(redactor.redact(#"name="status" kept"#) == "name=[redacted]")
        #expect(SensitiveDataRedactor(allowedTextKeys: ["name"]).redact(#"name="status" kept"#) == #"name="status" kept"#)
    }
}
