import Foundation
import Testing
@testable import iOSSecurityTools

/// A secret name written as a value — `name="password"`, `<string name="api_key">`,
/// `<key>password</key>` — names what follows it. In free text, a text/plain body and text inside a
/// JSON string, the text is cut there: `name=` is not an allowed key, after an allowed key that
/// holds a name a secret name or one that is not plain ASCII cuts the text, and markup is never
/// parsed, so the first tag cuts the text at its `<`. In a JSON object, the other members are
/// hidden.
@Suite("SensitiveDataRedactor secret names written as values")
struct RedactionNameAsValueTests {
    let redactor = SensitiveDataRedactor()
    static let secret = "S3CR3Tq"

    /// The text as a log line, as a text/plain body and as a string in a JSON body.
    func outputs(_ text: String) -> [String] {
        let json = try! JSONSerialization.data(withJSONObject: ["note": text])
        return [
            redactor.redact(text),
            redactor.redact(body: Data(text.utf8), contentType: "text/plain"),
            redactor.redact(body: json, contentType: "application/json"),
        ]
    }

    @Test("the ninth review's probes hide the secret after the name", arguments: [
        #"<string name="api_key">S3CR3Tq</string>"#,
        #"<entry key="db.password">S3CR3Tq</entry>"#,
        #"<field id="pin">S3CR3Tq</field>"#,
        #"<param name="token" value="x">S3CR3Tq</param>"#,
        #"<string name="password" />S3CR3Tq"#,
        #"field name="password" S3CR3Tq"#,
        "name='token' S3CR3Tq",
        #"id: "pin" S3CR3Tq"#,
        #"header="Authorization" S3CR3Tq end"#,
        #"label="password", S3CR3Tq"#,
        "note=\"password\"\nS3CR3Tq",
        #"{"xml":"<string name=\"password\">S3CR3Tq</string>"}"#,
    ])
    func reviewProbes(input: String) {
        for output in outputs(input) {
            #expect(!output.contains(Self.secret), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a key that holds a name cuts the text at its value", arguments: [
        (#"<string name="api_key">S3CR3Tq</string>"#, "[redacted]"),
        (#"field name="password" S3CR3Tq"#, "field name=[redacted]"),
        ("name=`token` S3CR3Tq", "name=[redacted]"),
        (#"name=\"token\" S3CR3Tq"#, "name=[redacted]"),
        ("note=\"password\"\u{2028}S3CR3Tq", "note=[redacted]"),
        // The name is read as any word of a line is: disguised, escaped or split.
        ("name=\"p\u{0430}ssword\" S3CR3Tq", "name=[redacted]"),
        ("name=\"pass\u{200B}word\" S3CR3Tq", "name=[redacted]"),
        ("name=\"p&#97;ssword\" S3CR3Tq", "name=[redacted]"),
        ("name=\"pass word\" S3CR3Tq", "name=[redacted]"),
        ("name=\"API Key\" S3CR3Tq", "name=[redacted]"),
    ])
    func restOfLine(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("markup with a name in an attribute is cut at its first tag", arguments: [
        (#"<input path="S3CR3Tq" name="password">"#, "[redacted]"),
        (#"<input value="S3CR3Tq" name="password">"#, "[redacted]"),
        (#"<input name="password" value="S3CR3Tq">"#, "[redacted]"),
        (#"<add key="DbPassword" value="S3CR3Tq" />"#, "[redacted]"),
        (#"<property name="spring.datasource.password" value="S3CR3Tq"/>"#, "[redacted]"),
        (#"<p title="password">S3CR3Tq</p>"#, "[redacted]"),
        (#"<string name="api_key"><![CDATA[S3CR3Tq]]></string>"#, "[redacted]"),
        ("<td>password</td><td>S3CR3Tq</td>", "[redacted]"),
    ])
    func sameElement(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("an element that goes on below its line is hidden with everything after it", arguments: [
        ("<string name=\"password\">\n  S3CR3Tq\n</string>\nstatus=200", "[redacted]"),
        (
            "<string name=\"private_key\">-----BEGIN-----\nS3CR3Tq1\nS3CR3Tq2\n-----END-----</string>\nstatus=200",
            "[redacted]"
        ),
        ("<input\n  name=\"password\"\n  value=\"S3CR3Tq\">\n<p>after</p>", "[redacted]"),
        ("<string name=\"password\"\n  >S3CR3Tq</string>", "[redacted]"),
        ("<param name=\"token\" value=\"x\">\n  S3CR3Tq\n</param>\nstatus=200", "[redacted]"),
    ])
    func linesBelow(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("the element after a key in a property list is hidden with everything after it", arguments: [
        ("<key>password</key><string>S3CR3Tq</string>", "[redacted]"),
        ("<dict>\n\t<key>password</key>\n\t<string>S3CR3Tq\nS3CR3Tq2</string>\n</dict>", "[redacted]"),
        ("<key>password</key> <!-- note -->\n<string>S3CR3Tq</string>", "[redacted]"),
        ("<key>password</key>\nS3CR3Tq\nnext line", "[redacted]"),
        ("<label>Password</label>\n<input value=\"S3CR3Tq\">\n<p>after</p>", "[redacted]"),
    ])
    func siblingElement(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("files that write secrets by name are cut at their first tag", arguments: [
        // Android strings.xml
        (
            "<resources>\n    <string name=\"app_name\">My App</string>\n    <string name=\"api_key\">S3CR3Tq</string>\n    <string name=\"title\">Hello</string>\n</resources>",
            "[redacted]"
        ),
        // Java Properties XML
        (
            "<properties>\n<entry key=\"db.user\">bob</entry>\n<entry key=\"db.password\">\nS3CR3Tq\n</entry>\n<entry key=\"db.url\">jdbc</entry>\n</properties>",
            "[redacted]"
        ),
        // .NET appSettings
        (
            "<add key=\"ConnectionString\" value=\"Server=x;Password=S3CR3Tq\" />\n<add key=\"Mode\" value=\"fast\" />",
            "[redacted]"
        ),
        // Spring beans
        (
            "<bean id=\"ds\"><property name=\"password\" value=\"S3CR3Tq\"/><property name=\"url\" value=\"jdbc:x\"/></bean>",
            "[redacted]"
        ),
    ])
    func configurationFiles(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("after allowed keys, names that are not secret keep what follows them", arguments: [
        (#"name="status" ok"#, #"name="status" ok"#),
        (#"<string name="status">200</string> status=200"#, "[redacted]"),
        (#"user="bob" status=200 path=/x"#, #"user="bob" status=200 path=/x"#),
        (#"name="password" S3CR3Tq"#, #"name="password" [redacted]"#),
        ("name=\"\u{15E}ifre\" S3CR3Tq", "name=\"\u{15E}ifre\" [redacted]"),
        (#"<input path="S3CR3Tq" name="password">"#, "[redacted]"),
        ("login <password> required\nnext line\nlast line", "login [redacted]"),
        ("<token>unclosed\nnext line", "[redacted]"),
    ])
    func plainNames(input: String, expected: String) {
        #expect(SensitiveDataRedactor(allowedTextKeys: ["name", "user", "string"]).redact(input) == expected)
    }

    @Test("a JSON member that names a secret hides the other members", arguments: [
        #"{"label":"Password","value":"S3CR3Tq"}"#,
        #"{"type":"password","value":"S3CR3Tq"}"#,
        #"{"variable":"API_KEY","value":"S3CR3Tq"}"#,
        #"{"ParameterKey":"DbPassword","ParameterValue":"S3CR3Tq"}"#,
        #"{"key":"pin","text":"S3CR3Tq"}"#,
        #"{"label":"API Key:","input":"S3CR3Tq"}"#,
        #"{"title":"pаssword","data2":["S3CR3Tq"]}"#,
        #"{"label":"Password","value":{"x":"S3CR3Tq"}}"#,
        #"[{"op":"replace","path":"/user/password","value":"S3CR3Tq"}]"#,
    ])
    func jsonMembers(input: String) {
        for output in [redactor.redact(body: Data(input.utf8), contentType: "application/json"), redactor.redact("body=" + input)] {
            #expect(!output.contains(Self.secret), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("JSON members beside names that are not secret, sentences and operations stay", arguments: [
        (#"{"label":"Status","value":"ok"}"#, #"{"label":"Status","value":"ok"}"#),
        (#"{"label":"Password","value":"x","op":"add"}"#, #"{"label":"Password","value":"[redacted]","op":"add"}"#),
        (#"{"name":"Cookie","value":"a=b","comment":"x"}"#, #"{"name":"Cookie","value":"[redacted]","comment":"[redacted]"}"#),
        (#"{"msg":"Error: token expired","user":"bob"}"#, #"{"msg":"Error: [redacted]","user":"bob"}"#),
        (#"{"query":"mutation","variables":"{\"password\":\"x\"}"}"#, #"{"query":"mutation","variables":"{[redacted]"}"#),
    ])
    func jsonKeepsPlainMembers(input: String, expected: String) {
        #expect(redactor.redact(body: Data(input.utf8), contentType: "application/json") == expected)
    }

    @Test("the logging guide's examples of names written as values")
    func guideExamples() {
        #expect(redactor.redact("field name=\"password\" hunter2") == "field name=[redacted]")
        #expect(redactor.redact(#"<string name="api_key">k-1</string>"#) == "[redacted]")
        #expect(redactor.redact("<key>password</key>\n<string>k-1</string>") == "[redacted]")
        let pair = #"{"label":"Password","value":"hunter2"}"#
        #expect(redactor.redact(body: Data(pair.utf8), contentType: "application/json") == #"{"label":"Password","value":"[redacted]"}"#)
    }
}
