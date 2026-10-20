import Foundation
import Testing
import iOSSecurityTools

/// Layouts that spread a name and its value over lines: a property list writes `<key>password</key>`
/// and its value on lines of their own, and JSON after `name=` may span lines. They need nothing
/// carried from line to line: the first trigger hides every line after it.
@Suite("SensitiveDataRedactor values over several lines")
struct RedactionMultiLineTests {
    static let secret = "Xq7Secret"
    let redactor = SensitiveDataRedactor()

    /// The text on every path that reads free text: a log line, a JSON string, a text/plain body,
    /// a form value and a multipart part.
    static func everyPath(_ text: String) -> [(String, String)] {
        let redactor = SensitiveDataRedactor()
        let json = "{\"log\":\"" + RedactionStackTests.escaped(text).replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r").replacingOccurrences(of: "\t", with: "\\t") + "\"}"
        let form = "note=" + (text.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")
        let multipart = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n" + text + "\r\n--B0und--"
        return [
            ("line", redactor.redact(text)),
            ("JSON string", redactor.redact(body: Data(json.utf8), contentType: "application/json")),
            ("text/plain", redactor.redact(body: Data(text.utf8), contentType: "text/plain")),
            ("form value", redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded")),
            ("multipart part", redactor.redact(body: Data(multipart.utf8), contentType: "multipart/form-data; boundary=B0und")),
        ]
    }

    private func expectHidden(_ text: String, sourceLocation: SourceLocation = #_sourceLocation) {
        for (path, output) in Self.everyPath(text) {
            #expect(!output.contains(Self.secret), "\(path): \(text.debugDescription) -> \(output.debugDescription)", sourceLocation: sourceLocation)
        }
    }

    // Review probes 360 and 367–374 of the eleventh review, with the secret as S.
    @Test("a property list's value on the lines below its key is hidden", arguments: [
        "<key>password</key>\n<string/>\nS",
        "\t<key>password</key>\n\t<string/>\n\tS",
        "<key>password</key>\n<string/> S",
        "<key>password</key>\n<string/>S",
        "<key>password</key>\n\n<string/>\nS",
        "<key>api_key</key>\r\n<string />\r\nS",
        "<key>Şifre</key>\n<string/>\nS",
        "<key>token</key>\n<data/> S",
        "<key>password</key>\n<data/>\nS",
        "<key>password</key>\n<string>S</string>",
        "<key>password</key>\n  <string>\n    S\n  </string>",
        "<key>password</key>\n<string>a</string> S",
        "<key>password</key>\n<string></string>\nS",
        "<string name=\"password\"></string>\nS",
        "<string name=\"password\">\n</string>\nS",
        "<string name=\"password\">\na\n</string> S",
    ])
    func propertyListLines(layout: String) {
        expectHidden(layout.replacingOccurrences(of: "S", with: Self.secret))
    }

    // Review probes 328, 329, 382 and 383 of the eleventh review.
    @Test("JSON over several lines after a key that holds a name hides the rest of the line where it closes", arguments: [
        "name=[\n\"pin\"\n] S",
        "name={\"a\":\n\"pin\"} S",
        "key=[\n\"x\",\n] S",
        "label=[\n  \"pin\"\n]\nS",
        "field={\n\"a\": [\n1\n]\n} S",
    ])
    func jsonOverLines(layout: String) {
        expectHidden(layout.replacingOccurrences(of: "S", with: Self.secret))
    }

    @Test("a trigger on one line hides every line after it, and text without one stays")
    func cutOverLines() {
        // `<key>` is itself the secret word `key`, so a property list is hidden from its first key.
        #expect(redactor.redact("<key>CFBundleName</key>\n<string/>\nMyApp") == "<key>[redacted]")
        #expect(redactor.redact("<key>password</key>\n<string>k-1</string>\nnext") == "<key>[redacted]")
        #expect(redactor.redact("<string name=\"title\"></string>\nHello") == "<string name=[redacted]")
        #expect(redactor.redact("status=[\n1,\n2\n] ok") == "status=[\n1,\n2\n] ok")
        #expect(redactor.redact("started\nstatus=200\ncount=3\ndone") == "started\nstatus=200\ncount=3\ndone")
        // After an allowed key that holds a name, a plain name is read on over the lines.
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["name"])
        #expect(allowing.redact("<string name=\"title\"></string>\nHello") == "<string name=\"title\"></string>\nHello")
    }

    /// Generated layouts of a property list and of JSON after `name=`, with names that are secret
    /// or not plain ASCII, on every path.
    @Test("a value laid out over lines in any of these ways never shows", arguments: 0..<4)
    func generatedLayouts(seed: Int) {
        var random = SeededRandom(seed: UInt64(seed) + 211)
        let names = ["password", "api_key", "Şifre", "token", "client_secret", "ⓟⓘⓝ", "Пароль"]
        let empties = ["<string/>", "<string />", "<string></string>", "<data/>", "<string>\n</string>"]
        for _ in 0..<60 {
            let indent = ["", "\t", "  "].randomElement(using: &random)!
            let lineEnd = ["\n", "\r\n"].randomElement(using: &random)!
            let blank = Bool.random(using: &random) ? lineEnd : ""
            let name = names.randomElement(using: &random)!
            let value: String
            switch Int.random(in: 0..<5, using: &random) {
            case 0: value = empties.randomElement(using: &random)! + lineEnd + indent + Self.secret
            case 1: value = empties.randomElement(using: &random)! + " " + Self.secret
            case 2: value = "<string>" + Self.secret + "</string>"
            case 3: value = "<string>" + lineEnd + indent + "  " + Self.secret + lineEnd + indent + "</string>"
            default: value = empties.randomElement(using: &random)! + lineEnd + blank + indent + Self.secret
            }
            expectHidden(indent + "<key>" + name + "</key>" + lineEnd + blank + indent + value)
            let open = Bool.random(using: &random)
            let json = (open ? "[" : "{\"a\":") + lineEnd + indent + "\"" + name + "\"" + (Bool.random(using: &random) ? "," : "") + lineEnd
                + (open ? "]" : "}")
            let after = Bool.random(using: &random) ? " " + Self.secret : lineEnd + Self.secret
            expectHidden(["name=", "key=", "label=", "id="].randomElement(using: &random)! + json + after)
        }
    }
}
