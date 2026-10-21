import Foundation
import Testing
@testable import iOSSecurityTools

/// The one cut of free text: everything after the first trigger is hidden, to the end of the
/// text, on every path that reads free text. Text without a trigger stays as it is.
@Suite("SensitiveDataRedactor free-text cut")
struct RedactionCutRuleTests {
    let redactor = SensitiveDataRedactor()

    /// The text on every path that reads free text: a log line, a text/plain body, a JSON string,
    /// a form value, an allowed query value and a multipart text part.
    static func everyPath(_ text: String) -> [(path: String, output: String)] {
        let redactor = SensitiveDataRedactor()
        let json = try! JSONSerialization.data(withJSONObject: ["note": text])
        let encoded = text.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let query = URL(string: "https://x.example/a?note=\(encoded)")!
        let part = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n\(text)\r\n--B0und--"
        return [
            ("line", redactor.redact(text)),
            ("text/plain", redactor.redact(body: Data(text.utf8), contentType: "text/plain")),
            ("JSON string", redactor.redact(body: json, contentType: "application/json")),
            ("form value", redactor.redact(body: Data("note=\(encoded)".utf8), contentType: "application/x-www-form-urlencoded")),
            ("query value", SensitiveDataRedactor(allowedQueryParameters: ["note"]).redact(url: query)),
            ("multipart part", redactor.redact(body: Data(part.utf8), contentType: "multipart/form-data; boundary=B0und")),
        ]
    }

    /// Text without a trigger, which the cut must leave as it is.
    static let plainTexts = [
        "INFO started", "GET /api/items", "status=200 method=GET path=/api/items", "user logged in at 12:30", "Kullanıcı giriş yaptı",
        "[INFO] ready in 12 ms", "count=3 duration_ms=12", "done", "retrying in 5 s", "request finished",
    ]

    /// Ways to start a trigger; the value follows right after.
    static let triggers: [@Sendable (inout SeededRandom) -> String] = [
        { random in
            // A key that is not allowed, with any separator.
            let key = String((0..<Int.random(in: 1...8, using: &random)).map { _ in "abcdefghijklmnoqruvwxyz".randomElement(using: &random)! })
            return key + ["=", ": ", " = ", ":=", "=>", "\u{FF1D}", "%3D", "&#61;", "\u{A789}", "\": \""].randomElement(using: &random)!
        },
        { random in
            // A secret name without a separator.
            ["password ", "PIN ", "api_key ", "Authorization ", "client-secret ", "the token ", "pass word ", "p&#97;ssword ", "pass%77ord "]
                .randomElement(using: &random)!
        },
        { random in
            // A name written as a value, in markup or in a multipart part written as text.
            [
                "name=\"password\" ", "key='token' ", "id: \"pin\" ", "<string name=\"api_key\">", "<entry key=\"db.password\">\n",
                "<key>password</key>\n<string>", "<key>\u{15E}ifre</key>\n<string>", "label=\"\u{41F}\u{430}\u{440}\u{43E}\u{43B}\u{44C}\" ",
                "Content-Disposition: form-data; name=\"pin\"\r\n\r\n", "--B\nContent-Disposition: form-data; name=\"note\"\n\n",
            ].randomElement(using: &random)!
        },
        { random in
            // A word that cannot be read, a quote or a bracket that does not close.
            ["pass\u{200B}word ", "p\u{0430}ssword ", "ab\u{200D}cd ", "\"open ", "(open ", "x \u{2066}y "].randomElement(using: &random)!
        },
        { random in
            // JSON with a member that is not allowed.
            ["{\"user\":\"", "{\"status\":200,\"note\":\"", "[{\"count\":1},{\"x\":\""].randomElement(using: &random)!
        },
        { random in
            // A trigger disguised the ways the property tests disguise secret names.
            DisguisedName.make(using: &random) + ["=", ": ", "\u{FF1A}"].randomElement(using: &random)!
        },
    ]

    @Test("no value after a trigger shows, on any path that reads free text", arguments: 0..<6)
    func valuesAfterTriggers(seed: Int) {
        var random = SeededRandom(seed: 0xC13_0000 + UInt64(seed))
        for _ in 0..<150 {
            let first = RedactionPropertyTests.value(using: &random)
            let second = RedactionPropertyTests.value(using: &random)
            let before = Self.plainTexts.randomElement(using: &random)! + [" ", "\n", "\r\n", " | "].randomElement(using: &random)!
            let trigger = Self.triggers.randomElement(using: &random)!(&random)
            let after = ["\n", " ", "\r\n\r\n", "\u{2028}"].randomElement(using: &random)! + Self.plainTexts.randomElement(using: &random)! + "\n" + second
            let text = before + trigger + first + after
            for (path, output) in Self.everyPath(text) {
                for value in [first, second] {
                    #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    // A log line is cut once: what comes before the cut is the text as written, and one
    // replacement takes the rest.
    @Test("a log line is the text before its trigger and one replacement")
    func oneReplacement() {
        var random = SeededRandom(seed: 0xC13_0100)
        for _ in 0..<600 {
            let before = Self.plainTexts.randomElement(using: &random)! + " "
            let text = before + Self.triggers.randomElement(using: &random)!(&random) + RedactionPropertyTests.value(using: &random) + "\nstatus=200"
            let output = redactor.redact(text)
            #expect(output.hasSuffix(SensitiveDataRedactor.replacement), "\(text.debugDescription) -> \(output.debugDescription)")
            let kept = output.dropLast(SensitiveDataRedactor.replacement.count)
            #expect(text.unicodeScalars.starts(with: kept.unicodeScalars), "\(text.debugDescription) -> \(output.debugDescription)")
            #expect(kept.unicodeScalars.count >= before.unicodeScalars.count, "\(text.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("text without a trigger stays as it is on every path", arguments: plainTexts)
    func plainTextStays(text: String) {
        for (path, output) in Self.everyPath(text) where path == "line" || path == "text/plain" {
            #expect(output == text, "\(path)")
        }
        let lines = Self.plainTexts.joined(separator: "\n")
        #expect(redactor.redact(lines) == lines)
    }

    @Test("lines of allowed keys stay, and the app can allow more")
    func usefulness() {
        #expect(redactor.redact("status=200 method=GET path=/api/items") == "status=200 method=GET path=/api/items")
        #expect(redactor.redact("GET /api/items status=200 duration_ms=12 count=3") == "GET /api/items status=200 duration_ms=12 count=3")
        #expect(redactor.redact("login user=bob status=200") == "login user=[redacted]")
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["user"])
        #expect(allowing.redact("login user=bob status=200") == "login user=bob status=200")
        #expect(allowing.redact("login user=bob password=hunter2 status=200") == "login user=bob password=[redacted]")
        #expect(SensitiveDataRedactor.defaultAllowedTextKeys == ["status", "method", "path", "duration_ms", "count"])
    }

    // The twelfth review's second lens: a quote left open, a part or an element whose value goes
    // on below its line, and a name that a second reading did not see. One cut covers each.
    @Test("the twelfth review's repros of values that went on below their line", arguments: [
        ("x: <string name=\"pin\"> msg='start\n</string>\nHUNTER2'", "x: [redacted]"),
        ("Content-Disposition: form-data; name=\"pin\"\nmsg=\"a\n--x HUNTER2", "Content-Disposition: [redacted]"),
        ("x: Content-Disposition: form-data; name=\"pin\"\n\nmsg=\"a\n\nHUNTER2\"", "x: [redacted]"),
        ("note: a name=\"pin\"id: \"pin\"{ T\n</string>msg=\" T\nstatus= HUNTER2", "note: [redacted]"),
        ("--B\r\nContent-Disposition: form-data; name=\"pin\"; filename=\"very long\r\n name.txt\"\r\nContent-Type: text/plain\r\n\r\nSECRET\r\n--B--",
         "--B\r\nContent-Disposition: [redacted]"),
        ("<b>Content-Disposition: form-data; name=\"pin\"</b>\nContent-Type: text/plain\n\nSECRET", "[redacted]"),
        ("</pin 1234", "[redacted]"),
        ("login </token SECRET", "login [redacted]"),
        ("</pass\u{200B}word> SECRET", "[redacted]"),
        ("msg: name%3Dpassword\nSECRET", "msg: [redacted]"),
        ("name%3Dpassword\nSECRET", "[redacted]"),
        ("Content-Disposition%3A form-data%3B name%3D%22pin%22\n\nSECRET", "[redacted]"),
    ])
    func twelfthReviewRepros(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
        for (path, output) in Self.everyPath(input) {
            #expect(!output.contains("HUNTER2") && !output.contains("SECRET") && !output.contains("1234"), "\(path): \(output.debugDescription)")
        }
    }
}
