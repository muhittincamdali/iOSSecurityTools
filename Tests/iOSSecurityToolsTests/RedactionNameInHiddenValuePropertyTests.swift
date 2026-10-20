import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated secret names written as values inside the hidden value of another key — a part
/// header of a multipart body written to a log, a header line, a YAML block, a quoted message —
/// disguised the ways ``DisguisedName`` disguises them: the secret that follows never shows, on
/// any path that reads free text. Plain names that hold no secret word keep what follows them.
@Suite("SensitiveDataRedactor names inside hidden values property tests")
struct RedactionNameInHiddenValuePropertyTests {
    let redactor = SensitiveDataRedactor()

    /// Ways to write a name `n` inside the value of another key, and the secret `v` after it.
    static let shapes: [@Sendable (String, String) -> String] = [
        { n, v in "Content-Disposition: form-data; name=\"\(n)\"\r\n\r\n\(v)" },
        { n, v in "--B\r\nContent-Disposition: form-data; name=\"\(n)\"\r\nContent-Type: text/plain\r\n\r\n\(v)\r\n--B--" },
        { n, v in "upload failed body=--B\nContent-Disposition: form-data; name=\"\(n)\"\n\n\(v)\n--B--" },
        { n, v in "note: a name=\"\(n)\"\n\(v)" },
        { n, v in "x-debug: field label='\(n)'\n\n\(v)" },
        { n, v in "token: |\n  key=\"\(n)\"\n\n\(v)" },
        { n, v in "msg: <string name=\"\(n)\">\n\(v)\n</string>" },
        { n, v in "msg: id: \"\(n)\" \(v)" },
    ]

    /// Ways to write an unquoted name, which ends at white space, inside such a value.
    static let unquotedShapes: [@Sendable (String, String) -> String] = [
        { n, v in "Content-Disposition: form-data; name=\(n)\r\n\r\n\(v)" },
        { n, v in "note: a key=\(n)\n\(v)" },
    ]

    func outputs(_ text: String) -> [String] {
        let string = try! JSONSerialization.data(withJSONObject: ["note": text])
        return [
            redactor.redact(text),
            redactor.redact(body: Data(text.utf8), contentType: "text/plain"),
            redactor.redact(body: string, contentType: "application/json"),
        ]
    }

    @Test("no disguised secret name inside a hidden value lets what follows it show")
    func disguisedNames() {
        var random = SeededRandom(seed: 0xA1_2B_0120)
        for _ in 0..<1_500 {
            let name = RedactionNameAsValuePropertyTests.name(using: &random)
            let value = RedactionPropertyTests.value(using: &random)
            let text = Self.shapes.randomElement(using: &random)!(name, value)
            for output in outputs(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("no disguised unquoted secret name inside a hidden value lets what follows it show")
    func unquotedNames() {
        var random = SeededRandom(seed: 0xA1_2B_0121)
        var checked = 0
        while checked < 800 {
            let name = RedactionNameAsValuePropertyTests.name(using: &random)
            // An unquoted name ends at white space and at the characters that end a word.
            guard !name.unicodeScalars.contains(where: { $0.properties.isWhitespace || ",;&?|([{=:".unicodeScalars.contains($0) }) else { continue }
            let value = RedactionPropertyTests.value(using: &random)
            let text = Self.unquotedShapes.randomElement(using: &random)!(name, value)
            for output in outputs(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(text.debugDescription) -> \(output.debugDescription)")
            }
            checked += 1
        }
    }

    @Test("plain names without a secret word inside a hidden value keep the text after them")
    func plainNamesKeepText() {
        var random = SeededRandom(seed: 0xA1_2B_0122)
        var checked = 0
        for _ in 0..<4_000 {
            let name = RedactionAllowlistPropertyTests.key(using: &random)
            guard let plain = PlainName(name.unicodeScalars), !plain.namesSecret,
                  !FreeTextScanner.mentionsSecret(Array(name.unicodeScalars), compatibility: CompatibilityText())
            else { continue }
            // Without vowels, `s`, `p`, `c`, `k`, `v` and `w` the text spells no secret word.
            let text = String((0..<12).map { _ in "BDFGHJLMNRTXYZ23456789".randomElement(using: &random)! })
            for output in outputs("Content-Disposition: form-data; name=\"\(name)\"\r\n\r\n\(text)") + outputs("note: a name=\"\(name)\"\n\(text)") {
                #expect(output.contains(text), "\(name.debugDescription) -> \(output.debugDescription)")
            }
            checked += 1
        }
        #expect(checked > 1_000)
    }
}
