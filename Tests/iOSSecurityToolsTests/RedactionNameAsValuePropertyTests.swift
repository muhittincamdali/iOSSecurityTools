import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated secret names written as values, disguised the ways ``DisguisedName`` disguises them,
/// in the shapes of free text, XML, HTML, property lists and JSON objects: the secret that follows
/// never shows. Plain names that hold no secret word keep what follows them.
@Suite("SensitiveDataRedactor names written as values property tests")
struct RedactionNameAsValuePropertyTests {
    let redactor = SensitiveDataRedactor()

    /// Ways to write a name `n` as a value and the secret `v` after it, as free text.
    static let textShapes: [@Sendable (String, String) -> String] = [
        { n, v in "field name=\"\(n)\" \(v)" },
        { n, v in "key='\(n)' \(v) end" },
        { n, v in "id: \"\(n)\"\n\(v)" },
        { n, v in "label=\"\(n)\", \(v)" },
        { n, v in "<string name=\"\(n)\">\(v)</string>" },
        { n, v in "<entry key=\"\(n)\">\n\(v)\n</entry>" },
        { n, v in "<input type=\"text\" path=\"\(v)\" name=\"\(n)\">" },
        { n, v in "<param name=\"\(n)\" value=\"x\">\n  \(v)\n</param>" },
        { n, v in "<string name=\"\(n)\" />\(v)" },
        { n, v in "<key>\(n)</key>\n<string>\(v)</string>" },
        { n, v in "<dict>\n  <key>\(n)</key>\n  <string>a\n\(v)</string>\n</dict>" },
    ]

    /// Ways to write them in a JSON object.
    static let jsonShapes: [@Sendable (String, String) -> String] = [
        { n, v in #"{"label":"\#(n)","value":"\#(v)"}"# },
        { n, v in #"{"type":"\#(n)","input":"\#(v)"}"# },
        { n, v in #"[{"ParameterKey":"\#(n)","ParameterValue":"\#(v)"}]"# },
        { n, v in #"{"title":"\#(n):","data":{"x":["\#(v)"]}}"# },
    ]

    /// A disguised secret name that XML can hold in an attribute and an element: without quotes,
    /// angle brackets and line breaks of its own.
    static func name(using random: inout SeededRandom) -> String {
        while true {
            let name = DisguisedName.make(using: &random)
            if !name.contains(where: { "\"'<>&\\\n".contains($0) }) { return name }
        }
    }

    @Test("no disguised secret name written as a value lets what follows it show")
    func disguisedNames() {
        var random = SeededRandom(seed: 0xA1_2B_0090)
        for _ in 0..<1_500 {
            let name = Self.name(using: &random)
            let value = RedactionPropertyTests.value(using: &random)
            let text = Self.textShapes.randomElement(using: &random)!(name, value)
            let string = try! JSONSerialization.data(withJSONObject: ["note": text])
            let outputs = [
                redactor.redact(text),
                redactor.redact(body: Data(text.utf8), contentType: "text/plain"),
                redactor.redact(body: string, contentType: "application/json"),
            ]
            for output in outputs {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(text.debugDescription) -> \(output.debugDescription)")
            }
            let json = Self.jsonShapes.randomElement(using: &random)!(DisguisedName.json(name), value)
            let body = redactor.redact(body: Data(json.utf8), contentType: "application/json")
            #expect(!RedactionPropertyTests.leaks(value, in: body), "\(json.debugDescription) -> \(body.debugDescription)")
        }
    }

    @Test("plain names without a secret word keep the text after them")
    func plainNamesKeepText() {
        var random = SeededRandom(seed: 0xA1_2B_0091)
        var checked = 0
        for _ in 0..<4_000 {
            let name = RedactionAllowlistPropertyTests.key(using: &random)
            guard let plain = PlainName(name.unicodeScalars), !plain.namesSecret,
                  !FreeTextScanner.mentionsSecret(Array(name.unicodeScalars), compatibility: CompatibilityText())
            else { continue }
            // Without vowels, `s`, `p`, `c`, `k`, `v` and `w` the text spells no secret word.
            let text = String((0..<12).map { _ in "BDFGHJLMNRTXYZ23456789".randomElement(using: &random)! })
            #expect(redactor.redact("<string name=\"\(name)\">\(text)</string>").contains(text))
            #expect(redactor.redact("name=\"\(name)\" \(text)").contains(text))
            let json = #"{"label":"\#(name)","value":"\#(text)"}"#
            #expect(redactor.redact(body: Data(json.utf8), contentType: "application/json") == json)
            checked += 1
        }
        #expect(checked > 1_000)
    }
}
