import Foundation
import Testing
@testable import iOSSecurityTools

/// Name and value pairs with generated names: a disguised secret name, or a random key that is not
/// plain ASCII, never lets the value beside it show, in any of the shapes that carry a name apart
/// from its value. Plain names that hold no secret word keep their values.
@Suite("SensitiveDataRedactor name and value pair property tests")
struct RedactionPairPropertyTests {
    let redactor = SensitiveDataRedactor()

    static let nameFields = ["name", "key", "field", "header", "param", "path", "k", "n", "Name", "PATH"]
    static let valueFields = ["value", "val", "values", "content", "data", "secret", "v", "Value"]

    /// A name as one reference token of a JSON Pointer: `~` and `/` escaped as `~0` and `~1`.
    static func pointerToken(_ name: String) -> String {
        name.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
    }

    /// Ways to carry name `n` and value `v` apart: as JSON text, in a body of the given type.
    static func shapes(_ n: String, _ v: String, using random: inout SeededRandom) -> [(text: String, contentType: String)] {
        let name = DisguisedName.json(n)
        let nameField = nameFields.randomElement(using: &random)!
        let valueField = valueFields.randomElement(using: &random)!
        let named = nameField.lowercased() == "path" ? "/" + DisguisedName.json(pointerToken(n)) : name
        let prefix = ["", "/user", "/a/0", "/credentials"].randomElement(using: &random)!
        let pointer = prefix + "/" + DisguisedName.json(pointerToken(n))
        return [
            (#"[{"\#(nameField)":"\#(named)","\#(valueField)":"\#(v)"}]"#, "application/json"),
            (#"{"headers":[{"\#(nameField)":"\#(named)","x":1,"\#(valueField)":["\#(v)",{"a":"\#(v)"}]}]}"#, "application/json"),
            (#"[{"op":"replace","path":"\#(pointer)","value":"\#(v)"}]"#, "application/json-patch+json"),
            (#"{"Operations":[{"op":"add","path":"\#(DisguisedName.json(pointerToken(n)))","value":{"x":"\#(v)"}}]}"#, "application/scim+json"),
            (#"[["\#(name)","\#(v)"],["status","ok"]]"#, "application/json"),
            (#"{"init":{"headers":[["\#(name)",["\#(v)"]]]}}"#, "application/json"),
        ]
    }

    @Test("no disguised secret name lets the value of its pair show")
    func disguisedNames() {
        var random = SeededRandom(seed: 0xA1_2B_0008)
        for _ in 0..<1_500 {
            let name = DisguisedName.make(using: &random)
            let value = RedactionPropertyTests.value(using: &random)
            for (text, contentType) in Self.shapes(name, value, using: &random) {
                let body = redactor.redact(body: Data(text.utf8), contentType: contentType)
                let line = redactor.redact("request body=\(text) status=200")
                #expect(!RedactionPropertyTests.leaks(value, in: body), "\(text.debugDescription) -> \(body.debugDescription)")
                #expect(!RedactionPropertyTests.leaks(value, in: line), "\(text.debugDescription) -> \(line.debugDescription)")
            }
        }
    }

    @Test("no random name that is not plain ASCII lets the value of its pair show")
    func randomNames() {
        var random = SeededRandom(seed: 0xA1_2B_0009)
        var checked = 0
        for _ in 0..<4_000 {
            let name = RedactionAllowlistPropertyTests.key(using: &random)
            // `-` alone is the index past the end of an array in a JSON Pointer, not a name.
            guard PlainName(name.unicodeScalars) == nil, name != "-" else { continue }
            let value = RedactionPropertyTests.value(using: &random)
            for (text, contentType) in Self.shapes(name, value, using: &random) {
                let body = redactor.redact(body: Data(text.utf8), contentType: contentType)
                #expect(!RedactionPropertyTests.leaks(value, in: body), "\(text.debugDescription) -> \(body.debugDescription)")
            }
            checked += 1
        }
        #expect(checked > 1_000)
    }

    @Test("plain names without a secret word keep the value of their pair")
    func plainNamesKeepValues() {
        var random = SeededRandom(seed: 0xA1_2B_000A)
        var checked = 0
        for _ in 0..<4_000 {
            let name = RedactionAllowlistPropertyTests.key(using: &random)
            guard let plain = PlainName(name.unicodeScalars), !plain.namesSecret else { continue }
            // Without vowels, `s`, `p`, `c`, `k`, `v` and `w` the value spells no secret word, which
            // free text would read in it.
            let value = String((0..<12).map { _ in "BDFGHJLMNRTXYZ23456789".randomElement(using: &random)! })
            let nameField = ["name", "header", "param", "path", "n"].randomElement(using: &random)!
            let valueField = ["value", "val", "values", "content", "data", "v"].randomElement(using: &random)!
            let named = nameField == "path" ? "/a/" + name : name
            for text in [#"[{"\#(nameField)":"\#(named)","\#(valueField)":"\#(value)"}]"#, #"[["\#(name)","\#(value)"]]"#] {
                #expect(redactor.redact(body: Data(text.utf8), contentType: "application/json") == text)
            }
            checked += 1
        }
        #expect(checked > 1_000)
    }
}
