import Foundation
import Testing
@testable import iOSSecurityTools

/// A quoted key in free text (`"…": value`, `"…"=value`) follows the key rule: unless its folded
/// form is on `allowedTextKeys`, the text is cut at its opening quote, so nothing written in the
/// quotes shows. The sixteenth review got values past the reading of quoted keys as JSON names,
/// whose words are not triggers, on every path that reads free text: a secret name, a word in two
/// scripts and a tag inside the quotes showed what came after them (`cache miss for "session
/// Qz9Wk7rX": refetching`). In structured JSON the names of members are shown and their values
/// hidden.
@Suite("SensitiveDataRedactor quoted keys in free text")
struct RedactionQuotedKeyTests {
    let redactor = SensitiveDataRedactor()

    /// The sixteenth review's lines, which showed the secret in the quotes on all six paths.
    static let reviewLines = [
        #""password hunter2": x"#, #"cache miss for "session Qz9Wk7rX": refetching"#, #"wrong "pin 4321": retry"#,
        "\"p\u{0430}ssword hunter2\": x", #""<password>hunter2</password>": x"#, #""status=ok password hunter2": 1"#,
        #""pass word hunter2": x"#, #""p|wd hunter2": x"#, #""my token is hunter2": ok"#, #""status: password hunter2": 1"#,
        #""password hunter2"=x"#, "\"password hunter2\"\n: x", #"{\"password hunter2\": 1}"#, #""\"password hunter2\":1": 2"#,
        #"{"password hunter2": 1}"#, #"["password hunter2","x"]"#,
    ]

    @Test("a quoted key that is not allowed shows nothing of itself or what follows, on every path", arguments: reviewLines)
    func reviewLinesOnEveryPath(line: String) {
        for (path, output) in RedactionCutRuleTests.everyPath(line) {
            for secret in ["hunter2", "Qz9Wk7rX", "4321"] {
                #expect(!output.contains(secret), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("the text is cut at the opening quote of a key that is not allowed", arguments: [
        (#"cache miss for "session Qz9Wk7rX": refetching"#, "cache miss for [redacted]"),
        (#""password hint": 1"#, "[redacted]"),
        (#"see "user=bob": 1"#, "see [redacted]"),
        (#"see \"user\": \"bob\""#, "see [redacted]"),
        (#"see \\\"user\\\": 1"#, "see [redacted]"),
        (#""status": "ok", "user": "bob""#, #""status": "ok", [redacted]"#),
        (#""status"="ok" "user"="bob""#, #""status"="ok" [redacted]"#),
        (#"{"status":200,"user":"bob"}"#, #"{"status":200,[redacted]"#),
        (#"got {"password hunter2": 1} ok"#, "got {[redacted]"),
        (#"got ["user","bob"] ok"#, "got [[redacted]"),
        (#""(status": 1"#, "[redacted]"),
        (#""stat us": 1"#, "[redacted]"),
        ("\"\u{200B}status\": 1", "[redacted]"),
        ("\"st\u{0430}tus\": 1", "[redacted]"),
    ])
    func cuts(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("allowed quoted keys keep their values, also when the app allows a key", arguments: [
        #""status": "ok", "count": 3"#, #""duration_ms": 12"#, #""STATUS": "ok""#, #"{"status":200,"count":1}"#, #""method"="GET""#,
        #"[["status","200"]]"#, "\"status\" : \"ok\"\n\"count\": 2",
    ])
    func allowedKeys(line: String) {
        #expect(redactor.redact(line) == line)
        #expect(redactor.redact(body: Data(line.utf8), contentType: "text/plain") == line)
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["user"])
        #expect(allowing.redact(line + #" "user": "bob""#) == line + #" "user": "bob""#)
    }

    @Test("the names of members in structured JSON are shown and their values hidden")
    func structuredNames() {
        let body = #"{"password hunter2":"x","api key Qz9Wk7rX":1,"status":"ok"}"#
        #expect(redactor.redact(body: Data(body.utf8), contentType: "application/json")
            == #"{"password hunter2":"[redacted]","api key Qz9Wk7rX":"[redacted]","status":"ok"}"#)
    }

    @Test("a key longer than any allowed key is turned down before it is read")
    func longKeys() {
        let key = String(repeating: "a", count: PlainName.maximumKeyLength + 1)
        #expect(redactor.redact("ok \"\(key)\": 1") == "ok [redacted]")
        #expect(SensitiveDataRedactor(allowedTextKeys: [key]).redact("ok \"\(key)\": 1") == "ok [redacted]")
    }

    // MARK: Property

    /// What generated keys are written of: secret names, words in two scripts, tags, keys and
    /// URLs written inside them, escapes, separators, and plain words.
    static let pieces: [@Sendable (inout SeededRandom) -> String] = [
        { random in DisguisedName.secretNames.randomElement(using: &random)! },
        { random in DisguisedName.make(using: &random) },
        { random in ["p\u{0430}ssword", "\u{0442}oken", "se\u{0441}ret", "pin\u{0441}", "к\u{0435}y"].randomElement(using: &random)! },
        { random in "<" + DisguisedName.secretNames.randomElement(using: &random)! + ">" },
        { random in "</" + ["password", "pin", "a"].randomElement(using: &random)! + ">" },
        { random in ["status=ok", "user=bob", "x: y", "a&#61;b", "%3D", "\\u003d", "https://x.example/?token=a"].randomElement(using: &random)! },
        { random in ["status", "count", "ok", "cache", "miss", "for", "the", "wrong", "my", "is"].randomElement(using: &random)! },
        { random in [" ", "  ", "|", ",", ";", "-", "_", ".", "/", "\t", "\u{00A0}", "\u{200B}", "\u{00AD}"].randomElement(using: &random)! },
    ]

    /// How the key is written: quotes, the separator after it, and what holds it.
    static let shapes: [@Sendable (String, String) -> String] = [
        { k, v in "\"\(k)\": \(v)" }, { k, v in "\"\(k)\"=\(v)" }, { k, v in "\"\(k)\" : \(v)" }, { k, v in "\"\(k)\"\n: \(v)" },
        { k, v in "log \"\(k)\": \"\(v)\" done" }, { k, v in "\\\"\(k)\\\": \(v)" }, { k, v in "{\"\(k)\": \"\(v)\"}" },
        { k, v in "status=200 \"\(k)\":\(v)" }, { k, v in "\"status\": 1, \"\(k)\": \(v)" },
    ]

    @Test("no generated quoted key shows a secret written in it or after it, on any path")
    func generatedKeys() {
        var random = SeededRandom(seed: 0x51_6B_E7)
        var checked = 0
        for _ in 0..<700 {
            let inside = RedactionPropertyTests.value(using: &random)
            var key: [String] = []
            for _ in 0..<Int.random(in: 1...4, using: &random) { key.append(Self.pieces.randomElement(using: &random)!(&random)) }
            key.insert(" " + inside, at: Int.random(in: 0...key.count, using: &random))
            let joined = key.joined().replacingOccurrences(of: "\"", with: "")
            // A key that holds a secret name or cannot be read is the point; a plain key on the
            // allowlist would be read on by design, and is checked by the usefulness tests.
            guard !redactor.allowsTextKey(joined.unicodeScalars) else { continue }
            let value = RedactionPropertyTests.value(using: &random)
            let line = Self.shapes.randomElement(using: &random)!(joined, value)
            for (path, output) in RedactionCutRuleTests.everyPath(line) {
                #expect(!RedactionPropertyTests.leaks(inside, in: output), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
            }
            checked += 1
        }
        #expect(checked > 600)
    }
}
