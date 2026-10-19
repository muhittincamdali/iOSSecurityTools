import Foundation
import Testing
@testable import iOSSecurityTools

/// Free text keeps a value only after an allowed key: keys made up at random, plain or not, never
/// keep theirs. Allowed keys, and plain names that hold no secret word in structured input, stay
/// readable, so the redactor stays useful.
@Suite("SensitiveDataRedactor allowlist property tests")
struct RedactionAllowlistPropertyTests {
    let redactor = SensitiveDataRedactor()

    static let keyCharacters = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
    /// Put into a key: letters outside ASCII, invisible characters, a mark, a full-width letter,
    /// brackets, punctuation, escapes, a filler and a control character.
    static let insertions = [
        "\u{E9}", "\u{131}", "\u{430}", "\u{DF}", "\u{540D}", "\u{200B}", "\u{301}", "\u{FF53}", "[0]", "()", "$", "@", "/", "%41",
        "&#65;", "\\u0041", "\u{115F}", "\u{7F}", "\\", "\u{2028}",
    ]
    static let separators = [
        "=", ":", ": ", " = ", " : ", ":=", "=>", "\u{FF1D}", "\u{FF1A}", "\u{FE13}", "==", "\t=\t", " :\n  ", "=\n", "\u{2254}",
        "\u{A789}", " \u{2192} ", "%3D", "&#61;",
    ]
    static let valueForms: [@Sendable (String) -> String] = [
        { $0 }, { "\"\($0)\"" }, { "'\($0)'" }, { "[\"\($0)\"]" }, { "{\"x\":\"\($0)\"}" }, { "<\($0)>" }, { "(\($0))" },
        { "`\($0)`" }, { "\\\"\($0)\\\"" }, { "\"a\n\($0)\"" }, { "'a\n  \($0)'" }, { "`a\n\($0)`" },
    ]
    static let contexts: [(before: String, after: String)] = [
        ("", ""), ("INFO ", " next"), ("status=200 ", " count=3"), ("a, ", ", b"), ("[x] ", "\nline2"), ("{", "}"), ("- ", ""),
        ("2026-10-19T12:00:00Z ", ""), ("msg=\"", "\""), ("x;", ";y"), ("| ", " |"), ("log: {\"m\":\"", "\"}"),
    ]
    static let allowedFolds = Set(SensitiveDataRedactor.defaultAllowedTextKeys.map { $0.replacingOccurrences(of: "_", with: "") })

    /// A key of 1 to 10 name characters, with something else put into a third of them.
    static func key(using random: inout SeededRandom) -> String {
        var key = String((0..<Int.random(in: 1...10, using: &random)).map { _ in keyCharacters.randomElement(using: &random)! })
        if Int.random(in: 0..<3, using: &random) == 0 {
            let offset = Int.random(in: 0...key.count, using: &random)
            key.insert(contentsOf: insertions.randomElement(using: &random)!, at: key.index(key.startIndex, offsetBy: offset))
        }
        return key
    }

    @Test("no value after a key that is not on the allowlist shows, whatever the key, separator and value form")
    func randomKeysHideTheirValue() {
        var random = SeededRandom(seed: 0xC3C3_0001)
        var checked = 0
        for _ in 0..<20_000 {
            let key = Self.key(using: &random)
            let folded = key.lowercased().filter { $0.isLetter || $0.isNumber }
            guard !Self.allowedFolds.contains(folded), key.first.map({ $0.isLetter || $0.isNumber }) == true else { continue }
            let value = RedactionPropertyTests.value(using: &random)
            let context = Self.contexts.randomElement(using: &random)!
            let input = context.before + key + Self.separators.randomElement(using: &random)!
                + Self.valueForms.randomElement(using: &random)!(value) + context.after
            let output = redactor.redact(input)
            #expect(!RedactionPropertyTests.leaks(value, in: output), "\(input.debugDescription) -> \(output.debugDescription)")
            checked += 1
        }
        #expect(checked > 15_000)
    }

    @Test("allowed keys keep their value in free text", arguments: [
        "GET /v1/users status=200 duration_ms=12 count=3",
        "status: 200 method: GET path: /v1/orders/42",
        "retry attempt=2 limit=50 offset=100 page=3 level=info",
        "{\"status\":\"ok\",\"count\":3}",
        "Order 1234 shipped to Istanbul at 12:30",
        "Request finished in 12 ms",
        "Kullan\u{131}c\u{131} giri\u{15F} yapt\u{131} status=200",
    ])
    func allowedKeysInText(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("keys the app allows keep their value in free text")
    func configuredKeysInText() {
        let configured = SensitiveDataRedactor(allowedTextKeys: ["user", "region", "build-number", "password", "p\u{430}ss"])
        #expect(configured.redact("login user=bob region=eu-west-1 build_number=512") == "login user=bob region=eu-west-1 build_number=512")
        // A key that names a secret or is not plain ASCII is never allowed.
        #expect(configured.redact("password=hunter2") == "password=[redacted]")
        #expect(configured.redact("p\u{430}ss=hunter2") == "p\u{430}ss=[redacted]")
    }

    /// Plain ASCII names that hold no secret word as a word.
    static let keptNames = [
        "user", "username", "name", "id", "user_id", "requestId", "X-Request-Id", "Content-Type", "status", "region", "lang", "page",
        "limit", "city", "order-id", "retry_after", "tokenizer", "secretary", "bypass", "compass", "passport", "session_start",
        "sessionCount", "keyboard", "spinner", "author", "description", "app.version", "first name",
    ]
    static let keptValues = ["bob", "42", "eu-west-1", "ok", "Istanbul", "v2"]

    @Test("plain ASCII names that hold no secret word keep their value in structured input", arguments: keptNames)
    func keptInStructuredInput(name: String) {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? name
        for value in Self.keptValues {
            let json = "{\"\(name)\":\"\(value)\",\"list\":[{\"\(name)\":\"\(value)\"}]}"
            #expect(redactor.redact(body: Data(json.utf8), contentType: "application/json") == json)
            #expect(redactor.redact("log \(json)") == "log \(json)")
            let form = "a=1&\(encoded)=\(value)"
            #expect(redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded") == form)
        }
    }

    /// Words that hold no secret word, for names made of several of them.
    static let plainWords = ["user", "name", "order", "id", "city", "status", "page", "item", "count", "region", "build", "app", "version", "request", "color", "first", "last"]

    @Test("generated plain ASCII names keep their value in structured input, and in text when allowed")
    func generatedPlainNamesKeepTheirValue() {
        var random = SeededRandom(seed: 0x9A1D_5E)
        for _ in 0..<600 {
            let words = (0..<Int.random(in: 1...3, using: &random)).map { _ in
                let word = Self.plainWords.randomElement(using: &random)!
                return Bool.random(using: &random) ? word.capitalized : word
            }
            let name = words.joined(separator: ["_", "-", ".", ""].randomElement(using: &random)!)
            let spaced = words.joined(separator: " ")
            let value = Self.keptValues.randomElement(using: &random)!
            for json in ["{\"\(name)\":\"\(value)\"}", "{\"\(spaced)\":[\"\(value)\"]}"] {
                #expect(redactor.redact(body: Data(json.utf8), contentType: "application/json") == json)
            }
            let form = "a=1&\(name)=\(value)"
            #expect(redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded") == form)
            let allowing = SensitiveDataRedactor(allowedTextKeys: [name])
            let allowedByDefault = Self.allowedFolds.contains(words.joined().lowercased())
            for input in ["\(name)=\(value)", "log \(name): \(value) done"] {
                #expect(allowing.redact(input) == input)
                #expect((redactor.redact(input) == input) == allowedByDefault)
            }
        }
    }

    // A plain name that holds a secret word as a word hides its value even when it only
    // describes the secret: telling the two apart would take a list of exceptions.
    @Test("names that hold a secret word as a word hide their value in structured input", arguments: [
        "passwordHint", "token_type", "pin_length", "pass_count", "password_policy", "keyPath", "card_type", "auth_method",
        "otp_enabled", "cookie_policy", "secret_name", "signature_version",
    ])
    func describingNamesHideTheirValue(name: String) {
        #expect(redactor.redact(body: Data("{\"\(name)\":\"bob\"}".utf8), contentType: "application/json") == "{\"\(name)\":\"[redacted]\"}")
        #expect(redactor.redact(body: Data("\(name)=bob".utf8), contentType: "application/x-www-form-urlencoded") == "\(name)=[redacted]")
    }
}
