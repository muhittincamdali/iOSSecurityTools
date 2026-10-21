import Foundation
import Testing
@testable import iOSSecurityTools

/// SplitMix64: a small random source with a fixed seed, so every run checks the same cases and
/// a failure can be repeated.
struct SeededRandom: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Secret field names disguised the ways attackers and accidents disguise them.
enum DisguisedName {
    static let secretNames = [
        "password", "passwd", "pwd", "pass", "token", "secret", "api_key", "apiKey", "x-api-key", "access_token",
        "refreshToken", "client_secret", "Authorization", "session_id", "sessionId", "private_key", "passphrase",
        "id_token", "SECRET_KEY", "db_password", "otp", "cvv", "cvc", "ssn", "pin", "key", "auth", "sid", "card", "iban",
        "cookie", "set-cookie", "signature", "credentials", "passcode", "tokens", "pinCode", "card_number",
    ]

    /// Letters of other scripts that look like Latin ones.
    static let lookAlikes: [Character: [String]] = [
        "a": ["\u{0430}", "\u{03B1}", "\u{0251}"], "c": ["\u{0441}", "\u{03F2}"], "d": ["\u{0501}"], "e": ["\u{0435}", "\u{03B5}"],
        "i": ["\u{0456}", "\u{0131}"], "k": ["\u{043A}", "\u{03BA}"], "n": ["\u{0578}"], "o": ["\u{043E}", "\u{03BF}", "\u{0585}"],
        "p": ["\u{0440}", "\u{03C1}"], "s": ["\u{0455}"], "t": ["\u{03C4}"], "w": ["\u{051D}"], "x": ["\u{0445}"], "y": ["\u{0443}"],
    ]
    static let formatCharacters = [
        "\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{00AD}", "\u{FEFF}", "\u{200E}", "\u{202E}", "\u{2066}", "\u{180E}", "\u{2063}", "\u{E0061}",
    ]
    static let marks = ["\u{0301}", "\u{0308}", "\u{0336}", "\u{FE0F}"]
    /// Characters that split a name without ending it; `,`, `;`, `&`, `?`, quotes and brackets end
    /// a name, and `=` and `:` are separators.
    static let separators = [".", "/", "+", "~", "|", "*", "#", "!", "@", "$", "^", "\\", "\u{00B7}", "\u{2027}", "\u{FF0E}", "\u{FF3F}", "\u{2010}"]
    static let whitespace = [" ", "  ", "\t", "\u{00A0}", "\u{2009}", "\u{3000}"]

    /// A secret name with one to three disguises.
    static func make(using random: inout SeededRandom) -> String {
        var name = Array(secretNames.randomElement(using: &random)!).map(String.init)
        for _ in 0..<Int.random(in: 1...3, using: &random) {
            disguise(&name, using: &random)
        }
        return name.joined()
    }

    static func disguise(_ name: inout [String], using random: inout SeededRandom) {
        let letters = name.indices.filter { name[$0].count == 1 && name[$0].first!.isASCII && name[$0].first!.isLetter }
        guard let index = letters.randomElement(using: &random) else { return }
        let letter = name[index].first!
        let gap = Int.random(in: 1..<name.count, using: &random)
        switch Int.random(in: 0..<8, using: &random) {
        case 0: if let lookAlike = lookAlikes[Character(letter.lowercased())]?.randomElement(using: &random) { name[index] = lookAlike }
        case 1: name[index] = styled(letter, using: &random)
        case 2: name.insert(formatCharacters.randomElement(using: &random)!, at: gap)
        case 3: name.insert(marks.randomElement(using: &random)!, at: index + 1)
        case 4: name.insert(separators.randomElement(using: &random)!, at: gap)
        case 5: name.insert(whitespace.randomElement(using: &random)!, at: gap)
        case 6: name[index] = escaped(letter, using: &random)
        default: name[index] = Bool.random(using: &random) ? letter.uppercased() : letter.lowercased()
        }
    }

    /// Mathematical bold, full-width or circled forms.
    private static func styled(_ letter: Character, using random: inout SeededRandom) -> String {
        let offset = letter.lowercased().unicodeScalars.first!.value - 0x61
        let base: UInt32 = [0x1D41A, 0xFF41, 0x24D0].randomElement(using: &random)!
        return String(Unicode.Scalar(base + offset)!)
    }

    private static func escaped(_ letter: Character, using random: inout SeededRandom) -> String {
        let value = letter.unicodeScalars.first!.value
        let hex = String(value, radix: 16)
        return ["%" + hex, "%25" + hex, "&#\(value);", "&#x" + hex + ";", "\\u00" + hex, "\\u{" + hex + "}", "\\x" + hex].randomElement(using: &random)!
    }

    /// The name as the content of a JSON string.
    static func json(_ name: String) -> String {
        JSONDocument.escaped(name)
    }

    /// The name percent-encoded for a form body.
    static func form(_ name: String) -> String {
        name.utf8.map { ASCII.isAlphanumeric($0) ? String(UnicodeScalar($0)) : String(format: "%%%02X", $0) }.joined()
    }
}

@Suite("SensitiveDataRedactor property tests")
struct RedactionPropertyTests {
    let redactor = SensitiveDataRedactor()

    /// Ways to write a field with name `n` and value `v` as free text, JSON or JSON inside text.
    static let textFormats: [@Sendable (String, String) -> String] = [
        { n, v in "\(n)=\(v)" },
        { n, v in "\(n): \(v)" },
        { n, v in "\(n) = \"\(v)\"" },
        { n, v in "\(n)='\(v)'" },
        { n, v in "\(n)\u{FF1A}\(v)" },
        { n, v in "\(n) := \(v)" },
        { n, v in "INFO user=bob \(n)=\(v) next=1" },
        { n, v in "{\"\(DisguisedName.json(n))\":\"\(v)\"}" },
        { n, v in "{\"a\":{\"\(DisguisedName.json(n))\":[\"\(v)\",{\"x\":\"\(v)\"}]}}" },
        { n, v in "[{\"\(DisguisedName.json(n))\":\"\(v)\"},{\"\(DisguisedName.json(n))\":\"\(v)\"}]" },
        { n, v in "log: {\"\(DisguisedName.json(n))\": \"\(v)\", \"\(DisguisedName.json(n))\": \"\(v)\"}" },
        { n, v in "{\\\"\(DisguisedName.json(DisguisedName.json(n)))\\\":\\\"\(v)\\\"}" },
        { n, v in "{\"wrapper\":\"{\\\"\(DisguisedName.json(DisguisedName.json(n)))\\\":\\\"\(v)\\\"}\"}" },
        { n, v in "{\"q\":\"a=1&\(DisguisedName.json(n))=\(v)&b=2\"}" },
        { n, v in "msg=\"\(DisguisedName.json(n)): \(v)\" status=500" },
    ]

    /// A value with nothing in it that other text could contain by chance.
    static func value(using random: inout SeededRandom) -> String {
        "Q" + String((0..<11).map { _ in "ABCDEFGHJKLMNPRSTUVWXYZ23456789".randomElement(using: &random)! })
    }

    /// Whether any six characters of the value show in the output.
    static func leaks(_ value: String, in output: String) -> Bool {
        let characters = Array(value)
        return (0...(characters.count - 6)).contains { output.contains(String(characters[$0..<($0 + 6)])) }
    }

    @Test("no disguised secret name leaks its value from text")
    func disguisedNamesInText() {
        var random = SeededRandom(seed: 0x5EC2_E7)
        for _ in 0..<1_500 {
            let name = DisguisedName.make(using: &random)
            let value = Self.value(using: &random)
            let input = Self.textFormats.randomElement(using: &random)!(name, value)
            let output = redactor.redact(input)
            #expect(!Self.leaks(value, in: output), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    static let separators = [
        "=", ":", ": ", " = ", ":=", " == ", "=>", "+=", "?=", "!=", "\u{FF1D}", "\u{FF1A}", "\u{FE13}", "\u{2254}", "%3D",
        "&#61;", "\\u003A", "\n=\n", " :\n  ", "\t=\t", "\u{00A0}:\u{00A0}",
    ]
    static let contexts: [(before: String, after: String)] = [
        ("", ""), ("INFO ", " next=1"), ("user=bob ", "&b=2"), ("\u{0414}\u{0430}\u{043D}\u{043D}\u{044B}\u{0435} ", " \u{0434}\u{0430}"),
        ("[x] ", "\nnext line"), ("a, ", ", \"z\": 1}"), ("x;", ""), ("?", "&b=2"), ("{", "}"), ("(", ")"), ("log: \"", "\""),
        ("\u{200B}", ""), ("- ", ""), ("2026-10-15T12:00:00Z ", ""),
    ]
    static let prefixes = ["", "", "user_", "x-", "my_", "DB_", "app."]

    private static func valueForm(_ value: String, using random: inout SeededRandom) -> String {
        [value, "\"\(value)\"", "'\(value)'", "[\"\(value)\"]", "{\"x\":\"\(value)\"}", "(\(value))", "<\(value)>",
         "\\\"\(value)\\\"", "`\(value)`", "\(value)==", "Bearer \(value)"].randomElement(using: &random)!
    }

    @Test("no disguised secret name leaks its value whatever the separator, context or value form")
    func disguisedNamesInContext() {
        var random = SeededRandom(seed: 0xC0_47E7)
        for _ in 0..<1_500 {
            let name = Self.prefixes.randomElement(using: &random)! + DisguisedName.make(using: &random)
            let value = Self.value(using: &random)
            let context = Self.contexts.randomElement(using: &random)!
            let input = context.before + name + Self.separators.randomElement(using: &random)!
                + Self.valueForm(value, using: &random) + context.after
            let output = redactor.redact(input)
            #expect(!Self.leaks(value, in: output), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("no disguised secret name leaks its value from a body")
    func disguisedNamesInBodies() {
        var random = SeededRandom(seed: 0xB0D1_E5)
        for _ in 0..<600 {
            let name = DisguisedName.make(using: &random)
            let value = Self.value(using: &random)
            let quoted = name.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            // A mark or a joiner after `&` forms one Character with it; the form is still split there.
            let glue = (DisguisedName.marks + ["\u{200D}", "\u{20DD}"]).randomElement(using: &random)!
            let bodies: [(String, String?)] = [
                ("{\"\(DisguisedName.json(name))\":\"\(value)\",\"n\":[{\"\(DisguisedName.json(name))\":1}]}", "application/json"),
                ("a=1&\(DisguisedName.form(name))=\(value)&b=2", "application/x-www-form-urlencoded"),
                ("status=1&\(glue)\(DisguisedName.form(name))=\(value)&b=2", "application/x-www-form-urlencoded"),
                ("a=1&\(DisguisedName.form(name))=\(value)", nil),
                ("--B\r\nContent-Disposition: form-data; name=\"\(quoted)\"\r\n\r\n\(value)\r\n--B--", "multipart/form-data; boundary=B"),
            ]
            let (body, type) = bodies.randomElement(using: &random)!
            let output = redactor.redact(body: Data(body.utf8), contentType: type)
            #expect(!Self.leaks(value, in: output), "\(body.debugDescription) -> \(output.debugDescription)")
        }
    }

    static let ambiguousSeparators = ["\t", "  ", " | ", "\u{A789}", " \u{2192} ", "\u{2025}", " \u{2014} ", "%u003D", "&#61"]

    // Where no `=` or `:` follows, a word is read for a secret name after its escapes are decoded,
    // with punctuation inside it and a space or `|` between two words read as a separator, and a
    // letter without an ASCII form read as any letter; a word that mixes scripts or holds an
    // invisible character is not read at all. Each disguise leaves one of these.
    @Test("a secret name disguised once hides the value after a character that might be a separator")
    func disguisedNamesBeforeAmbiguousSeparators() {
        var random = SeededRandom(seed: 0xA3B1_6E)
        for _ in 0..<1_500 {
            var name = Array(DisguisedName.secretNames.randomElement(using: &random)!).map(String.init)
            DisguisedName.disguise(&name, using: &random)
            let value = Self.value(using: &random)
            let context = Self.contexts.randomElement(using: &random)!
            let input = context.before + name.joined() + Self.ambiguousSeparators.randomElement(using: &random)! + value + context.after
            let output = redactor.redact(input)
            #expect(!Self.leaks(value, in: output), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }
}
