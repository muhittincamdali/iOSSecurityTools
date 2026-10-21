import Foundation
import Testing
@testable import iOSSecurityTools

/// A name with an escape in it is read as written, with the letter that starts a hex escape read
/// as punctuation, and with its escapes decoded; the reading that hides most counts. The
/// twenty-third review found that a word with `%` or `&` was read only decoded, and that decoding
/// takes the first letters of a name for digits of the escape when they are hex letters: `%card`
/// decodes to U+FFFD and `rd`, `&#xcvv` to U+000C and `vv`, so neither named a secret, while
/// `~card` and `card` did. Every path that reads a name written as a value, an array element or a
/// URL path segment showed the value after such a name: the value beside
/// `{"ParameterKey":"%card"}`, the element after `"%cardnumber"`, the form, multipart and allowed
/// query fields after `ParameterKey=%25card`, and the segment after `/%26%23xcvv/`. Read as
/// written, `&#xpass` glues the `x` to `pass`, and a name with the `;` of a character reference
/// (`p&#97;ssword`, `&amp;#xcard`) did not count as a name beside a field that holds no name.
@Suite("SensitiveDataRedactor names read as written and decoded")
struct RedactionEscapeReadingTests {
    static let value = "98765"

    /// Every secret name, as the list holds it and in capitals.
    static let names: [String] = SecretNames.entries.flatMap { entry -> [String] in
        let name = String(decoding: entry.letters, as: UTF8.self)
        return [name, name.uppercased()]
    }

    /// The escape starts the review put before a name: `%` and `&#x` take hex letters after them
    /// as digits, `&#x0` takes them after a zero, and `x%` puts a letter before the escape. `%u`,
    /// `&#` and `&amp;#x` start the other escapes that are decoded.
    static let escapeStarts = ["%", "&#x", "&#X", "&#x0", "x%", "%u", "%U", "&#", "&amp;#x"]

    /// The names with an escape start before them.
    static let escapedNames: [String] = names.flatMap { name in escapeStarts.map { $0 + name } }

    /// The names the review measured or sent, with an escape before or inside them.
    static let reviewNames = [
        "%card", "%cardnumber", "Debit%card", "debit%cardnumber", "&#xcard", "&#xCard", "&#xcvv", "&#xauth",
        "&#xauthorization", "&#xcookie", "&#xcredential",
    ]

    static func scalars(_ text: String) -> [Unicode.Scalar] { Array(text.unicodeScalars) }

    @Test("a name after an escape start reads as it does after a separator")
    func escapeStartReadsAsSeparator() {
        let compatibility = CompatibilityText()
        for name in Self.names {
            let separated = Self.scalars("~" + name)
            let namesSecret = FreeTextScanner.nameNamesSecret(separated, compatibility: compatibility)
            let mentionsSecret = FreeTextScanner.mentionsSecret(separated, compatibility: compatibility)
            #expect(namesSecret && mentionsSecret, "~\(name)")
            for start in Self.escapeStarts {
                let escaped = Self.scalars(start + name)
                #expect(FreeTextScanner.nameNamesSecret(escaped, compatibility: compatibility) == namesSecret, "nameNamesSecret \(start)\(name)")
                #expect(FreeTextScanner.mentionsSecret(escaped, compatibility: compatibility) == mentionsSecret, "mentionsSecret \(start)\(name)")
            }
        }
    }

    @Test("the review's direct measurements")
    func reviewMeasurements() {
        let compatibility = CompatibilityText()
        #expect(FreeTextScanner.nameNamesSecret(Self.scalars("%card"), compatibility: compatibility))
        #expect(FreeTextScanner.mentionsSecret(Self.scalars("%cardnumber"), compatibility: compatibility))
        for name in Self.reviewNames {
            #expect(FreeTextScanner.nameNamesSecret(Self.scalars(name), compatibility: compatibility), "\(name)")
            #expect(FreeTextScanner.mentionsSecret(Self.scalars(name), compatibility: compatibility), "\(name)")
        }
    }

    /// Names that only their decoding spells as a secret name, some with the `;` of a reference.
    static let decodedNames = [
        "pass%77ord", "p&#97;ssword", "p&#97ssword", "pass%2577ord", "&#x70;in", "&#112;in", "&#99;ard", "&#x63;ard",
        "&amp;#x63;ard", "&#x63;&#x76;&#x76;", "c v%2576", "%u0070assword", "%u0063ard",
    ]

    @Test("a decoded name is still read: the decoding hides more where it reads a name")
    func decodedNamesStillRead() {
        let compatibility = CompatibilityText()
        for name in Self.decodedNames {
            #expect(FreeTextScanner.nameNamesSecret(Self.scalars(name), compatibility: compatibility), "\(name)")
        }
    }

    // MARK: Every path

    enum Path: String, CaseIterable, Sendable {
        case jsonPair, jsonOptionPair, jsonAttributePair, jsonArray, jsonTags, form, multipart, allowedQuery, urlPath
    }

    /// `name` written where a name is read, with ``value`` after it.
    static func redacted(_ name: String, path: Path) -> String {
        let redactor = SensitiveDataRedactor()
        let encoded = percentEncoded(name)
        func json(_ text: String) -> String { redactor.redact(body: Data(text.utf8), contentType: "application/json") }
        switch path {
        case .jsonPair: return json(#"{"ParameterKey":"\#(name)","ParameterValue":"\#(value)"}"#)
        case .jsonOptionPair: return json(#"{"OptionName":"\#(name)","Value":"\#(value)"}"#)
        case .jsonAttributePair: return json(#"{"attribute":"\#(name)","value":"\#(value)"}"#)
        case .jsonArray: return json(#"["x","\#(name)","\#(value)"]"#)
        case .jsonTags: return json(#"{"tags":["\#(name)","\#(value)","z"]}"#)
        case .form:
            let body = "ParameterKey=\(encoded)&ParameterValue=\(value)"
            return redactor.redact(body: Data(body.utf8), contentType: "application/x-www-form-urlencoded")
        case .multipart:
            let body = "--B\r\nContent-Disposition: form-data; name=\"ParameterKey\"\r\n\r\n\(name)\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"ParameterValue\"\r\n\r\n\(value)\r\n--B--\r\n"
            return redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B")
        case .allowedQuery:
            let allowing = SensitiveDataRedactor(allowedQueryParameters: ["ParameterKey", "ParameterValue"])
            return allowing.redact(url: URL(string: "https://x.example/a?ParameterKey=\(encoded)&ParameterValue=\(value)")!)
        case .urlPath:
            return redactor.redact(url: URL(string: "https://x.example/\(encoded)/\(value)")!)
        }
    }

    private static let asciiAlphanumerics = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

    /// `%`, `&`, `#` and every other character outside ASCII letters and digits, percent-encoded.
    static func percentEncoded(_ text: String) -> String {
        text.addingPercentEncoding(withAllowedCharacters: asciiAlphanumerics)!
    }

    @Test("the review's names hide the value on every path", arguments: Path.allCases)
    func reviewNamesHideValue(path: Path) {
        for name in Self.reviewNames + ["%26%23xcvv", "&#X0CVV"] {
            let output = Self.redacted(name, path: path)
            #expect(!output.contains(Self.value), "\(path.rawValue): \(name.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a name that only its decoding spells hides the value on every path", arguments: Path.allCases)
    func decodedNamesHideValue(path: Path) {
        for name in Self.decodedNames where path != .jsonArray && path != .jsonTags || !name.contains(" ") {
            let output = Self.redacted(name, path: path)
            #expect(!output.contains(Self.value), "\(path.rawValue): \(name.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("every secret name after every escape start hides the value on every path", arguments: Path.allCases)
    func escapedNamesHideValue(path: Path) {
        for name in Self.escapedNames {
            let output = Self.redacted(name, path: path)
            #expect(!output.contains(Self.value), "\(path.rawValue): \(name.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("the review's URL: the segment after a name with an escape is an identifier")
    func urlPathLabel() {
        let redactor = SensitiveDataRedactor()
        #expect(redactor.redact(url: URL(string: "https://x.example/cvv/98765")!) == "https://x.example/cvv/:id")
        let escaped = redactor.redact(url: URL(string: "https://x.example/%26%23xcvv/98765")!)
        #expect(!escaped.contains("98765"), "\(escaped)")
        let reference = redactor.redact(url: URL(string: "https://x.example/&%23xcvv/98765")!)
        #expect(!reference.contains("98765"), "\(reference)")
    }

    @Test("free text reads the letter of an escape start as punctuation too", arguments: [
        "&#xpass hunter2", "&#Xsession hunter2", "&#xsid hunter2", "&#xpw hunter2", "%upass hunter2", "%Usid hunter2",
        "login &#xpass hunter2", "&amp;#xpass hunter2",
    ])
    func freeTextEscapeStart(line: String) {
        for (path, output) in RedactionCutRuleTests.everyPath(line) {
            #expect(!output.contains("hunter2"), "\(path): \(line.debugDescription) -> \(output.debugDescription)")
        }
    }

    // MARK: Usefulness

    @Test("a name that names no secret keeps the value beside it", arguments: Path.allCases.filter { $0 != .allowedQuery })
    func plainNamesKeepValue(path: Path) {
        // A `%25` in a URL path is a double encoding, which records the scheme and host only, and
        // a segment that is not a plain-ASCII name (`#xbox`) is a label, as a secret name is.
        for name in ["status", "region", "page", "Debit", "#xbox", "%users", "50%off"] where path != .urlPath || PlainName(name.unicodeScalars) != nil {
            let output = Self.redacted(name, path: path)
            #expect(output.contains(Self.value), "\(path.rawValue): \(name) -> \(output.debugDescription)")
        }
    }

    @Test("an allowed query keeps the value beside a name that names no secret")
    func allowedQueryKeepsValue() {
        let output = Self.redacted("status", path: .allowedQuery)
        // `ParameterKey` ends in the secret word `key`, so its own value is hidden; the value beside it is not.
        #expect(output == "https://x.example/a?ParameterKey=[redacted]&ParameterValue=98765")
    }
}
