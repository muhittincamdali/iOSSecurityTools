import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated input for the key rule in every shape it takes besides `key=value`: the first string
/// of a two-element array in a line, the tag of an element, the name of a multipart part header
/// and the host of a URL. A key that is not allowed, or a host that is not an address, never lets
/// the value show; one that is allowed keeps it, so the redactor stays useful.
@Suite("SensitiveDataRedactor key shape properties")
struct RedactionKeyShapePropertyTests {
    let redactor = SensitiveDataRedactor()

    /// A key of free text that is not on the default allowlist, starting with a letter.
    static func unallowedKey(using random: inout SeededRandom) -> String {
        while true {
            let key = RedactionAllowlistPropertyTests.key(using: &random)
            let folded = key.lowercased().filter { $0.isLetter || $0.isNumber }
            guard !RedactionAllowlistPropertyTests.allowedFolds.contains(folded), key.first?.isLetter == true else { continue }
            return key
        }
    }

    static let pairLayouts: [@Sendable (String, String) -> String] = [
        { key, value in "log [[\(Self.quoted(key)),\(Self.quoted(value))]]" },
        { key, value in "headers [[\"Accept\",\"*/*\"],[\(Self.quoted(key)),\(Self.quoted(value))]] ok" },
        { key, value in "log [\(Self.quoted(key)),\(Self.quoted(value))]" },
        { key, value in "log {\"status\":[[\(Self.quoted(key)),\(Self.quoted(value))]]}" },
        { key, value in "log {\"status\":[[\(Self.quoted(key)), [\(Self.quoted(value))]]]}" },
        { key, value in "[\n  [\(Self.quoted(key)),\n   \(Self.quoted(value))]\n]" },
    ]

    static func quoted(_ text: String) -> String {
        String(data: try! JSONSerialization.data(withJSONObject: text, options: .fragmentsAllowed), encoding: .utf8)!
    }

    @Test("the value of a two-element array in a line never shows after a key that is not allowed", arguments: 0..<3)
    func pairsInText(seed: Int) {
        var random = SeededRandom(seed: 0x9A12_0000 + UInt64(seed))
        for _ in 0..<300 {
            let key = Self.unallowedKey(using: &random)
            let value = RedactionPropertyTests.value(using: &random)
            let text = Self.pairLayouts.randomElement(using: &random)!(key, value)
            for (path, output) in RedactionCutRuleTests.everyPath(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("a pair in a line keeps its value after an allowed key")
    func allowedPairsInText() {
        var random = SeededRandom(seed: 0x9A12_0100)
        for _ in 0..<200 {
            let key = SensitiveDataRedactor.defaultAllowedTextKeys.randomElement(using: &random)!
            let value = RedactionPropertyTests.value(using: &random)
            let text = "log [[\(Self.quoted(key)),\(Self.quoted(value))]] done"
            #expect(redactor.redact(text) == text)
        }
    }

    static let elementLayouts: [@Sendable (String, String) -> String] = [
        { tag, value in "<\(tag)>\(value)</\(tag)>" },
        { tag, value in "<\(tag) id=\"1\">\(value)</\(tag)>" },
        { tag, value in "<root>\n  <\(tag)>\n    \(value)\n  </\(tag)>\n</root>" },
        { tag, value in "<dict>\r\n\t<key>x</key><\(tag)>\(value)</\(tag)>" },
        { tag, value in "ok <\(tag) >\(value)" },
    ]

    @Test("the text of an element never shows when its tag is not allowed", arguments: 0..<3)
    func elementText(seed: Int) {
        var random = SeededRandom(seed: 0x7A60_0000 + UInt64(seed))
        for _ in 0..<300 {
            let tag = Self.unallowedKey(using: &random).filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
            guard tag.first?.isLetter == true else { continue }
            let value = RedactionPropertyTests.value(using: &random)
            let text = Self.elementLayouts.randomElement(using: &random)!(tag, value)
            for (path, output) in RedactionCutRuleTests.everyPath(text) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(path): \(text.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("the text of an element shows when the app allows its tag")
    func allowedElementText() {
        var random = SeededRandom(seed: 0x7A60_0100)
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["item", "note"])
        for _ in 0..<200 {
            let tag = ["status", "count", "item", "note"].randomElement(using: &random)!
            let value = RedactionPropertyTests.value(using: &random)
            let text = "<\(tag)>\(value)</\(tag)> done"
            #expect(allowing.redact(text) == text)
        }
    }

    private static let headerCharacters = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!#$%&'*+^`|~")

    @Test("a multipart part header name never shows unless a part carries it")
    func partHeaderNames() {
        var random = SeededRandom(seed: 0x9A27_0000)
        let carried = ["Content-Length", "Content-Transfer-Encoding", "Content-ID", "Content-Description", "Content-Language", "Content-Location",
                       "Content-Encoding"]
        for _ in 0..<400 {
            let secret = RedactionPropertyTests.value(using: &random)
            let name = [secret, "X-" + secret, secret + "-Name", "4111111111111111", "DE89370400440532013000",
                        String((0..<Int.random(in: 1...20, using: &random)).map { _ in Self.headerCharacters.randomElement(using: &random)! }) + secret]
                .randomElement(using: &random)!
            let body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\(name): 1\r\n\r\nx\r\n--B--"
            let output = redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B")
            #expect(!output.contains(name), "\(body.debugDescription) -> \(output.debugDescription)")
            #expect(output.contains("[redacted]: [redacted]"), "\(output.debugDescription)")
        }
        for name in carried {
            let body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\(name): 1\r\n\r\nx\r\n--B--"
            #expect(redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B").contains(name + ": "))
        }
    }

    /// Characters a host may hold in `URLComponents` that no host name or address holds. A quote
    /// is left out: in free text it ends the URL before it.
    private static let hostBreakers = ["=", ";", ",", "&", "_", "%3D", "!", "$", "(", ")", "*", "+", "%40", "%2F", "%20", "~"]

    @Test("a URL host that is not an address never shows, on a URL, in a line and in a JSON body")
    func hosts() {
        var random = SeededRandom(seed: 0x4057_0000)
        for _ in 0..<400 {
            let secret = RedactionPropertyTests.value(using: &random).lowercased()
            let breaker = Self.hostBreakers.randomElement(using: &random)!
            let host = ["password" + breaker + secret, "h.example" + breaker + secret, secret + breaker + "x.example", "a" + breaker + secret + ".example"]
                .randomElement(using: &random)!
            let scheme = ["https", "http", "myapp", "x", "redis"].randomElement(using: &random)!
            let url = scheme + "://" + host + ["", "/", "/db", "/a?status=1", ":8080/x"].randomElement(using: &random)!
            var outputs = ["line": redactor.redact("connect " + url + " ok")]
            if let parsed = URL(string: url) { outputs["url"] = redactor.redact(url: parsed) }
            let json = "{\"callback\":" + Self.quoted(url) + "}"
            outputs["JSON"] = redactor.redact(body: Data(json.utf8), contentType: "application/json")
            for (path, output) in outputs {
                #expect(!RedactionPropertyTests.leaks(secret, in: output.lowercased()), "\(path): \(url) -> \(output)")
            }
        }
    }

    // In free text a URL is shown only when it is clean, which an IPv6 address in brackets is
    // not: its `:` cuts the text at the URL.
    @Test("a host that is a name of ASCII labels or an address is kept")
    func plainHosts() throws {
        for host in ["example.com", "api.example.co.uk", "localhost", "my-host", "10.0.0.1", "[::1]", "[2001:db8::7]", "a1-b2.example", "example.com."] {
            let url = try #require(URL(string: "https://\(host)/a"))
            #expect(redactor.redact(url: url) == "https://\(host)/a", "\(host)")
            let inText = host.hasPrefix("[") ? "see [redacted]" : "see https://\(host)/a done"
            #expect(redactor.redact("see https://\(host)/a done") == inText, "\(host)")
        }
        #expect(SensitiveDataRedactor(urlDetail: .hostOnly).redact(url: try #require(URL(string: "https://example.com:8443/a?b=1"))) == "https://example.com:8443")
    }
}
