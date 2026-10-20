import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated URLs in free text. Each URL that is not clean holds one thing that makes it so,
/// placed anywhere after its scheme: a character outside the safe alphabet, an escape, a query,
/// fragment or path parameters (empty, allowed or not), an end in `=` or `:`, user info, a port, a
/// host or segment that names a secret. No value after such a URL, or written in it, shows in any
/// place free text is read, and a clean URL keeps itself and the text after it.
@Suite("SensitiveDataRedactor URL in text properties")
struct RedactionURLInTextPropertyTests {
    static let schemes = ["https", "http", "HTTPS", "ftp", "wss", "myapp", "a+b", "mongodb+srv"]
    static let hosts = ["x.example", "api.example.com", "10.0.0.1", "localhost", "a1-b2.example"]
    static let words = ["a", "v1", "items", "docs", "b-c", "e.f", "users", "x_y", "status"]
    static let secretNames = ["password", "api_key", "token", "pin", "session", "passwd", "x-api-key", "secret", "PASSWORD", "Pass-Word", "accessToken"]

    /// What makes a URL not clean, written into it.
    static let breakers: [@Sendable (inout SeededRandom) -> String] = [
        { random in String(RedactionSafeAlphabetPropertyTests.unsafeScalars.randomElement(using: &random)!) },
        { random in RedactionSafeAlphabetPropertyTests.escapes.randomElement(using: &random)! },
        { random in ["?", "#", ";", "?#", ";/", "#!", "#)", ";#,", "?page=2", "#page=2", ";page=2", "?q=", "?page=2&q=", "#access_token="].randomElement(using: &random)! },
        { random in ["=", ":", "%3D", "%3A", "%253A", "%3A%22", "@", "\\", "%", "~", "+", "*", "$", "(", "'"].randomElement(using: &random)! },
    ]

    /// A URL that is not clean, and where in it the value goes.
    static func uncleanURL(using random: inout SeededRandom, value: String) -> String {
        let scheme = schemes.randomElement(using: &random)!
        var host = hosts.randomElement(using: &random)!
        var segments = (0..<Int.random(in: 0...3, using: &random)).map { _ in words.randomElement(using: &random)! }
        let kind = Int.random(in: 0..<6, using: &random)
        switch kind {
        case 0:
            host = [secretNames.randomElement(using: &random)!, "token.example", "[::1]", "x.example:8443", "bob@x.example", "x_y.example"]
                .randomElement(using: &random)!
        case 1:
            segments.insert(secretNames.randomElement(using: &random)!, at: Int.random(in: 0...segments.count, using: &random))
        case 2:
            segments.append(value)
        default:
            break
        }
        var url = scheme + "://" + host + segments.map { "/" + $0 }.joined()
        // A secret host or segment makes the URL not clean on its own; every other URL gets a breaker.
        if kind >= 2 || Bool.random(using: &random) {
            let breaker = breakers.randomElement(using: &random)!(&random)
            let offset = Int.random(in: (scheme.count + 3)...url.count, using: &random)
            url.insert(contentsOf: breaker, at: url.index(url.startIndex, offsetBy: offset))
        }
        return url
    }

    @Test("no value after or in a URL that is not clean shows, in any place free text is read", arguments: 0..<6)
    func uncleanURLsCut(seed: Int) {
        var random = SeededRandom(seed: 0x0C1E_A000 + UInt64(seed))
        var checked = 0
        for _ in 0..<150 {
            let value = RedactionPropertyTests.value(using: &random)
            let url = Self.uncleanURL(using: &random, value: value)
            guard !Self.isClean(url) else { continue }
            checked += 1
            let gap = RedactionWrittenURLTests.gaps.randomElement(using: &random)!
            let line = url + gap + value + " 200"
            for (place, output) in RedactionWrittenURLTests.places(line) {
                #expect(!RedactionPropertyTests.leaks(value, in: output), "\(place): \(line.debugDescription) -> \(output.debugDescription)")
            }
        }
        #expect(checked > 140)
    }

    @Test("a clean URL of plain segments keeps itself and the text after it, whatever the allowed query parameters", arguments: 0..<2)
    func cleanURLsStay(seed: Int) {
        var random = SeededRandom(seed: 0xC1EA_0000 + UInt64(seed))
        let redactors = [SensitiveDataRedactor(), SensitiveDataRedactor(allowedQueryParameters: ["page", "q"])]
        for _ in 0..<200 {
            let segments = (0..<Int.random(in: 0...4, using: &random)).map { _ in Self.words.randomElement(using: &random)! }
            let url = Self.schemes.randomElement(using: &random)! + "://" + Self.hosts.randomElement(using: &random)! + segments.map { "/" + $0 }.joined()
            let (before, after) = [("GET ", " 200"), ("see ", ". status=200"), ("(", ") ok"), ("[docs](", ")."), ("", ", done"), ("", "\nnext")]
                .randomElement(using: &random)!
            let line = before + url + after
            for redactor in redactors {
                #expect(redactor.redact(line) == line, "\(line.debugDescription)")
            }
        }
    }

    /// Whether a generated URL is clean after all, as a breaker of `+` in the scheme can leave it.
    private static func isClean(_ url: String) -> Bool {
        SensitiveDataRedactor().redact("see " + url + " Qz9") == "see " + url + " Qz9"
    }
}
