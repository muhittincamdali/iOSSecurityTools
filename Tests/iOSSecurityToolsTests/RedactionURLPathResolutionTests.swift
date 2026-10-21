import Foundation
import Testing
@testable import iOSSecurityTools

/// A URL path that servers resolve to other segments than it is written with — dot segments, a
/// `;`, escaped `.`, `/`, `\`, `;` or `%` — records only the scheme, host and port: which segment
/// follows a secret name would depend on the server.
@Suite("SensitiveDataRedactor URL paths that resolve differently")
struct RedactionURLPathResolutionTests {
    let redactor = SensitiveDataRedactor()

    @Test("a path with a dot segment, a semicolon, or an escaped dot, slash, backslash, semicolon or percent records the scheme and host", arguments: [
        "/pin/./4831", "/password/%2E/Qz9W1", "/password/%2e/Qz9W1", "/token/;/Qz9W1", "/token/x/../Qz9W1", "/token/./././Qz9W1", "/token/%2E%2E/Qz9W1",
        "/token/.%2e/Qz9W1", "/token/%252E/Qz9W1", "/token/;x/Qz9W1", "/token/.;/Qz9W1", "/token/..;x/Qz9W1", "/token/%2F/Qz9W1", "/token/%2f/Qz9W1",
        "/token/%5C/Qz9W1", "/token/%2525/Qz9W1", "/a/../token/Qz9W1", "/./token/Qz9W1", "/users/./12345678", "/token/..", "/cart;page=2",
        "/a;pin/Qz9W1", "/a%3Bpin/Qz9W1", "/a%3bpin/Qz9W1",
    ])
    func ambiguousPaths(path: String) throws {
        let url = try #require(URL(string: "https://api.example.com:8443" + path + "?page=2"))
        #expect(redactor.redact(url: url) == "https://api.example.com:8443")
        #expect(SensitiveDataRedactor(kinds: [.cardNumbers]).redact(url: url) == "https://api.example.com:8443")
    }

    @Test("a path written plainly is still read segment by segment", arguments: [
        ("/users/12345678/reset", "/users/:id/reset"), ("/files/report.pdf", "/files/report.pdf"), ("/v1.2/items", "/v1.2/items"),
        ("/a..b/c", "/a..b/c"), ("/pin/4831", "/pin/:id"), ("/status", "/status"),
    ])
    func plainPaths(path: String, expected: String) throws {
        let url = try #require(URL(string: "https://api.example.com" + path))
        #expect(redactor.redact(url: url) == "https://api.example.com" + expected)
    }

    @Test("in text a URL with a dot segment cuts the text at its start")
    func dotSegmentsInText() {
        #expect(redactor.redact("GET https://api.example.com/pin/./4831 200") == "GET [redacted]")
        #expect(redactor.redact("GET https://api.example.com/items/../token/Qz9W1 200") == "GET [redacted]")
    }
}
