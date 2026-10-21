import Foundation
import Testing
@testable import iOSSecurityTools

/// URLs read with `URLComponents`: no credentials or fragment, query values only on an allowlist,
/// identifiers in the path as `:id`.
@Suite("SensitiveDataRedactor URLs")
struct RedactionURLTests {
    let redactor = SensitiveDataRedactor()

    /// Each URL, as ``SensitiveDataRedactor/redact(url:)`` writes it and in a line of text, where
    /// a URL that is not clean cuts the text at its start (nil: the line keeps the URL as written
    /// and its end).
    @Test("drops user info and the fragment, hides query values and identifiers in the path", arguments: [
        ("https://example.com/users/12345678/reset?code=ft14", "https://example.com/users/:id/reset?code=[redacted]", "GET [redacted]"),
        ("https://bob:hunter2@example.com/a/b?x=1#frag", "https://example.com/a/b?x=[redacted]", "GET [redacted]"),
        ("https://bob@example.com:8443/", "https://example.com:8443/", "GET [redacted]"),
        ("https://example.com/orders/550e8400-e29b-41d4-a716-446655440000", "https://example.com/orders/:id", nil),
        ("https://example.com/files/0123456789abcdef0123456789abcdef", "https://example.com/files/:id", nil),
        ("https://example.com/s/aB3dE5fG7hJ9kL1m", "https://example.com/s/:id", nil),
        ("https://example.com/u/alice@example.com/x", "https://example.com/u/:id/x", "GET [redacted]"),
        ("https://example.com/cart;jsessionid=abc/view", "https://example.com", "GET [redacted]"),
        ("https://example.com/a?flag&q=", "https://example.com/a?[redacted]&q=", "GET [redacted]"),
        ("https://example.com/a?p%61ssword=x&%E2%80%8Btoken=y", "https://example.com/a?p%61ssword=[redacted]&[redacted]=[redacted]", "GET [redacted]"),
        ("https://example.com/v1/items/42?page=2", "https://example.com/v1/items/42?page=[redacted]", "GET [redacted]"),
        ("https://example.com/health", "https://example.com/health", nil),
    ] as [(String, String, String?)])
    func urls(input: String, expected: String, inText: String?) throws {
        #expect(redactor.redact(url: try #require(URL(string: input))) == expected)
        #expect(redactor.redact("GET \(input) done") == inText ?? "GET \(expected) done")
    }

    // In free text a URL is never read for what its query, fragment or path parameters hold:
    // `allowedQueryParameters` applies to `redact(url:)` only.
    @Test("in text, any URL with a query, fragment or parameters cuts the text at its start, also when they are allowed")
    func allowedURLInText() throws {
        let custom = SensitiveDataRedactor(allowedQueryParameters: ["page", "sort"])
        for line in [
            "GET https://example.com/a?page=2&sort=name status=200", "GET https://example.com/a;page=2/b status=200",
            "GET https://example.com/a?page=2#sort=name status=200", "GET https://example.com/a?page= hunter2",
            "GET https://example.com/a?page=2&token= hunter2", "GET https://example.com/a?page=2#token= hunter2",
        ] {
            #expect(custom.redact(line) == "GET [redacted]", "\(line)")
        }
        #expect(redactor.redact("GET https://example.com/v1/items/42 status=200") == "GET https://example.com/v1/items/42 status=200")
        #expect(custom.redact(url: try #require(URL(string: "https://example.com/a?page=2&sort=name"))) == "https://example.com/a?page=2&sort=name")
    }

    @Test("query values on the allowlist are kept, read as free text")
    func allowedQueryParameters() throws {
        let custom = SensitiveDataRedactor(allowedQueryParameters: ["page", "sort", "token"])
        let url = try #require(URL(string: "https://example.com/a?page=2&sort=name%20asc&token=abc&q=x&note=user%3Dbob"))
        #expect(custom.redact(url: url) == "https://example.com/a?page=2&sort=name%20asc&token=[redacted]&q=[redacted]&note=[redacted]")
        let pageNote = try #require(URL(string: "https://example.com/a?page=user%3Dbob"))
        #expect(custom.redact(url: pageNote) == "https://example.com/a?page=user%3D[redacted]")
    }

    @Test("host only records the scheme, host and port")
    func hostOnly() throws {
        let hostOnly = SensitiveDataRedactor(urlDetail: .hostOnly)
        #expect(hostOnly.redact(url: try #require(URL(string: "https://bob:pw@api.example.com:8443/users/42?q=1#x"))) == "https://api.example.com:8443")
        #expect(hostOnly.redact("see https://example.com/reset now") == "see https://example.com now")
        #expect(hostOnly.redact("see https://example.com/reset?code=1 now") == "see [redacted]")
    }

    @Test("a URL in text ends at white space, quotes and closing punctuation, and one that is not clean cuts the text at its start")
    func urlsInText() {
        #expect(redactor.redact("(see https://example.com/r?code=1).") == "(see [redacted]")
        // Two marks after a URL leave its end open: only one may end a sentence.
        #expect(redactor.redact("(see https://example.com/r).") == "(see [redacted]")
        #expect(redactor.redact("(see https://example.com/r) ok") == "(see https://example.com/r) ok")
        #expect(redactor.redact("url=\"https://example.com/r?code=1\" ok") == "url=[redacted]")
        #expect(redactor.redact("path=https://example.com/r?code=1 ok") == "path=[redacted]")
        #expect(redactor.redact("path=https://example.com/r ok") == "path=https://example.com/r ok")
        #expect(redactor.redact("redis://:hunter2@cache.local:6379/0 up") == "[redacted]")
        #expect(redactor.redact("git clone https://bob:hunter2@github.com/x/y.git") == "git clone [redacted]")
        #expect(redactor.redact("git clone https://github.com/x/y.git") == "git clone https://github.com/x/y.git")
    }

    @Test("a URL in text that does not parse, or parses but is not clean, cuts the text at its start")
    func unparsed() throws {
        #expect(redactor.redact("go https://[::1/x?code=1 now") == "go [redacted]")
        #expect(redactor.redact("go https://exa%ZZmple.com/?code=1") == "go [redacted]")
        #expect(redactor.redact("go https://x.com:abc/?code=1") == "go [redacted]")
        #expect(redactor.redact("go https://example.com/%ZZ?code=1") == "go [redacted]")
        #expect(redactor.redact("go https://example.jp/パス ok") == "go [redacted]")
        #expect(redactor.redact("go https://例え.jp/a ok") == "go [redacted]")
        // `URLComponents` encodes the bare `%` as `%25`, which a server that decodes twice reads
        // as another escape, so `redact(url:)` writes only the scheme and host.
        #expect(redactor.redact(url: try #require(URL(string: "https://example.com/%ZZ?code=1"))) == "https://example.com")
    }

    @Test("without secret fields the user info and fragment are still dropped and the detectors still run")
    func kinds() throws {
        let detectorsOnly = SensitiveDataRedactor(kinds: [.cardNumbers, .emailAddresses])
        let url = try #require(URL(string: "https://bob:pw@example.com/pay?card=4111111111111111&email=alice@example.com#frag"))
        let output = detectorsOnly.redact(url: url)
        #expect(output == "https://example.com/pay?card=%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2+1111&email=a%E2%80%A2%E2%80%A2%E2%80%A2%40example.com")
        for leaked in ["bob", "pw", "frag", "4111111111111111", "alice"] {
            #expect(!output.contains(leaked))
        }
        #expect(detectorsOnly.redact("https://example.com/pay?card=4111111111111111&email=alice@example.com") == "https://example.com/pay?card=•••• 1111&email=a•••@example.com")

        let path = try #require(URL(string: "https://example.com/users/alice@example.com/cards/4111-1111-1111-1111?b=1&flag"))
        #expect(detectorsOnly.redact(url: path) == "https://example.com/users/:id/cards/:id?b=1&flag")
        #expect(SensitiveDataRedactor(kinds: []).redact(url: try #require(URL(string: "https://bob:pw@example.com/a?b=1#x"))) == "https://example.com/a?b=1")
        let hostOnly = SensitiveDataRedactor(kinds: .emailAddresses, urlDetail: .hostOnly)
        #expect(hostOnly.redact(url: try #require(URL(string: "https://bob:pw@example.com:8443/a?email=alice@example.com#x"))) == "https://example.com:8443")
    }

    @Test("a URL with more path segments or parameters than the limits records its scheme, host and port")
    func limits() throws {
        let segments = SensitiveDataRedactor.maximumPathSegments
        let parameters = SensitiveDataRedactor.maximumQueryParameters
        let longest = "https://example.com:8443" + String(repeating: "/a", count: segments) + "?b=1"
        #expect(redactor.redact(url: try #require(URL(string: longest))) == "https://example.com:8443" + String(repeating: "/a", count: segments) + "?b=[redacted]")
        let cases = [
            "https://example.com:8443" + String(repeating: "/a", count: segments + 1),
            "https://example.com:8443/a?" + (0...parameters).map { "k\($0)=1" }.joined(separator: "&"),
            "https://example.com:8443/a" + String(repeating: ";k=1", count: parameters + 1),
            "https://example.com:8443" + String(repeating: "/pin/4831", count: segments / 2 + 1) + "?password=hunter2",
        ]
        for input in cases {
            #expect(redactor.redact(url: try #require(URL(string: input))) == "https://example.com:8443")
            #expect(redactor.redact("GET \(input) done") == "GET [redacted]")
            #expect(SensitiveDataRedactor(kinds: .cardNumbers).redact(url: try #require(URL(string: input))) == "https://example.com:8443")
        }
        let most = "https://example.com/a?" + (1...parameters).map { "k\($0)=1" }.joined(separator: "&")
        #expect(redactor.redact(url: try #require(URL(string: most))).hasSuffix("&k\(parameters)=[redacted]"))
    }

    @Test("a segment read once keeps its reading where it comes again, after a label or not")
    func repeatedSegments() throws {
        let url = try #require(URL(string: "https://example.com/pin/pin/users/4831/users/pin/4831/a%40b.com/a%40b.com/users"))
        #expect(redactor.redact(url: url) == "https://example.com/pin/:id/:id/4831/users/pin/:id/:id/:id/users")
    }
}
