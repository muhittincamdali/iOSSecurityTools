import Foundation
import Testing
@testable import iOSSecurityTools

/// URLs read with `URLComponents`: no credentials or fragment, query values only on an allowlist,
/// identifiers in the path as `:id`.
@Suite("SensitiveDataRedactor URLs")
struct RedactionURLTests {
    let redactor = SensitiveDataRedactor()

    @Test("drops user info and the fragment, hides query values and identifiers in the path", arguments: [
        ("https://example.com/users/12345678/reset?code=ft14", "https://example.com/users/:id/reset?code=[redacted]"),
        ("https://bob:hunter2@example.com/a/b?x=1#frag", "https://example.com/a/b?x=[redacted]"),
        ("https://bob@example.com:8443/", "https://example.com:8443/"),
        ("https://example.com/orders/550e8400-e29b-41d4-a716-446655440000", "https://example.com/orders/:id"),
        ("https://example.com/files/0123456789abcdef0123456789abcdef", "https://example.com/files/:id"),
        ("https://example.com/s/aB3dE5fG7hJ9kL1m", "https://example.com/s/:id"),
        ("https://example.com/u/alice@example.com/x", "https://example.com/u/:id/x"),
        ("https://example.com/cart;jsessionid=abc/view", "https://example.com/cart;jsessionid=[redacted]/view"),
        ("https://example.com/a?flag&q=", "https://example.com/a?[redacted]&q="),
        ("https://example.com/a?p%61ssword=x&%E2%80%8Btoken=y", "https://example.com/a?p%61ssword=[redacted]&[redacted]=[redacted]"),
        ("https://example.com/v1/items/42?page=2", "https://example.com/v1/items/42?page=[redacted]"),
        ("https://example.com/health", "https://example.com/health"),
    ])
    func urls(input: String, expected: String) throws {
        #expect(redactor.redact(url: try #require(URL(string: input))) == expected)
        #expect(redactor.redact("GET \(input) done") == "GET \(expected) done")
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
        #expect(hostOnly.redact("see https://example.com/reset?code=1 now") == "see https://example.com now")
    }

    @Test("a URL in text ends at white space, quotes and closing punctuation")
    func urlsInText() {
        #expect(redactor.redact("(see https://example.com/r?code=1).") == "(see https://example.com/r?code=[redacted]).")
        #expect(redactor.redact("url=\"https://example.com/r?code=1\" ok") == "url=\"[redacted]\" ok")
        #expect(redactor.redact("path=https://example.com/r?code=1 ok") == "path=https://example.com/r?code=[redacted] ok")
        #expect(redactor.redact("redis://:hunter2@cache.local:6379/0 up") == "redis://cache.local:6379/0 up")
        #expect(redactor.redact("git clone https://bob:hunter2@github.com/x/y.git") == "git clone https://github.com/x/y.git")
    }

    @Test("a URL that does not parse is not written; one that parses is written as URLComponents encodes it")
    func unparsed() {
        #expect(redactor.redact("go https://[::1/x?code=1 now") == "go \(SensitiveDataRedactor.unparsedURL) now")
        #expect(redactor.redact("go https://exa%ZZmple.com/?code=1") == "go \(SensitiveDataRedactor.unparsedURL)")
        #expect(redactor.redact("go https://x.com:abc/?code=1") == "go \(SensitiveDataRedactor.unparsedURL)")
        #expect(redactor.redact("go https://example.com/%ZZ?code=1") == "go https://example.com/%25ZZ?code=[redacted]")
        #expect(redactor.redact("go https://例え.jp/パス?code=1") == "go https://%E4%BE%8B%E3%81%88.jp/%E3%83%91%E3%82%B9?code=[redacted]")
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
}
