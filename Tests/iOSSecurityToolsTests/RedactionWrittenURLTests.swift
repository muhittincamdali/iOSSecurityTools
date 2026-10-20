import Foundation
import Testing
@testable import iOSSecurityTools

/// A URL in free text is not a safe place to read on from. The fourteenth review got 168 values
/// past the redactor that stood right after a URL whose end named them: an empty query parameter
/// (`?token= hunter2`), a path that ends in `=` or `:`, a last segment, query name or host that is
/// a secret name. Path parameters, a query or a fragment cut the text at their start unless every
/// parameter in them is allowed and has a value, and a URL whose end names a value cuts the text
/// after it.
@Suite("SensitiveDataRedactor URLs written in text")
struct RedactionWrittenURLTests {
    static let secret = "Kp7Zw3Qx9"

    /// Where the URL starts: schemes, addresses, ports and user info.
    static let starts = [
        "http://x.example", "HTTPS://X.EXAMPLE", "ftp://files.example", "wss://rt.example", "postgres://app@db.example:5432",
        "https://[::1]:8443", "https://10.0.0.1", "https://x.example:8443", "https://bob@x.example", "myapp://callback",
        "mongodb+srv://c.example",
    ]

    /// How the URL ends: with a name whose value comes after it.
    static let ends = [
        "/a?token=", "/a;token=", "/password=", "/a#access_token=", "/v1/api_key:", "/password", "/a?secret", "/api/password/",
        "/a?x=1&pin=", "/a?page=2&pin=", "/a?b=1#password", "/t%6Fken=", "/a?t%6Fken=", "/a?t\u{043E}ken=", "/a?TOKEN=",
    ]

    /// What can stand between the URL and the value.
    static let gaps = [
        " ", "\"", "'", "`", "<", ">", "\n", "\r", "\r\n", "\t", ". ", ", ", ") ", "] ", "; ", "! ", "? ", ": ", "=\"",
        "\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}",
    ]

    /// Every place free text is read: a log line, after an allowed key, a text/plain body, a JSON
    /// string, a form value and a multipart text part.
    static func places(_ line: String) -> [(String, String)] {
        let redactor = SensitiveDataRedactor(allowedTextKeys: ["note", "url"])
        let json = String(decoding: (try? JSONSerialization.data(withJSONObject: ["msg": line])) ?? Data(), as: UTF8.self)
        let form = "note=" + SensitiveDataRedactor.formEncoded(line)
        let multipart = "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n" + line + "\r\n--B--"
        return [
            ("text", redactor.redact("see " + line)),
            ("allowed key", redactor.redact("status=200 path=" + line)),
            ("text/plain", redactor.redact(body: Data(line.utf8), contentType: "text/plain")),
            ("JSON", redactor.redact(body: Data(json.utf8), contentType: "application/json")),
            ("JSON array", redactor.redact(body: Data("[\(json)]".utf8), contentType: "application/json")),
            ("form", redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded")),
            ("multipart", redactor.redact(body: Data(multipart.utf8), contentType: "multipart/form-data; boundary=B")),
        ]
    }

    @Test("no value after a URL whose end names it shows, in any place, after any scheme and gap", arguments: starts)
    func valueAfterURLIsHidden(start: String) {
        for end in Self.ends {
            for gap in Self.gaps {
                let line = start + end + gap + Self.secret + " 200"
                for (place, output) in Self.places(line) {
                    #expect(!output.contains(Self.secret), "\(place): \(line.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    @Test("the review's examples are cut at the query, the fragment or the end of the URL", arguments: [
        ("GET https://api.example/v1/items?api_key='X1' 200", "GET https://api.example/v1/items?[redacted]"),
        ("GET https://api.example/v1/items?password=\"X1\" 200", "GET https://api.example/v1/items?[redacted]"),
        ("see https://x.example/a?token= X1", "see https://x.example/a?[redacted]"),
        ("[docs](https://x.example/a?token=) X1", "[docs](https://x.example/a?[redacted]"),
        ("open(\"https://x.example/a?token=\", \"X1\")", "open(\"https://x.example/a?[redacted]"),
        ("see https://x.example/a#access_token= X1", "see https://x.example/a#[redacted]"),
        ("see https://x.example/a?t\u{043E}ken= X1", "see https://x.example/a?[redacted]"),
        ("see https://x.example/v1/api_key: X1", "see https://x.example/v1/api_key: [redacted]"),
        ("see https://x.example/a/password X1", "see https://x.example/a/password [redacted]"),
        ("see https://password X1", "see https://password [redacted]"),
        ("see https://x.example/token= X1", "see https://x.example/token= [redacted]"),
        ("see myapp://pass%77ord X1", "see myapp://[redacted]"),
        ("see myapp://password= X1", "see myapp://[redacted]"),
        ("connect myapp://password=hunter2 ok", "connect myapp://[redacted] ok"),
    ])
    func reviewExamples(input: String, expected: String) {
        #expect(SensitiveDataRedactor().redact(input) == expected)
    }

    @Test("a URL past the limits of segments or parameters cuts the text after its host")
    func limits() {
        let segments = "see https://x.example" + String(repeating: "/a", count: SensitiveDataRedactor.maximumPathSegments + 6) + "?token= X1"
        #expect(SensitiveDataRedactor().redact(segments) == "see https://x.example[redacted]")
        let parameters = "see https://x.example/a?" + String(repeating: "b=1&", count: SensitiveDataRedactor.maximumQueryParameters + 1) + "token= X1"
        #expect(SensitiveDataRedactor().redact(parameters) == "see https://x.example[redacted]")
    }

    // The library stays useful: a URL whose parameters are all allowed and have values, and one
    // without parameters whose end names nothing, keep the text after them.
    @Test("a URL that leaves nothing for the text after it keeps that text")
    func usefulURLsAreKept() {
        let redactor = SensitiveDataRedactor(allowedQueryParameters: ["page", "sort"])
        for line in [
            "GET https://x.example/a?page=2 status=200 duration_ms=12",
            "GET https://x.example/a?page=2&sort=name status=200",
            "GET https://x.example/a;page=2/b status=200",
            "see https://x.example/docs/getting-started. status=200",
            "see https://x.example status=200",
            "GET https://x.example/v1/items/42 status=200",
        ] {
            #expect(redactor.redact(line) == line)
        }
        #expect(redactor.redact("GET https://x.example/users/12345678 status=200") == "GET https://x.example/users/:id status=200")
        #expect(redactor.redact("GET https://bob:pw@x.example/a?page=2 status=200") == "GET https://x.example/a?page=2 status=200")
    }

    @Test("the same text without a scheme is cut as it was")
    func withoutScheme() {
        #expect(SensitiveDataRedactor().redact("GET /v1/items?api_key='X1' 200") == "GET /v1/items?api_key=[redacted]")
        #expect(SensitiveDataRedactor().redact("see x.example/a?token= X1") == "see x.example/a?token= [redacted]")
    }
}
