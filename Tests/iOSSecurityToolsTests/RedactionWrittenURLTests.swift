import Foundation
import Testing
@testable import iOSSecurityTools

/// A URL in free text is shown only when it is clean: `scheme://host` with an optional path of
/// ASCII letters, digits, `.`, `_`, `-` and `/`, a host and segments that name no secret, and
/// white space, a line break or punctuation that ends a sentence after it. Any other URL cuts the
/// text where it starts. The fourteenth and fifteenth reviews got values past every reading of
/// the query, fragment and path parameters of a URL in text, one ending at a time: an empty or
/// allowed section after a secret segment (`/password# hunter2`), an encoded `=` or `:` at the
/// end (`/user%3A hunter2`), a character outside the safe alphabet inside the URL.
@Suite("SensitiveDataRedactor URLs written in text")
struct RedactionWrittenURLTests {
    static let secret = "Kp7Zw3Qx9"

    /// Where the URL starts: schemes, addresses, ports and user info.
    static let starts = [
        "http://x.example", "HTTPS://X.EXAMPLE", "ftp://files.example", "wss://rt.example", "postgres://app@db.example:5432",
        "https://[::1]:8443", "https://10.0.0.1", "https://x.example:8443", "https://bob@x.example", "myapp://callback",
        "mongodb+srv://c.example", "a+b://x.example",
    ]

    /// How the URL ends: with a name whose value comes after it, with an empty or allowed section,
    /// with an escape, or with a character outside the safe alphabet.
    static let ends = [
        "/a?token=", "/a;token=", "/password=", "/a#access_token=", "/v1/api_key:", "/password", "/a?secret", "/api/password/",
        "/a?x=1&pin=", "/a?page=2&pin=", "/a?b=1#password", "/t%6Fken=", "/a?t%6Fken=", "/a?t\u{043E}ken=", "/a?TOKEN=",
        "/password#", "/password?#", "/password;/", "/token;#", "/password#!", "/password#)", "/password;#,", "/password/#",
        "/a/../password#", "//password#", "/v1/users/passwd#", "/session#", "/x-api-key#", "/a=#", "/a:#", "/token=;/", "/a:;/",
        "/a%3D", "/a%3d", "/a%3A", "/user%3A", "/a/note%3A", "/a%253D", "/user%3A%22", "/a%3A%20", "/a\\x3D", "/a&#61", "/a=", "/a:",
        "/a?page=2", "/a;page=2", "/a#page=2", "/password?page=2", "/a;page=1/password", "/a?q=user%3A", "/a?page=%3D",
        "/a;page=user%3D", "/a?q=%22user%22%3A", "/a?q=1", "/a\u{2192}b", "/\u{1F511}", "/a\u{00B7}", "/a\u{200B}", "/a\u{FF1D}",
    ]

    /// What can stand between the URL and the value.
    static let gaps = [
        " ", "\"", "'", "`", "<", ">", "\n", "\r", "\r\n", "\t", ". ", ", ", ") ", "] ", "; ", "! ", "? ", ": ", "=\"",
        "\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}",
    ]

    /// Every place free text is read: a log line, after an allowed key, a text/plain body, a JSON
    /// string, a JSON string in an array, a form value and a multipart text part. The query
    /// parameters are allowed, which free text does not use.
    static func places(_ line: String) -> [(String, String)] {
        let redactor = SensitiveDataRedactor(allowedTextKeys: ["note", "url"], allowedQueryParameters: ["page", "q"])
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

    @Test("no value after a URL that is not clean shows, in any place, after any scheme and gap", arguments: starts)
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

    /// What can come in a URL before a value that is written in it.
    static let insides = [
        "\u{2192}", "\u{1F511}", "\u{00A0}", "\u{3000}", "\u{FF0F}", "\u{2215}", "\u{200B}", "%3D", "%3A", "%2F", "%253D", "?q=", "?page=",
        "#", "#q=", ";p=", ";page=", "=", ":", "@", "\\", "?", "&", "~", "!", "(", "*", "+", "$", ",",
    ]

    @Test("no value written in a URL after a character that makes it not clean shows, in any place")
    func valueInURLIsHidden() {
        for inside in Self.insides {
            var layouts = ["https://x.example/a\(inside)b/\(Self.secret)?q=1 tail", "https://x.example/a\(inside)\(Self.secret) tail",
                           "https://x.example\(inside)\(Self.secret)/a tail"]
            // A clean URL that ends a sentence (`…/value, tail`) shows its path, the value in it too.
            if ![",", "!"].contains(inside) { layouts.append("https://x.example/a/\(Self.secret)\(inside) tail") }
            for layout in layouts {
                for (place, output) in Self.places(layout) {
                    #expect(!output.contains(Self.secret), "\(place): \(layout.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    @Test("the reviews' examples are cut where the URL starts, whatever the allowed query parameters", arguments: [
        ("GET https://api.example/v1/items?api_key='X1' 200", "GET [redacted]"),
        ("GET https://api.example/v1/items?password=\"X1\" 200", "GET [redacted]"),
        ("see https://x.example/a?token= X1", "see [redacted]"),
        ("[docs](https://x.example/a?token=) X1", "[docs]([redacted]"),
        ("open(\"https://x.example/a?token=\", \"X1\")", "open(\"[redacted]"),
        ("see https://x.example/a#access_token= X1", "see [redacted]"),
        ("see https://x.example/v1/api_key: X1", "see [redacted]"),
        ("see https://x.example/a/password X1", "see [redacted]"),
        ("see https://password X1", "see [redacted]"),
        ("see https://x.example/token= X1", "see [redacted]"),
        ("see myapp://pass%77ord X1", "see [redacted]"),
        ("connect myapp://password=hunter2 ok", "connect [redacted]"),
        ("see https://x.example/password# hunter2", "see [redacted]"),
        ("see https://x.example/password?page=2 hunter2", "see [redacted]"),
        ("see https://x.example/a=# hunter2", "see [redacted]"),
        ("see https://x.example/a%3D hunter2", "see [redacted]"),
        ("see https://x.example/user%3A Qz9Wk7rX", "see [redacted]"),
        ("see https://x.example/a?q=user%3A Qz9Wk7rX", "see [redacted]"),
        ("see https://x.example/a\u{2192}b/Qz9Wk7rX?q=1 tail", "see [redacted]"),
        ("see https://x.example/\u{1F511}/Qz9Wk7rX?q=1", "see [redacted]"),
        ("path=https://x.example/a\u{2192}/Qz9Wk7rX?q=1", "path=[redacted]"),
        ("see https://x.example/a: hunter2", "see [redacted]"),
        ("see https://x.example:8443/a ok", "see [redacted]"),
        ("see https://bob@x.example/a ok", "see [redacted]"),
        ("see https://[::1]/a ok", "see [redacted]"),
        ("see https://auth.example.com/login ok", "see [redacted]"),
    ])
    func reviewExamples(input: String, expected: String) {
        #expect(SensitiveDataRedactor().redact(input) == expected)
        #expect(SensitiveDataRedactor(allowedQueryParameters: ["page", "q"]).redact(input) == expected)
    }

    // The library stays useful: a clean URL keeps the text after it, with identifiers in its path
    // written as `:id`.
    @Test("a clean URL keeps the text after it")
    func cleanURLsAreKept() {
        let redactor = SensitiveDataRedactor(allowedQueryParameters: ["page"])
        for line in [
            "GET https://api.example.com/items 200",
            "GET https://x.example/v1/items/42 status=200",
            "see https://x.example/docs/getting-started. status=200",
            "see https://x.example status=200",
            "see [docs](https://x.example/docs) status=200",
            "see (https://x.example/a) ok",
            "see \"https://x.example/a\" ok",
            "see https://x.example/a, ok",
            "fetched https://cdn.example.com/assets/app.min.js in 12 ms",
            "ping http://10.0.0.1/health ok",
            "GET https://x.example/a_b/c-d/e.f ok",
            "git clone https://github.com/x/y.git",
            "open https://x.example/a.) then",
            "https://x.example/a\nnext line",
        ] {
            #expect(redactor.redact(line) == line, "\(line.debugDescription)")
        }
        #expect(redactor.redact("GET https://x.example/users/12345678 status=200") == "GET https://x.example/users/:id status=200")
        #expect(redactor.redact("GET https://x.example/orders/550e8400-e29b-41d4-a716-446655440000 ok")
            == "GET https://x.example/orders/:id ok")
    }

    @Test("a clean URL longer than the longest word cuts the text; one of more segments than the limit keeps its host")
    func limits() {
        let long = "see https://x.example/" + String(repeating: "a", count: FreeTextScanner.longestWord) + " ok"
        #expect(SensitiveDataRedactor().redact(long) == "see [redacted]")
        let segments = "see https://x.example" + String(repeating: "/a", count: SensitiveDataRedactor.maximumPathSegments + 1) + " ok"
        #expect(SensitiveDataRedactor().redact(segments) == "see https://x.example ok")
    }

    @Test("a URL in a quoted key is read as a key is: one that is not clean cuts the text where it starts")
    func quotedKeys() {
        let redactor = SensitiveDataRedactor()
        #expect(redactor.redact("see \"https://x.example/a?token=abc\": 1") == "see \"[redacted]")
        #expect(redactor.redact("see \\\"https://x.example/a?token=abc\\\": 1") == "see \\\"[redacted]")
        #expect(redactor.redact("\"https://x.example/users/123456789\": 1") == "\"https://x.example/users/:id\": [redacted]")
        #expect(redactor.redact("see \"user=bob\": 1") == "see \"user=[redacted]")
        // The words of a key are not triggers, as in JSON: the value after it is hidden.
        #expect(redactor.redact("\"password hint\": 1") == "\"password hint\": [redacted]")
        #expect(redactor.redact("\"status\": \"ok\"") == "\"status\": \"ok\"")
    }

    @Test("the same text without a scheme is cut as it was")
    func withoutScheme() {
        #expect(SensitiveDataRedactor().redact("GET /v1/items?api_key='X1' 200") == "GET /v1/items?api_key=[redacted]")
        #expect(SensitiveDataRedactor().redact("see x.example/a?token= X1") == "see x.example/a?token= [redacted]")
    }

    @Test("the fifteenth review's correctness inputs: every one that is not a control hides its value, in every place")
    func correctnessPlaces() {
        for line in [
            "see https://x.example/token\u{2192}/Qz9Wk7rX?q=1 tail", "https://x.example/user%3A Qz9Wk7rX 200",
            "https://x.example/a?q=user%3D Qz9Wk7rX 200",
        ] {
            for (place, output) in Self.places(line) {
                #expect(!output.contains("Qz9Wk7rX"), "\(place): \(line.debugDescription) -> \(output.debugDescription)")
            }
        }
    }
}
