import Foundation
import Testing
@testable import iOSSecurityTools

/// A URL path segment is read by the one rule for names: unless it is a plain-ASCII name that
/// names no secret, it is a label, and the segment after it becomes `:id`. The twenty-fourth
/// review wrote names with a line break or a space in them (`/p%0Ain/…`, `/p%20in/…`), which
/// showed the segment after them.
@Suite("SensitiveDataRedactor URL path segments that are not plain names")
struct RedactionURLPathLabelTests {
    let redactor = SensitiveDataRedactor()

    @Test("a segment that is not a plain-ASCII name, or that names a secret by the key rule, is a label", arguments: [
        ("https://x.example/v1/p%0Ain/X1", "https://x.example/v1/p%0Ain/:id"),
        ("https://x.example/v1/p%0Din/X1", "https://x.example/v1/p%0Din/:id"),
        ("https://x.example/v1/p%0Bin/X1", "https://x.example/v1/:id/:id"),
        ("https://x.example/v1/p%20in/X1", "https://x.example/v1/p%20in/:id"),
        ("https://x.example/v1/pass%20word/X1", "https://x.example/v1/:id/:id"),
        ("https://x.example/v1/t%CD%A6ken/X1", "https://x.example/v1/t%CD%A6ken/:id"),
        ("https://x.example/v1/p%C9%91sswo%CA%80d/X1", "https://x.example/v1/p%C9%91sswo%CA%80d/:id"),
        ("https://x.example/api/%C5%9Eifre/X1", "https://x.example/api/%C5%9Eifre/:id"),
        ("https://x.example/users/@me/settings", "https://x.example/users/@me/:id"),
        ("https://x.example/a,b/c", "https://x.example/a,b/:id"),
        ("https://x.example/~bob/files", "https://x.example/~bob/:id"),
    ])
    func labels(input: String, expected: String) throws {
        #expect(redactor.redact(url: try #require(URL(string: input))) == expected)
    }

    @Test("plain names that name no secret keep the segment after them, and `:id` reads the same again", arguments: [
        "https://api.example.com/v1/items/42/info", "https://api.example.com/docs/getting-started/intro.html",
        "https://api.example.com/users/:id/reset", "https://api.example.com/a/:id/b", "https://api.example.com/my_files/report.pdf",
        "https://api.example.com/v1.2/status",
    ])
    func plainNames(input: String) throws {
        #expect(redactor.redact(url: try #require(URL(string: input))) == input)
    }

    @Test("every control character in a segment makes the segment after it a value")
    func controlCharacters() throws {
        var shown: [String] = []
        for value in Array(0x00...0x1F) + [0x7F] {
            let escape = String(format: "%%%02X", value)
            for segment in ["p\(escape)in", "\(escape)region", "region\(escape)"] {
                let url = try #require(URL(string: "https://x.example/v1/\(segment)/X98765"))
                let output = redactor.redact(url: url)
                if output.contains("X98765") { shown.append(output) }
            }
        }
        #expect(shown.isEmpty, "\(shown.prefix(5))")
    }
}
