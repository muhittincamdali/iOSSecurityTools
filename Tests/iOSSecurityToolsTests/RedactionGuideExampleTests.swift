import Foundation
import Testing
import iOSSecurityTools

/// The examples of the logging guide's sections on free text, bodies and URLs, as the guide writes
/// them, so that the guide shows what the redactor does.
@Suite("SensitiveDataRedactor logging guide examples")
struct RedactionGuideExampleTests {
    let redactor = SensitiveDataRedactor()

    @Test("the free-text examples", arguments: [
        ("GET /api/items status=200 method=GET duration_ms=12", "GET /api/items status=200 method=GET duration_ms=12"),
        ("login user=bob status=401 password=hunter2", "login user=[redacted]"),
        ("Error: connection refused\nretrying in 5 s", "Error: [redacted]"),
        ("user\u{A789} hunter2", "user[redacted]"),
        ("status=200 note\u{2192} hunter2", "status=200 note[redacted]"),
        ("user&colon;hunter2", "[redacted]"),
        ("contact alice%40example.com", "contact [redacted]"),
        (#"log [["X-User","bob"]]"#, #"log [[[redacted]"#),
        (#"cache miss for "session Qz9Wk7rX": refetching"#, "cache miss for [redacted]"),
        ("<user>bob</user>", "[redacted]"),
        ("password hunter2", "password [redacted]"),
        ("p\u{0430}ssword=hunter2", "p\u{0430}ssword=[redacted]"),
        ("login pa\u{115F}ssword hunter2", "login [redacted]"),
        ("password: 'abc\n  hunter2'", "password: [redacted]"),
        ("| password | hunter2 |", "| password [redacted]"),
        ("field name=\"password\" hunter2", "field name=[redacted]"),
        (#"<string name="api_key">k-1</string>"#, "[redacted]"),
        ("<key>password</key>\n<string>k-1</string>", "[redacted]"),
        ("upload ok status=200\n--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\n4831\r\n--B--",
         "upload ok status=200\n--B\r\nContent-Disposition: [redacted]"),
        (#"{"status":200,"user":"bob"} done"#, #"{"status":200,[redacted]"#),
        ("git clone https://bob:hunter2@github.com/x/y.git", "git clone [redacted]"),
        ("connect myapp://password=hunter2 ok", "connect [redacted]"),
        ("see https://x.example/a?token= hunter2", "see [redacted]"),
        ("GET https://api.example.com/items 200", "GET https://api.example.com/items 200"),
        ("GET https://api.example.com/users/12345678 200", "GET https://api.example.com/users/:id 200"),
        ("user1:2345678 at 12:30", "user1:[redacted]"),
        ("see https://x.example/a?q=1 ok", "see [redacted]"),
        ("Merhaba dünya \u{1F44B} bye", "Merhaba dünya [redacted]"),
        ("Optional<String>(x)", "Optional[redacted]"),
        ("note \"a\nhunter2\": 1", "note [redacted]"),
        ("if a < b then", "if a < b then"),
        ("login pa\\x{73}sword hunter2", "login [redacted]"),
        ("copied to \\\\nas\\backup", "copied to [redacted]"),
        ("pattern ^\\d+$ matched", "pattern [redacted]"),
        ("x\"status\": 200", "[redacted]"),
        ("\u{1F101}\"status\": 200", "[redacted]"),
        ("\u{1F101}status=200", "[redacted]"),
    ])
    func freeText(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("an app that allows a key reads on after it")
    func allowedKey() {
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["user"])
        #expect(allowing.redact("login user=bob status=401 password=hunter2") == "login user=bob status=401 password=[redacted]")
    }

    @Test("the body and URL examples")
    func bodiesAndURLs() throws {
        let part = "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\nX-4111111111111111: 1\r\n" + "Content-Length: 1\r\n\r\nx\r\n--B0und--"
        #expect(redactor.redact(body: Data(part.utf8), contentType: "multipart/form-data; boundary=B0und")
            == "--B0und\r\nContent-Disposition: form-data; name=\"a\"\r\n[redacted]: [redacted]\r\nContent-Length: 1\r\n\r\nx\r\n--B0und--")
        #expect(redactor.redact(url: try #require(URL(string: "https://h.example;password=hunter2/db"))) == "https://[redacted]")
        #expect(redactor.redact(url: try #require(URL(string: "https://example.com/pin/./4831"))) == "https://example.com")
        #expect(redactor.redact(url: try #require(URL(string: "https://bob:pw@example.com/users/12345678/reset?code=x#y")))
            == "https://example.com/users/:id/reset?code=[redacted]")
        let body = Data(("{\"a\":\"" + String(repeating: "abc ", count: 70_000) + "\"}").utf8)
        #expect(redactor.redact(body: body, contentType: "application/json") == "[body omitted: \(body.count) bytes, application/json]")
        #expect(SensitiveDataRedactor(maximumBodySize: 1_048_576).redact(body: body, contentType: "application/json") == String(decoding: body, as: UTF8.self))
    }
}
