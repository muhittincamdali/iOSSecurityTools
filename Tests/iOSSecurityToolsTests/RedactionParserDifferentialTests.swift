import Foundation
import Testing
@testable import iOSSecurityTools

/// Input that a common server parser (PHP, Werkzeug, Rack, Go, busboy) could split into fields
/// differently from a strict reading. Each one is omitted whole, so a field the redactor did not
/// see cannot show its value; the controls check that strict input is still read.
@Suite("SensitiveDataRedactor parser differentials")
struct RedactionParserDifferentialTests {
    let redactor = SensitiveDataRedactor()
    static let secret = "Qz7Wk9r"

    private func expectOmitted(_ template: String, _ contentType: String, described: String, sourceLocation: SourceLocation = #_sourceLocation) {
        let body = Data(template.replacingOccurrences(of: "{S}", with: Self.secret).utf8)
        let output = redactor.redact(body: body, contentType: contentType)
        #expect(output == "[body omitted: \(body.count) bytes, \(described)]", "\(template.debugDescription) -> \(output.debugDescription)", sourceLocation: sourceLocation)
    }

    // MARK: Multipart

    static let head = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n"

    // The first seven are review probes 232–236, 437 and 439. Werkzeug 3.1.3 reads the first as
    // {'note': ['hi'], 'password': [secret]}; PHP also splits at a delimiter after a bare LF.
    static let splitBodies: [String] = [
        head + "hi\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\r--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\n--B0und\nContent-Disposition: form-data; name=\"password\"\n\n{S}\r\n--B0und--",
        head + "hi\n--B0und\r\nContent-Disposition: form-data; name=\"pin\"\r\nContent-Type: text/plain\r\n\r\n{S}\r\n--B0und--",
        head + "hi\n--B0und\r\nContent-Disposition: form-data; name=\"x\"; filename=\"a\"\r\n\r\nok\n--B0und\r\n"
            + "Content-Disposition: form-data; name=\"token\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\r\n\r\n{S}\r\n--B0und--",
        head + "hi\r\n\n--B0und\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\n--B0und\r\nContent-Disposition: form-data; name=\"n2\"\r\n\r\npassword\r\n--B0und\r\n"
            + "Content-Disposition: form-data; name=\"x\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\r\n\r--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi --B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\r\n--b0UND\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\r\n--B0und \r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        head + "hi\r\n--B0und\t\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
        "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\nX-Note: --B0und\r\n\r\n{S}\r\n--B0und--",
        "--B0und\nContent-Disposition: form-data; name=\"note\"\n\n{S}\n--B0und--",
        "--B0und\r\nContent-Disposition: form-data; name=\"note\"\nContent-Type: text/plain\n\n{S}\r\n--B0und--",
        "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n{S}\n--B0und--",
        "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n{S}\r--B0und--",
        head + "{S}\r\n--B0und--\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--B0und--",
    ]

    @Test("omits a multipart body with --boundary anywhere but on a delimiter line after a CRLF", arguments: splitBodies)
    func multipartSplit(body: String) {
        expectOmitted(body, "multipart/form-data; boundary=B0und", described: "multipart/form-data")
    }

    // Servers differ in which of several boundaries they take and in whether they undo the quotes
    // and escapes of a quoted one.
    @Test("omits a multipart body unless the content type has one unquoted boundary of at most 70 characters", arguments: [
        "multipart/form-data; boundary=\"B0und\"",
        "multipart/form-data; boundary=\"B0\\und\"",
        "multipart/form-data; boundary=B0und; boundary=B0und",
        "multipart/form-data; boundary=B0und; BOUNDARY=Other",
        "multipart/form-data; boundary=B0und; boundary*=UTF-8''B0und",
        "multipart/form-data; boundary*=UTF-8''B0und",
    ])
    func multipartBoundaryParameter(contentType: String) {
        expectOmitted(Self.head + "{S}\r\n--B0und--", contentType, described: "multipart/form-data")
    }

    @Test("reads a boundary of 70 characters and omits one of 71")
    func multipartBoundaryLength() {
        for (length, isRead) in [(70, true), (71, false)] {
            let boundary = String(repeating: "b", count: length)
            let body = "--\(boundary)\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\(Self.secret)\r\n--\(boundary)--"
            let output = redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=\(boundary)")
            #expect(!output.contains(Self.secret))
            #expect(output.hasPrefix("[body omitted:") == !isRead, "\(length): \(output)")
        }
    }

    @Test("still reads a strict multipart body, also with the boundary in a part as plain text")
    func multipartControl() {
        let body = Self.head + "see B0und and -B0und\r\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\(Self.secret)\r\n--B0und--\r\n"
        let expected = Self.head + "see B0und and -B0und\r\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[redacted]\r\n--B0und--"
        #expect(redactor.redact(body: Data(body.utf8), contentType: "Multipart/Form-Data; Boundary=B0und; charset=utf-8") == expected)
    }

    // MARK: Forms

    @Test("omits a form that a server could split into other fields", arguments: [
        "note=hi;password={S}",
        "note=hi&x=1;token={S}",
        "note=50%&password={S}",
        "note=%4&x={S}",
        "note=%G1&x={S}",
        "note=hi& password={S}",
        "note=hi&\tpassword={S}",
        "note=hi\r\n&password={S}",
        "note=hi&x={S}\n",
        "note=caf\u{E9}&x={S}",
        "note=hi&\u{301}status={S}",
        "note=hi&\u{200B}status={S}",
        "note=a\u{7F}&x={S}",
        "note=a\u{0}&x={S}",
        "status=ok&st%61tus={S}",
        "note=a&Note={S}",
        "user.name=a&user_name={S}",
        "user+name=a&user_name={S}",
        "user%20name=a&user.name={S}",
        "note=a&%20note={S}",
        "note=a&+note={S}",
    ])
    func formSplit(body: String) {
        expectOmitted(body, "application/x-www-form-urlencoded", described: "application/x-www-form-urlencoded")
    }

    @Test("still reads a strict form: repeated names, brackets and the URL characters clients leave as they are", arguments: [
        ("status=ok&status=again", "status=ok&status=again"),
        ("ids[]=1&ids[]=2", "ids[]=[redacted]&ids[]=[redacted]"),
        ("q=a/b@d!e~f(g)h*i,j'k", "q=a/b@d!e~f(g)h*i,j'k"),
        ("user=bob&password=\(secret)&&flag", "user=bob&password=[redacted]&&flag"),
        ("first+name=Ada&last%20name=Lovelace", "first+name=Ada&last%20name=Lovelace"),
    ])
    func formControl(body: String, expected: String) {
        #expect(redactor.redact(body: Data(body.utf8), contentType: "application/x-www-form-urlencoded") == expected)
    }

    // MARK: URL queries

    @Test("writes a URL query that servers could split differently as ?[redacted], whatever the allowlist", arguments: [
        "https://example.com/a?note=hi;password=\(secret)",
        "https://example.com/a?note=hi&st%61tus=1&status=\(secret)",
        "https://example.com/a?user.name=a&user_name=\(secret)",
    ])
    func urlQuery(input: String) throws {
        let url = try #require(URL(string: input))
        for redactor in [redactor, SensitiveDataRedactor(allowedQueryParameters: ["note", "status", "user_name"]), SensitiveDataRedactor(kinds: .cardNumbers)] {
            #expect(redactor.redact(url: url) == "https://example.com/a?[redacted]")
        }
    }

    @Test("still reads a strict URL query")
    func urlControl() throws {
        let url = try #require(URL(string: "https://example.com/a?note=hi&page=2&page=3&password=\(Self.secret)"))
        #expect(SensitiveDataRedactor(allowedQueryParameters: ["note", "page"]).redact(url: url) == "https://example.com/a?note=hi&page=2&page=3&password=[redacted]")
    }

    // MARK: JSON

    @Test("omits JSON that parsers read differently", arguments: [
        "{\"a\":1}{\"password\":\"{S}\"}",
        "{\"a\":1}\n{\"password\":\"{S}\"}",
        "{'password':'{S}'}",
        "{password:\"{S}\"}",
        "{\"a\":NaN,\"password\":\"{S}\"}",
        "{\"a\":\"\\ud800\",\"password\":\"{S}\"}",
        "{\"password\":\"{S}\" /* c */}",
        "{\"password\":\"{S}\",}",
        "{\"a\":01,\"password\":\"{S}\"}",
        "{\"a\":\"x\u{1}\",\"password\":\"{S}\"}",
        "{\"a\":\"\\x41\",\"password\":\"{S}\"}",
        "{\"password\"\u{A0}:\"{S}\"}",
    ])
    func jsonSplit(body: String) {
        expectOmitted(body, "application/json", described: "application/json")
    }

    // Parsers differ in which repetition of a name they keep, and Go matches names without case
    // and with Unicode folding (`ſ` as `s`): every repetition is hidden, names are compared without
    // case, and a name that is not plain ASCII hides its value.
    @Test("hides a JSON value under every name a parser could bind to a secret")
    func jsonNames() {
        let body = #"{"password":"a","note":"ok","password":"b","PASSWORD":"c","pa\u017F\u017Fword":"d","pass\u0077ord":"e"}"#
        let expected = #"{"password":"[redacted]","note":"ok","password":"[redacted]","PASSWORD":"[redacted]","pa\u017F\u017Fword":"[redacted]","pass\u0077ord":"[redacted]"}"#
        #expect(redactor.redact(body: Data(body.utf8), contentType: "application/json") == expected)
    }

    // MARK: Content-Type header

    @Test("omits a body whose content type a server could read as another type or charset", arguments: [
        ("note={S}", "application/x-www-form-urlencoded, text/plain", "unreadable content type"),
        ("note={S}", "application/x-www-form-urlencoded text/plain", "unreadable content type"),
        ("note={S}", "application /x-www-form-urlencoded", "unreadable content type"),
        ("note={S}", "text/plain;; charset=utf-8", "unreadable content type"),
        ("note={S}", "text/plain; charset = utf-8", "unreadable content type"),
        ("note={S}", "text/plain; charset=utf-8; charset=latin1", "text/plain"),
        ("{\"note\":\"{S}\"}", "application/json; charset=\"utf-8\"; charset=utf-16", "application/json"),
        (head + "{S}\r\n--B0und--", "multipart/form-data; boundary = B0und", "unreadable content type"),
    ])
    func contentType(body: String, contentType: String, described: String) {
        expectOmitted(body, contentType, described: described)
    }
}
