import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor bodies")
struct RedactionBodyTests {
    let redactor = SensitiveDataRedactor()

    private func redact(_ body: String, _ contentType: String?) -> String {
        redactor.redact(body: Data(body.utf8), contentType: contentType)
    }

    // MARK: JSON

    @Test("hides every value under a secret name in a JSON body and stays valid JSON")
    func json() throws {
        let body = #"{"user":"bob","password":"hunter2","nested":[{"token":{"a":[1,2]}},{"Token":42,"secret":null}],"password":"again"}"#
        let output = redact(body, "application/json; charset=utf-8")
        #expect(output == #"{"user":"bob","password":"[redacted]","nested":[{"token":"[redacted]"},{"Token":"[redacted]","secret":"[redacted]"}],"password":"[redacted]"}"#)
        #expect(try JSONSerialization.jsonObject(with: Data(output.utf8)) is NSDictionary)
    }

    @Test("compares JSON names after decoding their escapes")
    func jsonEscapedNames() {
        #expect(redact(#"{"pass\u0077ord":"hunter2","user":"bob"}"#, "application/json") == #"{"pass\u0077ord":"[redacted]","user":"bob"}"#)
        #expect(redact(#"{"pаssword":"hunter2"}"#, "application/problem+json") == #"{"pаssword":"[redacted]"}"#)
    }

    // A JSON string is free text, so JSON in it follows the allowlist of keys in text: the string
    // is cut at the first member that is not allowed, and the body stays JSON.
    @Test("reads JSON inside a JSON string")
    func jsonInString() {
        let body = #"{"query":"mutation","variables":"{\"password\":\"hunter2\",\"user\":\"bob\"}"}"#
        #expect(redact(body, "application/json") == #"{"query":"mutation","variables":"{\"password\":[redacted]"}"#)
        let allowed = #"{"query":"mutation","variables":"{\"status\":200,\"count\":3}"}"#
        #expect(redact(allowed, "application/json") == allowed)
    }

    @Test("omits JSON that does not parse completely", arguments: [
        #"{"password":"hunter2""#,
        #"{"password":"hunter2",}"#,
        #"{"password":"hunter2"} trailing"#,
        #"{"a":"\ud800"}"#,
        "{\"a\":\"line\nbreak\"}",
        #"// comment"# + "\n{}",
    ])
    func malformedJSON(body: String) {
        #expect(redact(body, "application/json") == "[body omitted: \(body.utf8.count) bytes, application/json]")
    }

    @Test("omits JSON nested deeper than the parser reads")
    func deepJSON() {
        let depth = Nesting.maximumDepth + 1
        let body = String(repeating: "[", count: depth) + String(repeating: "]", count: depth)
        #expect(redact(body, "application/json") == "[body omitted: \(depth * 2) bytes, application/json]")
    }

    @Test("omits a body that is not UTF-8")
    func notUTF8() {
        #expect(redactor.redact(body: Data([0x7B, 0xFF, 0x7D]), contentType: "application/json") == "[body omitted: 3 bytes, application/json]")
        #expect(redact("{}", "application/json; charset=utf-16") == "[body omitted: 2 bytes, application/json]")
    }

    // MARK: Forms

    @Test("hides form fields by their decoded name", arguments: [
        ("user=bob&password=hunter2&next=%2Fhome", "user=bob&password=[redacted]&next=%2Fhome"),
        ("pass%77ord=hunter2&a=1", "pass%77ord=[redacted]&a=1"),
        ("pass+word=hunter2", "pass+word=[redacted]"),
        ("user%5Bpassword%5D=hunter2&user%5Bname%5D=bob", "user%5Bpassword%5D=[redacted]&user%5Bname%5D=[redacted]"),
        ("p%D0%B0ssword=hunter2", "p%D0%B0ssword=[redacted]"),
        ("user=bob%20smith&note=paid+4111+1111+1111+1111", "user=bob%20smith&note=paid+%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2+1111"),
        ("note=status%3D1+user%3Dbob", "note=status%3D1+user%3D[redacted]"),
        ("password=hunter2&password=again", "password=[redacted]&password=[redacted]"),
        ("q=%7B%22password%22%3A%22hunter2%22%7D", "q=%7B%22password%22%3A[redacted]"),
        ("flag&password=hunter2", "flag&password=[redacted]"),
    ])
    func form(body: String, expected: String) {
        #expect(redact(body, "application/x-www-form-urlencoded") == expected)
    }

    // A mark or a joiner after `&`, `=` or `+` forms one Character with it. Written as it is, such
    // a form is not strict and is omitted; percent-encoded, it is decoded scalar by scalar after
    // the split, so `%CC%81status` is a field of its own whose name is not plain ASCII.
    @Test("reads percent-encoded marks and joiners after & and = as part of the next field", arguments: [
        ("note=hi&%CC%81status=hunter2", "note=hi&%CC%81status=[redacted]"),
        // A joiner is outside the safe alphabet: the decoded name is cut there, and goes whole.
        ("x=1&%E2%80%8Dstatus=hunter2", "x=1&[redacted]=[redacted]"),
        ("user=bob&%E2%83%9Dtoken=abc", "user=bob&%E2%83%9Dtoken=[redacted]"),
        ("status=200&%CC%81=hunter2", "status=200&%CC%81=[redacted]"),
        ("password=%CC%81x", "password=[redacted]"),
    ])
    func formScalars(body: String, expected: String) {
        let output = redact(body, "application/x-www-form-urlencoded")
        #expect(Array(output.unicodeScalars) == Array(expected.unicodeScalars), "\(output.debugDescription)")
    }

    @Test("omits a form with a bad escape", arguments: ["password=%ZZ", "a=%", "a=%C3%28", "a=1&b=%2", "%=x"])
    func malformedForm(body: String) {
        #expect(redact(body, "application/x-www-form-urlencoded") == "[body omitted: \(body.utf8.count) bytes, application/x-www-form-urlencoded]")
    }

    @Test("reads a body without a content type as JSON when it parses as an object or array, and omits it otherwise")
    func noContentType() {
        #expect(redact(#"{"password":"hunter2"}"#, nil) == #"{"password":"[redacted]"}"#)
        #expect(redact("user=bob&password=hunter2", nil) == "[body omitted: 25 bytes, no content type]")
        #expect(redact("password hunter2", nil) == "[body omitted: 16 bytes, no content type]")
        #expect(redact(#""hunter2""#, nil) == "[body omitted: 9 bytes, no content type]")
    }

    @Test("omits a body larger than the maximum size without parsing it")
    func oversized() {
        #expect(SensitiveDataRedactor.defaultMaximumBodySize == 262_144)
        #expect(redactor.maximumBodySize == SensitiveDataRedactor.defaultMaximumBodySize)
        let body = Data(("{\"a\":\"" + String(repeating: "x", count: SensitiveDataRedactor.defaultMaximumBodySize) + "\"}").utf8)
        #expect(redactor.redact(body: body, contentType: "application/json") == "[body omitted: \(body.count) bytes, application/json]")
        #expect(redactor.redact(body: body, contentType: nil) == "[body omitted: \(body.count) bytes, no content type]")
        let fits = Data(("{\"a\":\"" + String(repeating: "abc ", count: (SensitiveDataRedactor.defaultMaximumBodySize - 8) / 4) + "\"}").utf8)
        #expect(fits.count == SensitiveDataRedactor.defaultMaximumBodySize)
        #expect(redactor.redact(body: fits, contentType: "application/json") == String(decoding: fits, as: UTF8.self))
    }

    @Test("an app may raise or lower the body limit")
    func customLimit() {
        let body = Data(("{\"a\":\"" + String(repeating: "abc ", count: 75_000) + "\"}").utf8)
        let raised = SensitiveDataRedactor(maximumBodySize: 1_048_576)
        #expect(raised.redact(body: body, contentType: "application/json") == String(decoding: body, as: UTF8.self))
        #expect(redactor.redact(body: body, contentType: "application/json") == "[body omitted: \(body.count) bytes, application/json]")
        let lowered = SensitiveDataRedactor(maximumBodySize: 10)
        #expect(lowered.redact(body: Data(#"{"a":"bc"}"#.utf8), contentType: "application/json") == #"{"a":"bc"}"#)
        #expect(lowered.redact(body: Data(#"{"a":"bcd"}"#.utf8), contentType: "application/json") == "[body omitted: 11 bytes, application/json]")
    }

    // MARK: Multipart

    private func multipart(_ parts: [String], boundary: String = "XyZ") -> String {
        parts.map { "--\(boundary)\r\n\($0)\r\n" }.joined() + "--\(boundary)--\r\n"
    }

    @Test("reads each multipart part by its name and content type")
    func multipartParts() {
        let body = multipart([
            "Content-Disposition: form-data; name=\"user\"\r\n\r\nbob",
            "Content-Disposition: form-data; name=\"password\"\r\n\r\nhunter2",
            "Content-Disposition: form-data; name=\"p\u{0430}ssword\"\r\n\r\nhunter2",
            "Content-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"token\":\"abc\",\"n\":1}",
            "Content-Disposition: form-data; name=\"note\"\r\n\r\nlogin with api_key=abc123",
            "Content-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\u{1}PNG",
        ])
        let expected = multipart([
            "Content-Disposition: form-data; name=\"user\"\r\n\r\nbob",
            "Content-Disposition: form-data; name=\"password\"\r\n\r\n[redacted]",
            "Content-Disposition: form-data; name=\"p\u{0430}ssword\"\r\n\r\n[redacted]",
            "Content-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"token\":\"[redacted]\",\"n\":1}",
            "Content-Disposition: form-data; name=\"note\"\r\n\r\nlogin with api_key=[redacted]",
            "Content-Disposition: form-data; name=\"avatar\"\r\nContent-Type: image/png\r\n\r\n[body omitted: 4 bytes, image/png]",
        ])
        // The output ends at the closing boundary, without the line break after it.
        #expect(redact(body, "multipart/form-data; boundary=XyZ") + "\r\n" == expected)
    }

    @Test("writes part headers again: the field name, the type, and other headers only when they are kept")
    func multipartHeaders() {
        let body = multipart([
            "Content-Disposition: form-data; name=\"note\"; filename=\"alice-passport.txt\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nx",
            "content-disposition: form-data; name=\"bio\"\r\nX-Secret: s3cr3t\r\nContent-Length: 2\r\n\r\nhi",
            "Content-Disposition: form-data; name=\"data\"\r\nContent-Transfer-Encoding: base64\r\n\r\naHVudGVyMg==",
            "Content-Disposition: form-data; name=\"a=b\"\r\n\r\nok",
        ])
        let expected = multipart([
            "Content-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\n[body omitted: 1 byte, text/plain]",
            "Content-Disposition: form-data; name=\"bio\"\r\n[redacted]: [redacted]\r\nContent-Length: 2\r\n\r\nhi",
            "Content-Disposition: form-data; name=\"data\"\r\nContent-Transfer-Encoding: base64\r\n\r\n[body omitted: 12 bytes, text/plain]",
            "Content-Disposition: form-data; name=\"a=[redacted]\"\r\n\r\n[redacted]",
        ])
        let output = redact(body, "multipart/form-data; boundary=XyZ")
        #expect(output + "\r\n" == expected)
        #expect(!output.contains("passport") && !output.contains("s3cr3t") && !output.contains("aHVudGVyMg"))
    }

    @Test("finds the colon of a part header among the scalars, also before a mark")
    func multipartHeaderColon() {
        let body = multipart(["Content-Disposition: form-data; name=\"bio\"\r\nX-Note:\u{301}s3cr3t\r\n\r\nhi"])
        let expected = multipart(["Content-Disposition: form-data; name=\"bio\"\r\n[redacted]: [redacted]\r\n\r\nhi"])
        #expect(redact(body, "multipart/form-data; boundary=XyZ") + "\r\n" == expected)
        let named = multipart(["Content-Disposition: form-data; name=\"bio\"\r\nContent-ID:\u{301}s3cr3t\r\n\r\nhi"])
        let namedExpected = multipart(["Content-Disposition: form-data; name=\"bio\"\r\nContent-ID: [redacted]\r\n\r\nhi"])
        #expect(redact(named, "multipart/form-data; boundary=XyZ") + "\r\n" == namedExpected)
    }

    // A part header name is a key of the part: only the names of the headers a part may carry are
    // written, so a name that holds a card number, an IBAN or a token never shows.
    @Test("writes a part header name only when it is one a part carries", arguments: [
        "4111111111111111", "X-4111111111111111", "DE89370400440532013000",
        "X-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl", "X-Zk9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT9uV8wX7y",
        "X-Api-Key", "Authorization",
    ])
    func multipartHeaderNames(name: String) {
        let body = multipart(["Content-Disposition: form-data; name=\"a\"\r\n\(name): 1\r\nContent-Length: 1\r\n\r\nx"])
        let expected = multipart(["Content-Disposition: form-data; name=\"a\"\r\n[redacted]: [redacted]\r\nContent-Length: 1\r\n\r\nx"])
        #expect(redact(body, "multipart/form-data; boundary=XyZ") + "\r\n" == expected)
        #expect(redact(body, "multipart/form-data; boundary=XyZ") + "\r\n" == expected)
    }

    @Test("omits multipart bodies that servers could split differently", arguments: [
        "preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XyZ--\r\nepilogue",
        "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XyZX\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx",
        "--XyZ\r\nContent-Disposition: form-data\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data; name=\"a\"; name=\"password\"\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data; name*=UTF-8''password\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data;\r\n name=\"password\"\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\nContent-Type: text/plain\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\nx\r\n--XyZ--",
        "--XyZ\r\nContent-Disposition:\u{301} form-data; name=\"password\"\r\n\r\nhunter2\r\n--XyZ--",
    ])
    func malformedMultipart(body: String) {
        #expect(redact(body, "multipart/form-data; boundary=XyZ") == "[body omitted: \(body.utf8.count) bytes, multipart/form-data]")
    }

    @Test("omits multipart bodies with a missing, repeated or invalid boundary", arguments: [
        "multipart/form-data",
        "multipart/form-data; boundary=XyZ; boundary=Other",
        "multipart/form-data; boundary=XyZ; boundary*=UTF-8''XyZ",
        "multipart/form-data; boundary=\"Xy\\Z\"",
        "multipart/form-data; boundary=\"XyZ \"",
    ])
    func badBoundary(contentType: String) {
        let body = "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XyZ--"
        #expect(redact(body, contentType) == "[body omitted: \(body.utf8.count) bytes, multipart/form-data]")
    }

    // MARK: Other types

    @Test("reads plain text with the free-text rule")
    func plainText() {
        #expect(redact("login password=hunter2 ok=1", "text/plain; charset=us-ascii") == "login password=[redacted]")
        #expect(redact("status=200 method=GET", "text/plain") == "status=200 method=GET")
    }

    @Test("omits bodies of other types and with unreadable content types", arguments: [
        ("<a><password>hunter2</password></a>", "application/xml", "application/xml"),
        ("<p>password=hunter2</p>", "text/html", "text/html"),
        ("password=hunter2", "application/octet-stream", "application/octet-stream"),
        ("password=hunter2", "json", "unreadable content type"),
        ("password=hunter2", "application/json; charset", "unreadable content type"),
        ("x", "text/csv", "text/csv"),
    ])
    func otherTypes(body: String, contentType: String, described: String) {
        let count = body.utf8.count
        #expect(redact(body, contentType) == "[body omitted: \(count) \(count == 1 ? "byte" : "bytes"), \(described)]")
    }

    @Test("an empty body stays empty")
    func emptyBody() {
        #expect(redactor.redact(body: Data(), contentType: "application/octet-stream") == "")
    }

    @Test("kinds without secret fields still parse the body")
    func kindsWithoutSecretFields() {
        let emailsOnly = SensitiveDataRedactor(kinds: .emailAddresses)
        let body = #"{"password":"hunter2","email":"alice@example.com"}"#
        #expect(emailsOnly.redact(body: Data(body.utf8), contentType: "application/json") == #"{"password":"hunter2","email":"a•••@example.com"}"#)
    }
}
