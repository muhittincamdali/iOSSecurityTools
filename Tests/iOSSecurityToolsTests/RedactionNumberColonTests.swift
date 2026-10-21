import Foundation
import Testing
@testable import iOSSecurityTools

/// A `:` between two digits is part of a number only when both sides are numbers. The fourteenth
/// review showed that reading every such `:` as part of a time let the value of a key that ends in
/// digits through (`user1:2345678`, `acct2:44556677`), in a line and in a JSON string or form value
/// alike. The twenty-fourth review showed that only the side before the `:` was read: after a
/// number, a value that starts with a digit showed whole (`id 7:9hunter2`, `attempt 1:482913`).
@Suite("SensitiveDataRedactor colons between digits")
struct RedactionNumberColonTests {
    let redactor = SensitiveDataRedactor()

    @Test("after a key that ends in digits, a colon is a separator", arguments: [
        "user1:2345678", "acct2:44556677", "phone1:905551234567", "user_id2:998877", "status=ok retry3:5", "user\u{FF11}:\u{FF12}345678",
        "user1:2345", "item2-1:2345", "db.port1:5432", "T1:2345", "v1.2:3", "id-9:12", "a.b.1:44",
    ])
    func keyEndingInDigits(input: String) {
        let output = redactor.redact(input)
        #expect(output.hasSuffix("[redacted]"), "\(input.debugDescription) -> \(output.debugDescription)")
        #expect(!output.contains("2345") && !output.contains("4455") && !output.contains("9988"), "\(input.debugDescription) -> \(output.debugDescription)")
    }

    @Test("times, dates and times, and addresses with ports are kept", arguments: [
        "at 12:30", "at 12:30:45", "2026-10-19T12:30:45Z", "2026-10-19T12:30:45.123+03:00", "2026-10-19T12:30:45-05:00",
        "connect 10.0.0.1:8080 ok", "connect 192.168.1.100:8080 ok", "took 1:05", "(12:30)", "[12:30:45] started", "line 42:10",
    ])
    func numbersAreKept(input: String) {
        #expect(redactor.redact(input) == input)
    }

    /// The twenty-fourth review's inputs and more of their shape: a letter after the digits that
    /// follow the `:`, five digits or more right after it, and a letter after a later group.
    static let valuesAfterNumbers = [
        "id 7:9hunter2", "user 42:7hunter2xyz", "status=1 12:3hunter2", "x 1.2.3.4:5hunter2", "x 99:99:99hunter2",
        "2026-10-21 12:3hunter2", "status=1 1-1:2hunter2", "attempt 1:482913", "slot 3:482913 ok", "x 12:345678901234",
        "rank 5:5f4dcc3b5aa765d61d8327deb882cf99", "x 0:0hunter2", "status=1 2:3:4:5hunter2", "status=1 99.123:1hunter2",
        "status=1 12:30Zhunter2", "at 12:30:45.123hunter2", "x 10.0.0.1:8080hunter2", "x 10.0.0.1:123456", "x 12:3-4hunter2",
        "x 12:30+03:00hunter2", "x 1:2_hunter2", "x 1:2/hunter2", "x 1:2.hunter2", "x 7:9\u{0430}bc", "x 7:9\u{FF41}bc",
        "x 1:48291",
    ]

    @Test("after a number, a colon is a separator unless a number of the same shape follows it", arguments: valuesAfterNumbers)
    func valueAfterNumber(input: String) {
        let output = redactor.redact(input)
        #expect(output.hasSuffix("[redacted]"), "\(input.debugDescription) -> \(output.debugDescription)")
        for secret in ["hunter2", "482913", "48291", "5f4dcc", "345678", "123456", "\u{0430}bc", "\u{FF41}bc"] {
            #expect(!output.contains(secret), "\(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a value after a number is hidden in a JSON string, a form value and a multipart part too")
    func valueAfterNumberOnEveryPath() {
        for input in Self.valuesAfterNumbers {
            let json = redactor.redact(body: Data(#"{"note":"\#(input)"}"#.utf8), contentType: "application/json")
            #expect(json.hasPrefix(#"{"note":""#) && json.hasSuffix(#"[redacted]"}"#), "\(input.debugDescription) -> \(json)")
            let form = redactor.redact(body: Data(("note=" + SensitiveDataRedactor.formEncoded(input)).utf8), contentType: "application/x-www-form-urlencoded")
            #expect(form.hasPrefix("note=") && form.hasSuffix("[redacted]"), "\(input.debugDescription) -> \(form)")
            let part = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n\(input)\r\n--B0und--"
            let multipart = redactor.redact(body: Data(part.utf8), contentType: "multipart/form-data; boundary=B0und")
            #expect(multipart.contains("[redacted]\r\n--B0und--"), "\(input.debugDescription) -> \(multipart.debugDescription)")
            for output in [json, form, multipart] {
                #expect(!output.contains("hunter2") && !output.contains("482913"), "\(input.debugDescription) -> \(output.debugDescription)")
            }
        }
        // The review's JSON and form inputs, and an allowed query value.
        #expect(redactor.redact(body: Data(#"{"note":"slot 12:3hunter2"}"#.utf8), contentType: "application/json") == #"{"note":"slot 12:[redacted]"}"#)
        #expect(redactor.redact(body: Data("note=12%3A3hunter2".utf8), contentType: "application/x-www-form-urlencoded") == "note=12%3A[redacted]")
        let query = SensitiveDataRedactor(allowedQueryParameters: ["note"]).redact(url: URL(string: "https://x.example/a?note=slot%2012%3A3hunter2")!)
        #expect(!query.contains("hunter2") && query.hasPrefix("https://x.example/a?note=slot"), "\(query)")
    }

    @Test("times with seconds, fractions and offsets, lines and columns, ports and ranges are kept", arguments: [
        "at 12:30:45,123 INFO started", "2026-10-21 12:30:45.123456Z", "2026-10-21T12:30:45+0300", "open 10:00-11:00", "at 12:30.",
        "took 1:05, then 2:10", "connect 10.0.0.1:65535 ok", "1:2:3", "at 9:05!", "{12:30}", "x 1:2|3",
        "line 42:1234",
    ])
    func moreNumbersAreKept(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("a colon after digits glued to a key cuts a JSON string and a form value too")
    func structuredPaths() {
        let json = redactor.redact(body: Data(#"{"note":"acct2:44556677","status":"12:30"}"#.utf8), contentType: "application/json")
        #expect(json == #"{"note":"acct2:[redacted]","status":"12:30"}"#)
        let form = redactor.redact(body: Data("note=acct2%3A44556677".utf8), contentType: "application/x-www-form-urlencoded")
        #expect(!form.contains("44556677"), "\(form)")
        #expect(redactor.redact(body: Data(#"{"note":"at 12:30:45"}"#.utf8), contentType: "application/json") == #"{"note":"at 12:30:45"}"#)
    }

    @Test("a number longer than the colon rule reads is a key")
    func longNumbers() {
        let long = String(repeating: "1-", count: FreeTextScanner.longestNumber) + "1:2345"
        #expect(!redactor.redact(long).contains("2345"))
        #expect(redactor.redact("1-1-1:2345") == "1-1-1:2345")
    }
}
