import Foundation
import Testing
@testable import iOSSecurityTools

/// A `:` between two digits is part of a number only after a number. The fourteenth review showed
/// that reading every such `:` as part of a time let the value of a key that ends in digits through
/// (`user1:2345678`, `acct2:44556677`), in a line and in a JSON string or form value alike.
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
