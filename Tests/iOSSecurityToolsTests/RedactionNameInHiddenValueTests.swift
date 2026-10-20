import Foundation
import Testing
@testable import iOSSecurityTools

/// A secret name written as a value names what follows it wherever it is written on its line, also
/// inside the value of another key that is hidden already: in a multipart body written to a log,
/// `Content-Disposition: form-data; name="pin"` hides the value of `Content-Disposition`, and the
/// name in it still hides the part's value on the lines below. The names are found in a second
/// pass over the text that the first pass hid without reading it.
@Suite("SensitiveDataRedactor secret names inside hidden values")
struct RedactionNameInHiddenValueTests {
    let redactor = SensitiveDataRedactor()
    static let secret = "HUNTER2XY"

    /// The text as a log line, as a text/plain body and as a string in a JSON body.
    func outputs(_ text: String) -> [String] {
        let json = try! JSONSerialization.data(withJSONObject: ["note": text])
        return [
            redactor.redact(text),
            redactor.redact(body: Data(text.utf8), contentType: "text/plain"),
            redactor.redact(body: json, contentType: "application/json"),
        ]
    }

    func expectHidden(_ input: String, _ secrets: [String] = [secret], sourceLocation: SourceLocation = #_sourceLocation) {
        for output in outputs(input) {
            for secret in secrets {
                #expect(!output.contains(secret), "\(input.debugDescription) -> \(output.debugDescription)", sourceLocation: sourceLocation)
            }
        }
    }

    @Test("the twelfth review's probes hide the value after the name", arguments: [
        "Content-Disposition: form-data; name=\"pin\"\r\n\r\nHUNTER2XY",
        "--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\nHUNTER2XY\r\n--B--",
        "upload failed body=--B\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nHUNTER2XY\r\n--B--",
        "Content-Disposition: form-data; name=password\r\n\r\nHUNTER2XY",
        "note: a name=\"pin\"\nHUNTER2XY",
        // The controls of the review: without a key before them the names hid the value already.
        "form-data; name=\"pin\"\n\nHUNTER2XY",
        "name=\"pin\"\n\nHUNTER2XY",
    ])
    func reviewProbes(input: String) {
        expectHidden(input)
    }

    @Test("the review's JSON body with a multipart body in a string hides the value")
    func reviewJSONBody() {
        let body = #"{"msg":"--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\nQz213Wk7r\r\n--B--"}"#
        let output = redactor.redact(body: Data(body.utf8), contentType: "application/json")
        #expect(output == #"{"msg":"--B\r\nContent-Disposition: [redacted]\r\n\r\n[redacted]\r\n--B--"}"#)
    }

    @Test("what a name inside a hidden value hides", arguments: [
        ("Content-Disposition: form-data; name=\"pin\"\r\n\r\nHUNTER2XY", "Content-Disposition: [redacted]\r\n\r\n[redacted]"),
        ("note: a name=\"pin\"\nHUNTER2XY", "note: [redacted]\n[redacted]"),
        ("token: |\n  name=\"pin\"\n\nHUNTER2XY", "token: [redacted]\n  [redacted]\n\n[redacted]"),
        ("msg=\"name=\\\"pin\\\"\" HUNTER2XY", "msg=\"[redacted]\"[redacted]"),
        ("msg='label=\u{15E}ifre' HUNTER2XY", "msg='[redacted]'[redacted]"),
        ("status=name=\"pin\"\n\nHUNTER2XY", "status=name=\"[redacted]\"\n\n[redacted]"),
        ("x: name=[\n\"x\"\n] HUNTER2XY", "x: [redacted]\n[redacted]\n[redacted]"),
    ])
    func exactOutput(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("every way to write the name in a part header", arguments: [
        "Content-Disposition: form-data; name=\"pin\"\rHUNTER2XY",
        "Content-Disposition: form-data; name=\"pin\"\u{2028}\u{2028}HUNTER2XY",
        "Content-Disposition: form-data; name=\"pin\"\n\nHUNTER2XY",
        "Content-Disposition: form-data; name*=UTF-8''pin\r\n\r\nHUNTER2XY",
        "Content-Disposition: form-data; NAME=\"PIN\"\r\n\r\nHUNTER2XY",
        "content-disposition: form-data; name = \"pin\"\r\n\r\nHUNTER2XY",
        "Content-Disposition: form-data; name='pin'\r\n\r\nHUNTER2XY",
        "Content-Disposition: form-data; name=\\\"pin\\\"\r\n\r\nHUNTER2XY",
        "Content-Disposition: form-data; name=\"p\u{0430}ssword\"\r\n\r\nHUNTER2XY",
        "Content-Disposition: form-data; name=\"\u{15E}ifre\"\r\n\r\nHUNTER2XY",
        "X-Debug: Content-Disposition: form-data; name=\"pin\"\n\nHUNTER2XY",
    ])
    func partHeaders(input: String) {
        expectHidden(input)
    }

    @Test("a part's other headers and every line of its value are hidden", arguments: [
        ("Content-Disposition: form-data; name=\"pin\"\r\nContent-Type: text/plain\r\n\r\nHUNTER2XY", ["HUNTER2XY"]),
        (
            "--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\nHUNTER2XY\r\nSECOND2XY\r\n\r\nTHIRD2XY\r\n--B--",
            ["HUNTER2XY", "SECOND2XY", "THIRD2XY"]
        ),
        ("Content-Disposition: form-data; name=\"pin\"\n\nHUNTER2XY\nSECOND2XY", ["HUNTER2XY", "SECOND2XY"]),
        (
            "Content-Disposition: form-data; name=\"private_key\"\n\n-----BEGIN PRIVATE KEY-----\nMIIEHUNTER2XY\n-----END PRIVATE KEY-----",
            ["MIIEHUNTER2XY"]
        ),
        ("DEBUG --B\nDEBUG Content-Disposition: form-data; name=\"pin\"\nDEBUG\nDEBUG HUNTER2XY", ["HUNTER2XY"]),
    ])
    func partValues(input: String, secrets: [String]) {
        expectHidden(input, secrets)
    }

    @Test("the parts after the one with the secret name keep their values")
    func followingParts() {
        let body = "--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\nHUNTER2XY\r\n--B\r\n"
            + "Content-Disposition: form-data; name=\"note\"\r\n\r\nVISIBLE1\r\n--B--"
        for output in outputs(body) {
            #expect(!output.contains(Self.secret) && output.contains("VISIBLE1"), "\(output.debugDescription)")
        }
        #expect(redactor.redact("Content-Disposition: form-data; name=\"pin\"\n\nHUNTER2XY\n\nVISIBLE1").hasSuffix("\n\nVISIBLE1"))
    }

    @Test("names held by other keys inside a hidden value", arguments: [
        "x: key='token'\nHUNTER2XY",
        "x: id: \"pin\"\nHUNTER2XY",
        "x: header=\"Authorization\"\nHUNTER2XY",
        "x: label=\"API Key\"\nHUNTER2XY",
        "x: label=\"\u{41F}\u{430}\u{440}\u{43E}\u{43B}\u{44C}\"\nHUNTER2XY",
        "x: label=\u{15E}ifre\nHUNTER2XY",
        "x: name=[\"pin\"]\nHUNTER2XY",
        "x: name=password\n\nHUNTER2XY",
        "x: <string name=\"api_key\">\nHUNTER2XY\n</string>",
        "x: <string name=\"password\" />\nHUNTER2XY",
        "x: <entry key=\"db.password\">\nHUNTER2XY\n</entry>",
        "msg=\"a\nname=\\\"pin\\\"\n\nHUNTER2XY",
    ])
    func heldNames(input: String) {
        expectHidden(input)
    }

    @Test("a quote left open over lines goes on past a part header inside it", arguments: [
        "msg=\"a\nContent-Disposition: form-data; name=\\\"pin\\\"\n\nx\n\nHUNTER2XY\"",
        "Content-Disposition: form-data; name=\"pin\"; filename=\"bob's\"\r\n\r\nx\r\n\r\nHUNTER2XY",
    ])
    func openQuotes(input: String) {
        expectHidden(input)
    }

    @Test("an unquoted name after a key that holds one names what follows it", arguments: [
        ("name=password\n\nHUNTER2XY", "name=[redacted]\n\n[redacted]"),
        ("type=password\nHUNTER2XY", "type=[redacted]\n[redacted]"),
        ("name=status\nVISIBLE1", "name=[redacted]\nVISIBLE1"),
    ])
    func unquotedNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("names that are not secret keep what follows them", arguments: [
        ("Content-Disposition: form-data; name=\"status\"\r\n\r\nVISIBLE1", "Content-Disposition: [redacted]\r\n\r\nVISIBLE1"),
        ("x: name=\"status\"\nVISIBLE1", "x: [redacted]\nVISIBLE1"),
        ("--B\nContent-Disposition: form-data; name=\"note\"\n\nVISIBLE1\n--B--", "--B\nContent-Disposition: [redacted]\n\nVISIBLE1\n--B--"),
        ("msg: wrong password\nstatus=200", "msg: [redacted]\nstatus=200"),
        ("Content-Disposition: attachment\nstatus=200", "Content-Disposition: [redacted]\nstatus=200"),
        ("<key>user</key>\n<string>bob</string>\nstatus=200", "<key>[redacted]\n<string>bob</string>\nstatus=200"),
    ])
    func plainNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a form value that holds a multipart body hides the value after the name")
    func formValue() {
        let form = "note=--B%0D%0AContent-Disposition%3A+form-data%3B+name%3D%22pin%22%0D%0A%0D%0AHUNTER2XY"
        let output = redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded")
        #expect(!output.contains(Self.secret), "\(output)")
    }

    @Test("the logging guide's example of a name inside a hidden value")
    func guideExample() {
        #expect(redactor.redact("Content-Disposition: form-data; name=\"pin\"\r\n\r\n4831") == "Content-Disposition: [redacted]\r\n\r\n[redacted]")
    }
}
