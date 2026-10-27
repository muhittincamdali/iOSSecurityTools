import Foundation
import Testing
import iOSSecurityTools

/// The values of the two part headers a multipart body keeps, `Content-Length` and
/// `Content-Transfer-Encoding`, are written by their shape and never read as free text (shared
/// redaction spec §4 B4, §8.1 #17b). Read as free text, a value that no rule finds was written as
/// it is (`Content-Length: 12 hunter2`, `Content-Transfer-Encoding: hunter2`).
@Suite("SensitiveDataRedactor multipart part header values")
struct RedactionPartHeaderValueTests {
    private let redactor = SensitiveDataRedactor()

    /// The header line written for a part that carries `header`, the third line of the output.
    private func writtenLine(_ header: String, using redactor: SensitiveDataRedactor = SensitiveDataRedactor()) -> String {
        let body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\(header)\r\n\r\nx\r\n--B--"
        let output = redactor.redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B")
        let lines = output.components(separatedBy: "\r\n")
        return lines.count > 2 ? lines[2] : output
    }

    @Test("a Content-Length of ASCII digits is written as it is, without the white space around it", arguments: [
        ("Content-Length: 1", "Content-Length: 1"),
        ("Content-Length: 4831", "Content-Length: 4831"),
        ("content-length:  007 ", "content-length: 007"),
        ("Content-Length:\t262144", "Content-Length: 262144"),
        ("Content-Length: 999999999999", "Content-Length: 999999999999"),
    ])
    func contentLengthShown(header: String, expected: String) {
        #expect(writtenLine(header) == expected)
    }

    // Twelve digits is the longest word in which no value detector finds anything: the shortest
    // card number has 13 digits. A part of a terabyte is not in a body that is read.
    @Test("any other Content-Length is redacted", arguments: [
        "pin-4831", "12 hunter2", "\u{0661}\u{0662}", "hunter2", "", "+12", "-1", "0x1F", "1e3", "1,024", "12.0", "1_000",
        "\u{FF11}\u{FF12}", "1\u{0301}2", "4111111111111111", "4111 1111 1111 1111", "1234567890123", "12;x", "12\u{00A0}34",
    ])
    func contentLengthRedacted(value: String) {
        let line = writtenLine("Content-Length: " + value)
        #expect(line == "Content-Length: [redacted]", "\(value.debugDescription) -> \(line.debugDescription)")
    }

    @Test("a Content-Transfer-Encoding of MIME is written in lowercase", arguments: [
        ("Content-Transfer-Encoding: BASE64", "Content-Transfer-Encoding: base64"),
        ("Content-Transfer-Encoding: base64", "Content-Transfer-Encoding: base64"),
        ("Content-Transfer-Encoding:  Quoted-Printable ", "Content-Transfer-Encoding: quoted-printable"),
        ("Content-Transfer-Encoding: 7BIT", "Content-Transfer-Encoding: 7bit"),
        ("content-transfer-encoding: 8bit", "content-transfer-encoding: 8bit"),
        ("Content-Transfer-Encoding: Binary", "Content-Transfer-Encoding: binary"),
    ])
    func transferEncodingShown(header: String, expected: String) {
        #expect(writtenLine(header) == expected)
    }

    @Test("any other Content-Transfer-Encoding is redacted", arguments: [
        "hunter2", "pin-4831", "x-uuencode", "base64 hunter2", "base64; x", "7bit,8bit", "\u{FF42}\u{FF41}\u{FF53}\u{FF45}64",
        "bas\u{0435}64", "quoted printable", "", "bin\u{200B}ary", "8\u{00AD}bit",
    ])
    func transferEncodingRedacted(value: String) {
        let line = writtenLine("Content-Transfer-Encoding: " + value)
        #expect(line == "Content-Transfer-Encoding: [redacted]", "\(value.debugDescription) -> \(line.debugDescription)")
    }

    @Test("the shape rule does not depend on the kinds the redactor looks for")
    func shapeRuleWithoutKinds() {
        for redactor in [SensitiveDataRedactor(kinds: []), SensitiveDataRedactor(kinds: [.cardNumbers])] {
            #expect(writtenLine("Content-Length: 12 hunter2", using: redactor) == "Content-Length: [redacted]")
            #expect(writtenLine("Content-Transfer-Encoding: hunter2", using: redactor) == "Content-Transfer-Encoding: [redacted]")
            #expect(writtenLine("Content-Length: 12", using: redactor) == "Content-Length: 12")
        }
    }

    // One reading of the header decides what is written and whether the content is read: only
    // `7bit`, `8bit` and `binary` leave the content as it is.
    @Test("the transfer encoding still decides whether the content is read")
    func contentFollowsTheEncoding() {
        let type = "multipart/form-data; boundary=B"
        func output(_ encoding: String) -> String {
            let body = "--B\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Transfer-Encoding: \(encoding)\r\n\r\nhi\r\n--B--"
            return redactor.redact(body: Data(body.utf8), contentType: type)
        }
        #expect(output("8BIT") == "--B\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Transfer-Encoding: 8bit\r\n\r\nhi\r\n--B--")
        #expect(output("BASE64").hasSuffix("Content-Transfer-Encoding: base64\r\n\r\n[body omitted: 2 bytes, text/plain]\r\n--B--"))
        #expect(output("hunter2").hasSuffix("Content-Transfer-Encoding: [redacted]\r\n\r\n[body omitted: 2 bytes, text/plain]\r\n--B--"))
        #expect(!output("hunter2").contains("hunter2"))
    }
}
