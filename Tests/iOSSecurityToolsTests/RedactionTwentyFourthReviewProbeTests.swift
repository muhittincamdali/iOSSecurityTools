import Foundation
import Testing
@testable import iOSSecurityTools

/// The twenty-fourth review (`a-24`) found two classes of values shown that the documentation
/// says are hidden.
///
/// - **A name with a line break beside a field that holds no name.** `ParameterKey`, `OptionName`,
///   `attribute`, `Parameter`, `setting` and `env` hold names, but are not fields the redactor
///   knows to hold one, so a string there names a secret only when it is a name. A string with a
///   line feed or carriage return was not a name, so `{"ParameterKey":"DbPassword\n",
///   "ParameterValue":…}` showed the value, in JSON, a form, a multipart body and an allowed query
///   (64 of the probes). A name with a control character now names a secret when it does with
///   its control characters left out or read as spaces, and whatever it says in a field that
///   holds a name (see ``WrittenName/nameNamesSecret(_:byKeyRule:compatibility:)``).
/// - **A finding cut by a line separator.** A card number, an IBAN, an email address or a token
///   with a vertical tab, a form feed, U+0085, U+2028 or U+2029 in it showed the part before it
///   (`paid with 4111 1111 1111` and the vertical tab, 28 of the probes): free text is cut there,
///   and the detectors did not read across it. They now do, so the finding is whole and the text is
///   hidden from its start (see ``NormalizedText/isGap(_:)`` and ``NormalizedText/readable(after:)``).
@Suite("SensitiveDataRedactor twenty-fourth review probes")
struct RedactionTwentyFourthReviewProbeTests {
    /// The probes that showed their secret in the review.
    static let leakedNames = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43]
        + Array(1009...1038) + Array(1044...1050)
    static let leakedFindings = [911, 914, 917, 920, 923, 962, 963, 964, 965, 966, 968, 979, 980, 981, 982, 983, 985, 986, 987,
                                 988, 989, 990, 998, 999, 1001, 1002, 1004, 1005]

    @Test("the probes are numbered as the review numbered them")
    func counts() {
        let names = TwentyFourthReviewProbes.names
        let findings = TwentyFourthReviewProbes.findings
        #expect(names.count == 91 && findings.count == 100)
        #expect(names.map(\.id) == Array(1...45) + Array(1009...1054))
        #expect(findings.map(\.id) == Array(909...1008))
        #expect(names.first?.text == #"{"ParameterKey":"DbPassword\n","ParameterValue":"Qz001Wk5m"}"#)
        #expect(names.first { $0.id == 1046 }?.text == #"{"OptionSettings":[{"Namespace":"aws:rds","OptionName":"\nDBPassword","Value":"Qz1046Wk5m"}]}"#)
        #expect(findings.first { $0.id == 911 }?.text == "paid with 4111 1111 1111\u{000B}1111 ok")
        #expect(findings.first { $0.id == 979 }?.text == "mail Qz979Wk5m\u{000B}@example.com ok")
        #expect(Self.leakedNames.count == 64)
        #expect(Self.leakedFindings.count == 28)
    }

    @Test("a name with a line break beside a field that holds no name hides the value on every path")
    func names() {
        for probe in TwentyFourthReviewProbes.names {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim): \(probe.text.debugDescription) -> \(output.debugDescription)"
            if probe.claim == "K" {
                #expect(piece != nil, "\(description) is hidden")
            } else {
                #expect(piece == nil, "\(description)")
            }
        }
    }

    @Test("a finding cut by a control character or a line separator is hidden whole on every path")
    func findings() {
        for probe in TwentyFourthReviewProbes.findings {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim): \(probe.text.debugDescription) -> \(output.debugDescription)"
            if probe.claim == "X" {
                // A line feed or carriage return written as such is a line break of the log, which
                // ends a card number: the text is not cut there, and no card number is found.
                #expect(output == probe.text, "\(description)")
            } else {
                #expect(piece == nil, "\(description)")
            }
        }
    }

    @Test("the review's examples read as the documentation says")
    func examples() {
        let redactor = SensitiveDataRedactor()
        let body = { (text: String) in redactor.redact(body: Data(text.utf8), contentType: "application/json") }
        #expect(body(#"{"ParameterKey":"DbPassword\n","ParameterValue":"hunter2"}"#) == #"{"ParameterKey":"[redacted]","ParameterValue":"[redacted]"}"#)
        #expect(body(#"{"OptionName":"Db\nPassword","Value":"hunter2"}"#) == #"{"OptionName":"Db\nPassword","Value":"[redacted]"}"#)
        #expect(body(#"{"OptionName":"pa\nssword","Value":"hunter2"}"#) == #"{"OptionName":"pa\nssword","Value":"[redacted]"}"#)
        #expect(redactor.redact("paid with 4111 1111 1111\u{000B}1111 ok") == "paid with [redacted]")
        #expect(redactor.redact("to DE89 3704 0044 0532\u{2028}0130 00 ok") == "to [redacted]")
        #expect(redactor.redact("mail bob.smith\u{000B}@example.com") == "mail [redacted]")
        #expect(redactor.redact("got ghp_A1b2A1b2A1b2A1b2\u{2029}C3d4C3d4C3d4C3d4C3d4 ok") == "got [redacted]")
        #expect(body(#"{"note":"411111111111\u000b1111"}"#) == #"{"note":"[redacted]"}"#)
        // Usefulness: a name that is plain keeps the value beside a field that holds no name.
        #expect(body(#"{"ParameterKey":"DbUser","ParameterValue":"bob"}"#) == #"{"ParameterKey":"[redacted]","ParameterValue":"bob"}"#)
        #expect(body(#"{"OptionName":"Region","Value":"eu-west-1"}"#) == #"{"OptionName":"Region","Value":"eu-west-1"}"#)
        #expect(body(#"{"message":"Error: x\ny","code":"42"}"#) == #"{"message":"Error: [redacted]","code":"42"}"#)
    }

    @Test("a name with any control character in it, held by a field that holds a name, names a secret on every path")
    func controlCharacters() {
        let redactor = SensitiveDataRedactor()
        let controls: [Unicode.Scalar] = ["\n", "\r", "\t", "\u{0B}", "\u{0C}", "\u{00}", "\u{1B}", "\u{7F}", "\u{85}", "\u{9F}"]
        var shown: [String] = []
        for control in controls {
            for name in ["Db\(control)User", "\(control)region", "region\(control)"] {
                let escaped = name.unicodeScalars.map { $0.isASCII && $0.value >= 0x20 && $0 != "\u{7F}" ? String($0) : String(format: "\\u%04x", $0.value) }.joined()
                let bodies = [
                    (#"{"name":"\#(escaped)","value":"98765"}"#, "application/json"),
                    (#"[{"label":"\#(escaped)","Value":"98765"}]"#, "application/json"),
                    (#"[["\#(escaped)","98765"]]"#, "application/json"),
                    ("label=\(SensitiveDataRedactor.formEncoded(name))&Value=98765", "application/x-www-form-urlencoded"),
                    ("--B0und\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\n\(name)\r\n--B0und\r\n"
                        + "Content-Disposition: form-data; name=\"Value\"\r\n\r\n98765\r\n--B0und--", "multipart/form-data; boundary=B0und"),
                ]
                for (body, type) in bodies where redactor.redact(body: Data(body.utf8), contentType: type).contains("98765") {
                    shown.append(body)
                }
            }
        }
        #expect(shown.isEmpty, "\(shown.prefix(5))")
    }
}
