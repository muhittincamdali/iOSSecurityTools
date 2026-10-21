import Foundation
import Testing
@testable import iOSSecurityTools

/// The twenty-sixth review (`a-26`, `c-26`) found a name of control characters alone that did not
/// hide what was beside it, while the documentation said a name with a control character in it
/// names a secret wherever it is.
@Suite("SensitiveDataRedactor twenty-sixth review")
struct RedactionTwentySixthReviewTests {
    private static let secret = "Qz26Wk5m"

    private static func json(_ text: String) -> String {
        SensitiveDataRedactor().redact(body: Data(text.utf8), contentType: "application/json")
    }

    private static func form(_ text: String) -> String {
        SensitiveDataRedactor().redact(body: Data(text.utf8), contentType: "application/x-www-form-urlencoded")
    }

    private static func multipart(name: String, beside field: String) -> String {
        let body = "--B0und\r\nContent-Disposition: form-data; name=\"\(field)\"\r\n\r\n\(name)\r\n--B0und\r\n"
            + "Content-Disposition: form-data; name=\"Value\"\r\n\r\n\(secret)\r\n--B0und--"
        return SensitiveDataRedactor().redact(body: Data(body.utf8), contentType: "multipart/form-data; boundary=B0und")
    }

    @Test("a name of control characters and spaces alone hides the value beside it, on every path")
    func blankNames() {
        let s = Self.secret
        let shown = [
            Self.json(#"{"ParameterKey":"\n","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":"\t","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":"\u0000","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":" \n ","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"ParameterKey":"\r\n\u007f","ParameterValue":"\#(s)"}"#),
            Self.json(#"{"title":"\n","data":"\#(s)"}"#),
            Self.json(#"[{"OptionName":"\u0085","Value":"\#(s)"}]"#),
            Self.form("ParameterKey=%0A&ParameterValue=\(s)"),
            Self.form("ParameterKey=%00&ParameterValue=\(s)"),
            Self.form("ParameterKey=+%09+&ParameterValue=\(s)"),
            Self.multipart(name: "\t", beside: "OptionName"),
        ].filter { $0.contains(s) }
        #expect(shown.isEmpty, "\(shown)")
    }

    @Test("a name of spaces alone, or an empty one, beside a field that holds no name keeps the value")
    func spacesAlone() {
        #expect(Self.json(#"{"title":" ","data":"ok"}"#) == #"{"title":" ","data":"ok"}"#)
        #expect(Self.json(#"{"title":"","data":"ok"}"#) == #"{"title":"","data":"ok"}"#)
        #expect(Self.form("title=+&data=ok") == "title=+&data=ok")
    }
}
