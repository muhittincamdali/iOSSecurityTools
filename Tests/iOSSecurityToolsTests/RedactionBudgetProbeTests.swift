import Foundation
import Testing
import iOSSecurityTools

/// A probe of the nesting budget: input that puts a secret where a limit is reached, and how it
/// is redacted.
struct BudgetProbe: Sendable, CustomTestStringConvertible {
    enum Shape: Sendable { case text, json, form, multipart }

    let testDescription: String
    let shape: Shape
    let input: String
    var allowedQueryParameters: [String] = []

    func redacted() -> String {
        let redactor = SensitiveDataRedactor(allowedQueryParameters: allowedQueryParameters)
        switch shape {
        case .text: return redactor.redact(input)
        case .json: return redactor.redact(body: Data(input.utf8), contentType: "application/json")
        case .form: return redactor.redact(body: Data(input.utf8), contentType: "application/x-www-form-urlencoded")
        case .multipart: return redactor.redact(body: Data(input.utf8), contentType: "multipart/form-data; boundary=B")
        }
    }
}

// The probes written for the nesting budget: a secret at a level or depth limit, behind a limit,
// and in chains that mix JSON, URLs, forms and multipart parts. Each is redacted on a 512 KiB
// thread and must not show the secret.
@Suite("SensitiveDataRedactor nesting budget probes")
struct RedactionBudgetProbeTests {
    static let secret = "hunter2"

    private static func quoted(_ text: String) -> String { "\"" + RedactionStackTests.escaped(text) + "\"" }
    private static func noted(_ text: String) -> String { "{\"note\":" + quoted(text) + "}" }
    private static func noted(_ text: String, times: Int) -> String { (0..<times).reduce(text) { inner, _ in noted(inner) } }
    private static func brackets(_ count: Int, around inner: String) -> String {
        String(repeating: "[", count: count) + inner + String(repeating: "]", count: count)
    }
    private static func percentEncoded(_ text: String) -> String { text.addingPercentEncoding(withAllowedCharacters: .alphanumerics)! }

    static let secretJSON = #"{"password":"hunter2"}"#
    static let secretPair = "password=hunter2"

    static let probes: [BudgetProbe] = [
        BudgetProbe(testDescription: "a secret key four documents deep", shape: .json, input: noted(secretJSON, times: 3)),
        BudgetProbe(testDescription: "a secret key five documents deep", shape: .json, input: noted(secretJSON, times: 4)),
        BudgetProbe(testDescription: "a secret key nine documents deep", shape: .json, input: noted(secretJSON, times: 8)),
        BudgetProbe(testDescription: "a secret pair five documents deep in text", shape: .text, input: "log " + noted(secretPair, times: 5)),
        BudgetProbe(testDescription: "a secret pair after JSON one level too many", shape: .json,
                    input: noted("x {\"a\":1} " + secretPair, times: 4)),
        BudgetProbe(testDescription: "a secret pair before JSON one level too many", shape: .json,
                    input: noted(secretPair + " {\"a\":1}", times: 4)),
        BudgetProbe(testDescription: "secret JSON in a string inside 64 arrays", shape: .json, input: brackets(64, around: quoted(secretJSON))),
        BudgetProbe(testDescription: "a secret pair in a string inside 64 arrays", shape: .json, input: brackets(64, around: quoted(secretPair))),
        BudgetProbe(testDescription: "a secret pair in a string inside 65 arrays", shape: .json, input: brackets(65, around: quoted(secretPair))),
        BudgetProbe(testDescription: "secret JSON 65 arrays deep in a log line", shape: .text, input: "a " + brackets(65, around: secretJSON)),
        BudgetProbe(testDescription: "secret JSON 65 arrays deep over lines", shape: .text,
                    input: "a " + String(repeating: "[", count: 65) + "\n" + secretJSON + "\n" + String(repeating: "]", count: 65) + " b"),
        BudgetProbe(testDescription: "a secret pair after JSON too deep in a string", shape: .json,
                    input: noted(brackets(64, around: "1") + " " + secretPair)),
        BudgetProbe(testDescription: "secret JSON as a name four documents deep", shape: .json,
                    input: noted("{" + quoted(secretJSON) + ":1}", times: 3)),
        BudgetProbe(testDescription: "secret JSON as a name five documents deep", shape: .json,
                    input: noted("{" + quoted(secretJSON) + ":1}", times: 4)),
        BudgetProbe(testDescription: "a password in a URL four documents deep", shape: .json,
                    input: noted("see https://bob:hunter2@example.com/a", times: 3)),
        BudgetProbe(testDescription: "a password in a URL five documents deep", shape: .json,
                    input: noted("see https://bob:hunter2@example.com/a", times: 4)),
        BudgetProbe(testDescription: "secret JSON in an allowed query value in a JSON string", shape: .json,
                    input: noted("https://a.example/?q=" + percentEncoded(secretJSON), times: 2), allowedQueryParameters: ["q"]),
        BudgetProbe(testDescription: "a URL chain in allowed query values ending in a secret pair", shape: .text,
                    input: String(repeating: "https://a.example/?q=", count: 6) + secretPair, allowedQueryParameters: ["q"]),
        BudgetProbe(testDescription: "secret JSON in a form value, quoted three times", shape: .form,
                    input: "note=" + percentEncoded(noted(secretJSON, times: 3))),
        BudgetProbe(testDescription: "secret JSON in a form value, quoted four times", shape: .form,
                    input: "note=" + percentEncoded(noted(secretJSON, times: 4))),
        BudgetProbe(testDescription: "secret JSON in a multipart JSON part, quoted two and three times", shape: .multipart,
                    input: "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: application/json\r\n\r\n"
                        + noted(secretJSON, times: 2) + "\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n"
                        + "Content-Type: application/json\r\n\r\n" + noted(secretJSON, times: 3) + "\r\n--B--"),
        BudgetProbe(testDescription: "a secret pair in a multipart text part five documents deep", shape: .multipart,
                    input: "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nlog " + noted(secretPair, times: 4) + "\r\n--B--"),
        BudgetProbe(testDescription: "a secret pair in a multipart header", shape: .multipart,
                    input: "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Length: " + noted(secretPair, times: 4) + "\r\n\r\nx\r\n--B--"),
        BudgetProbe(testDescription: "an array that names a secret five documents deep", shape: .json,
                    input: noted(#"["password","hunter2"]"#, times: 4)),
        BudgetProbe(testDescription: "a name and value pair four documents deep", shape: .json,
                    input: noted(#"{"name":"password","value":"hunter2"}"#, times: 3)),
        BudgetProbe(testDescription: "escaped JSON in text one level too many", shape: .text,
                    input: noted(#"{\"password\":\"hunter2\"}"#, times: 4)),
        BudgetProbe(testDescription: "a secret after the deepest JSON a line may hold", shape: .text,
                    input: brackets(64, around: "1") + " password hunter2"),
    ]

    @Test("budget probes do not show the secret", arguments: probes)
    func probe(_ probe: BudgetProbe) {
        let output = onThread(stackSize: RedactionStackTests.threadStack, probe.redacted)
        #expect(!output.contains(Self.secret), "\(probe.input.prefix(120).debugDescription) -> \(output.prefix(200).debugDescription)")
    }
}
