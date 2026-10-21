import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the seventeenth review, on every free-text path (see
/// ``RedactionCutRuleTests/everyPath(_:)``). The correctness review found the text of an element
/// shown when a quote opened before its tag (`msg "<user>QZ9WK7RXV</user>" done`) and when
/// other markup came between the tag and the text (`<user><![CDATA[…]]></user>`,
/// `<user><br/>…</user>`); free text no longer parses markup, and its first tag cuts it. The
/// adversarial review found a quoted key with a line break in it read as two lines
/// (`"note\nQx31": 1`); a quote that does not close on its line now cuts the text at the quote.
@Suite("SensitiveDataRedactor seventeenth review probes")
struct RedactionSeventeenthReviewProbeTests {
    typealias Shapes = SeventeenthReviewShapes

    static func shows(_ output: String) -> Bool {
        output.contains(Shapes.secret) || output.contains(Shapes.digits) || output.contains(Shapes.tagSecret)
    }

    @Test("the correctness review's probes hide their secret on every path, unless shown by design")
    func correctnessProbes() {
        let shown = Shapes.shown
        #expect(Shapes.correctness.count == 178)
        for probe in Shapes.correctness + Shapes.markup {
            let outputs = RedactionCutRuleTests.everyPath(probe)
            if let reason = shown[probe] {
                #expect(Self.shows(outputs[0].output), "\(probe.debugDescription) is hidden, though shown by design: \(reason)")
                continue
            }
            for (path, output) in outputs {
                #expect(!Self.shows(output), "\(path): \(probe.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("the markup probes are cut at their first tag")
    func markupProbes() {
        let redactor = SensitiveDataRedactor()
        for probe in Shapes.markup {
            let output = redactor.redact(probe)
            #expect(output.hasSuffix(SensitiveDataRedactor.replacement), "\(probe.debugDescription) -> \(output.debugDescription)")
            let kept = output.dropLast(SensitiveDataRedactor.replacement.count)
            #expect(!kept.contains("<"), "\(probe.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("the adversarial review's quoted keys hide their marker, unless shown by design")
    func quotedKeys() {
        let redactor = SensitiveDataRedactor()
        #expect(Shapes.quotedKeys.count == 56)
        for (mode, input) in Shapes.quotedKeys {
            guard let range = input.range(of: "Qx[0-9]+", options: .regularExpression) else {
                Issue.record("no marker in \(input.debugDescription)")
                continue
            }
            let marker = String(input[range])
            let outputs: [(path: String, output: String)]
            switch mode {
            case "p": outputs = [("text/plain", redactor.redact(body: Data(input.utf8), contentType: "text/plain"))]
            case "j": outputs = [("JSON", redactor.redact(body: Data(input.utf8), contentType: "application/json"))]
            default: outputs = RedactionCutRuleTests.everyPath(input)
            }
            if let reason = Shapes.shownMarkers[marker] {
                #expect(outputs[0].output.contains(marker), "\(marker) is hidden, though shown by design: \(reason)")
                continue
            }
            for (path, output) in outputs {
                #expect(!output.contains(marker), "\(path): \(input.debugDescription) -> \(output.debugDescription)")
            }
        }
    }

    @Test("a quoted key with a line break in it is cut at its opening quote")
    func lineBreakInQuotedKey() {
        let redactor = SensitiveDataRedactor()
        #expect(redactor.redact("\"note\nQx31\": 1") == "[redacted]")
        #expect(redactor.redact("status=200 \"note\nQx40\": 1") == "status=200 [redacted]")
        #expect(redactor.redact("x \"a\nQx35 b\": 1") == "x [redacted]")
        #expect(redactor.redact("\"note\r\nQx36\": 1") == "[redacted]")
        #expect(redactor.redact("log \"user\nQx48\":") == "log [redacted]")
        // A line break inside the quotes is all it takes: no separator need follow.
        #expect(redactor.redact("\"note\nQx38\"") == "[redacted]")
    }
}
