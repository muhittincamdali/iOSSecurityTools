import Testing
@testable import iOSSecurityTools

/// Text made of `unit` repeated between a fixed prefix and suffix, so its length can be scaled.
struct RepeatedText: Sendable, CustomTestStringConvertible {
    var prefix = ""
    var unit: String
    var suffix = ""

    func text(length: Int) -> String {
        prefix + String(repeating: unit, count: max(1, length / unit.count)) + suffix
    }

    var testDescription: String { "\(prefix.debugDescription) + \(unit.debugDescription)… + \(suffix.debugDescription)" }
}

// Run serially so the measurements of one input do not compete with another's.
@Suite("SensitiveDataRedactor scaling", .serialized)
struct RedactionScalingTests {
    let redactor = SensitiveDataRedactor()

    /// Below this, timer and scheduling noise outweighs the work being measured.
    static let noiseFloor = Duration.milliseconds(30)

    /// Inputs where every few characters are a finding.
    static let manyFindings = [
        RepeatedText(unit: "pwd=x "),
        RepeatedText(unit: "a@b.co "),
        RepeatedText(unit: "4242424242424242 "),
    ]

    /// Inputs built to make a backtracking scanner rescan the same text, and findings that
    /// overlap and have to be joined.
    static let adversarial = [
        RepeatedText(unit: "token=abc_4111 1111 1111 1111 "),
        RepeatedText(unit: "eyJ"),
        RepeatedText(unit: "eyJa."),
        RepeatedText(unit: "@"),
        RepeatedText(unit: "a.", suffix: "@"),
        RepeatedText(prefix: "@", unit: "a."),
        RepeatedText(unit: "1 "),
        RepeatedText(unit: "password"),
        RepeatedText(prefix: "password=\"", unit: "\\"),
        RepeatedText(prefix: "password=\\\"", unit: "\\"),
        RepeatedText(unit: "p_a_s_s_w_o_r_d_"),
        RepeatedText(prefix: "a", unit: "_", suffix: "=x"),
        RepeatedText(unit: "bearer "),
        RepeatedText(unit: "\u{200B}"),
        RepeatedText(unit: "password["),
        RepeatedText(prefix: "password", unit: "[a]", suffix: "=x"),
        RepeatedText(unit: "[password]"),
        RepeatedText(unit: "[pass]"),
        RepeatedText(prefix: "password", unit: "[password]"),
        RepeatedText(unit: "<password>"),
        RepeatedText(prefix: "<password>", unit: "\n"),
        RepeatedText(unit: "password%3"),
    ]

    // 2.0.0 appended each piece of the output to a String.UnicodeScalarView, which copied the
    // output so far every time. That step is measured on its own here: in a debug build the scan
    // costs more than the copying until a text is hundreds of thousands of characters long.
    @Test("building the output takes time linear in the number of replacements")
    func replacementScale() {
        func replaceEveryFinding(length: Int) -> () -> Void {
            let scalars = Array(String(repeating: "pwd=x ", count: length / 6).unicodeScalars)
            let spans = stride(from: 4, to: scalars.count, by: 6).map {
                SensitiveDataRedactor.Span(start: $0, end: $0 + 1, kind: .secretFields, replacement: SensitiveDataRedactor.replacement)
            }
            return { _ = SensitiveDataRedactor.replacing(spans, in: scalars) }
        }
        // 16 times as many replacements: about 16 times the time if linear, 256 if quadratic.
        expectLinear(
            "one replacement every 6 scalars",
            small: replaceEveryFinding(length: 32_000),
            large: replaceEveryFinding(length: 512_000),
            maximumRatio: 40
        )
    }

    @Test("redaction time grows linearly with the number of findings", arguments: manyFindings)
    func manyFindingsScale(input: RepeatedText) {
        expectLinear(input)
    }

    @Test("redaction time grows linearly on adversarial inputs", arguments: adversarial)
    func adversarialScale(input: RepeatedText) {
        expectLinear(input)
    }

    /// Times `redact` on 20,000 characters of `input` and on four times as many: about 4 times
    /// the time if linear, about 16 times if quadratic.
    private func expectLinear(_ input: RepeatedText) {
        let small = input.text(length: 20_000)
        let large = input.text(length: 80_000)
        expectLinear(
            input.testDescription,
            small: { _ = redactor.redact(small) },
            large: { _ = redactor.redact(large) },
            maximumRatio: 10
        )
    }

    private func expectLinear(_ name: String, small: () -> Void, large: () -> Void, maximumRatio: Double) {
        var attempts: [String] = []
        // A second attempt keeps a burst of load from other processes from failing the test; work
        // that really grows faster than the input fails both.
        for _ in 0..<2 {
            let (smallTime, largeTime) = fastest(small, large)
            let ratio = largeTime / max(smallTime, .microseconds(1))
            if largeTime < Self.noiseFloor || ratio < maximumRatio { return }
            attempts.append("\(smallTime) and \(largeTime) (\(ratio)x)")
        }
        Issue.record("\(name): \(attempts.joined(separator: ", then ")), more than \(maximumRatio)x")
    }

    /// The shortest of three runs of each, alternating between them so that a slow period on the
    /// machine affects both.
    private func fastest(_ small: () -> Void, _ large: () -> Void) -> (small: Duration, large: Duration) {
        let clock = ContinuousClock()
        var result = (small: Duration.seconds(Int.max), large: Duration.seconds(Int.max))
        for _ in 0..<3 {
            result.small = min(result.small, clock.measure(small))
            result.large = min(result.large, clock.measure(large))
        }
        return result
    }
}
