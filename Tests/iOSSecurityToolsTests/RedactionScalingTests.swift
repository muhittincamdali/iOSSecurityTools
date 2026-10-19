import Foundation
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
        RepeatedText(unit: "%5Bpassword%5D"),
        RepeatedText(unit: "<password>"),
        RepeatedText(prefix: "<password>", unit: "\n"),
        RepeatedText(unit: "<password a=\"b\" "),
        RepeatedText(unit: "<ns:password "),
        RepeatedText(prefix: "<password ", unit: "a=\"b>"),
        RepeatedText(unit: "password%3"),
        RepeatedText(prefix: "password", unit: " ="),
        RepeatedText(prefix: "password", unit: "%20%3D"),
        RepeatedText(unit: "password===+"),
        RepeatedText(unit: "password:<a"),
        RepeatedText(prefix: "password:<", unit: "a"),
        RepeatedText(prefix: "password=<", unit: "password=<a "),
        // The scaling inputs of the 2.0.1 bypass probes.
        RepeatedText(unit: "<password a=\""),
        RepeatedText(unit: "<a:password b "),
        RepeatedText(unit: "password: <"),
        RepeatedText(unit: "password: <x"),
        RepeatedText(unit: "password=<"),
        RepeatedText(unit: "password%20%20"),
        RepeatedText(unit: "password ==="),
        RepeatedText(unit: "password %3D"),
        RepeatedText(unit: "password+"),
        RepeatedText(unit: "\\\"password\\\":\\\""),
        RepeatedText(unit: "pass."),
        RepeatedText(unit: "4111 1111 1111 1111 "),
        RepeatedText(unit: "a@b."),
        RepeatedText(unit: "password: \""),
        RepeatedText(unit: "password\""),
        RepeatedText(unit: "password \u{2254} "),
        // Names read back over whitespace, quotes, escapes and look-alike separators.
        RepeatedText(unit: "a ", suffix: "word=x"),
        RepeatedText(prefix: "a", unit: " ", suffix: "\u{A789}x"),
        RepeatedText(unit: "pass \u{0430}"),
        RepeatedText(unit: "\"a\":"),
        RepeatedText(unit: "\"a"),
        RepeatedText(unit: "\\\""),
        RepeatedText(unit: "&#97;", suffix: "=x"),
        RepeatedText(unit: "&#97"),
        RepeatedText(unit: "password\u{A789}"),
        RepeatedText(unit: "a\u{00B7}"),
        RepeatedText(unit: "%25"),
        RepeatedText(unit: "::"),
        RepeatedText(unit: "=a "),
        RepeatedText(unit: "<a:"),
        // Long names, read once; words that could spell a secret name, separators that only
        // might be one, values that run on and lines below a value.
        RepeatedText(unit: "passx", suffix: "=1"),
        RepeatedText(prefix: "{\"", unit: "tokenx", suffix: "\":1}"),
        RepeatedText(prefix: "secret", unit: "x", suffix: ": 1"),
        RepeatedText(unit: "k\u{0131}"),
        RepeatedText(unit: "Ka\u{0131}l "),
        RepeatedText(unit: "p\u{0430}ss\u{A789}"),
        RepeatedText(unit: "password  "),
        RepeatedText(unit: "%5B"),
        RepeatedText(unit: "password=a,"),
        RepeatedText(unit: "a,"),
        RepeatedText(unit: "(a"),
        RepeatedText(unit: "pa(ss)word="),
        RepeatedText(unit: "token\u{2192}"),
        RepeatedText(unit: "\"a\": "),
        RepeatedText(unit: "x=y "),
        RepeatedText(prefix: "password=", unit: "a "),
        RepeatedText(prefix: "password: |\n", unit: "  a\n"),
        RepeatedText(prefix: "password=\"", unit: "a\n"),
        RepeatedText(unit: "<key>password</key>"),
        RepeatedText(unit: "- key: password\n"),
        RepeatedText(unit: "</"),
        RepeatedText(unit: "DE89 "),
        RepeatedText(unit: "https://a:"),
        // JSON: nesting beyond the limit, many members and strings with escapes.
        RepeatedText(unit: "["),
        RepeatedText(prefix: "[", unit: "{\"password\":1},", suffix: "{}]"),
        RepeatedText(prefix: "[\"", unit: "\\\"", suffix: "\"]"),
        RepeatedText(prefix: "{\"a\":\"", unit: "password=\\\"", suffix: "\"}"),
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

    @Test("redacting a body takes time linear in its size", arguments: [
        ("a=1&password=x&", "application/x-www-form-urlencoded"),
        ("{\"password\":\"x\"},", "application/json"),
        ("--B\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nx\r\n", "multipart/form-data; boundary=B"),
    ])
    func bodyScale(unit: String, contentType: String) {
        func body(length: Int) -> Data {
            let repeated = String(repeating: unit, count: length / unit.count)
            switch contentType {
            case "application/json": return Data(("[" + repeated + "{}]").utf8)
            case "application/x-www-form-urlencoded": return Data((repeated + "z=1").utf8)
            default: return Data((repeated + "--B--").utf8)
            }
        }
        // A multipart body may have at most 1,000 parts; keep both sizes under that.
        let scale = contentType.hasPrefix("multipart") ? 12 : 1
        let small = body(length: 20_000 / scale)
        let large = body(length: 80_000 / scale)
        expectLinear(
            "\(contentType) body of \(unit.debugDescription)",
            small: { _ = redactor.redact(body: small, contentType: contentType) },
            large: { _ = redactor.redact(body: large, contentType: contentType) },
            maximumRatio: 10
        )
    }

    // A JSON or form name was compared in time quadratic in its length: 80,000 characters took
    // 3 seconds, a megabyte about 8 minutes.
    @Test("comparing a long JSON or form name takes time linear in its length")
    func longNameScale() {
        func json(_ length: Int) -> Data { Data(("{\"" + String(repeating: "tokenx", count: length / 6) + "\":1}").utf8) }
        func form(_ length: Int) -> Data { Data((String(repeating: "secretx", count: length / 7) + "=1").utf8) }
        let (smallJSON, largeJSON, smallForm, largeForm) = (json(20_000), json(80_000), form(20_000), form(80_000))
        expectLinear(
            "JSON body with a long name",
            small: { _ = redactor.redact(body: smallJSON, contentType: "application/json") },
            large: { _ = redactor.redact(body: largeJSON, contentType: "application/json") },
            maximumRatio: 10
        )
        expectLinear(
            "form body with a long name",
            small: { _ = redactor.redact(body: smallForm, contentType: "application/x-www-form-urlencoded") },
            large: { _ = redactor.redact(body: largeForm, contentType: "application/x-www-form-urlencoded") },
            maximumRatio: 10
        )
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
