import Foundation
import Testing
@testable import iOSSecurityTools

/// The twenty-fifth review (`a-25`) found one class of values shown that the documentation says
/// are hidden: a decimal digit of another script in a name written without a separator. Such a
/// digit has no ASCII form, so the one wildcard rule names it, but the scanning copy reads every
/// decimal digit as its ASCII digit, for numbers and the value detectors, and a word read it so
/// too: `t၀ken` (Myanmar zero) was `t0ken`, not `token` with one letter replaced, and `login
/// t၀ken X`, `{"title":"t၀ken","value":X}`, `["a","c๐okie",X]` and an allowed query
/// `?q=t%E1%81%80ken+X` showed `X` (150 probes, and 850 and 897). A word now reads such a digit
/// as the wildcard (see ``ScalarClass/isDigitWithoutASCIIForm(_:)``), while a digit with an
/// ASCII form (`０`, `𝟎`, `⁰`) is still that digit, as the documentation says.
@Suite("SensitiveDataRedactor twenty-fifth review probes")
struct RedactionTwentyFifthReviewProbeTests {
    /// The probes that showed their secret in the review.
    static let leaked = Array(1...152) + [850, 897]

    @Test("the probes are numbered as the review numbered them")
    func counts() {
        let probes = TwentyFifthReviewProbes.wildcards + TwentyFifthReviewProbes.followUps
        #expect(probes.map(\.id) == Array(1...273) + [850, 897])
        #expect(probes.first?.text == "login t\u{1040}ken Qz001Wk5m")
        #expect(probes.first { $0.id == 117 }?.text == #"{"msg":"login t၀ken Qz117Wk5m"}"#)
        #expect(probes.first { $0.id == 152 }?.text == "status=200 [c\u{0E50}okie] Qz152Wk5m")
        #expect(probes.first { $0.id == 261 }?.text == "login passw0rd Qz261Wk5m")
        #expect(probes.first { $0.id == 850 }?.text == "https://x.example/a?q=t%E1%81%80ken+Qz850Wk5m")
        #expect(probes.filter { $0.claim == "C" }.count == 262)
        #expect(Self.leaked.allSatisfy { id in probes.contains { $0.id == id && $0.claim == "C" } })
    }

    @Test("a digit of another script in a name is the wildcard on every path")
    func probes() {
        for probe in TwentyFifthReviewProbes.wildcards + TwentyFifthReviewProbes.followUps {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim): \(probe.text.prefix(120).debugDescription) -> \(output.suffix(120).debugDescription)"
            switch probe.claim {
            // Documented as not found: a digit with an ASCII form is that digit (`passw0rd`), and
            // two letters replaced are deliberate disguise (`pɑsswoʀd`).
            case "D", "K": #expect(piece != nil, "\(description) is shown")
            default: #expect(piece == nil, "\(description)")
            }
        }
    }

    @Test("every decimal digit reads as the wildcard exactly when it has no ASCII form")
    func everyDigit() {
        var differ: [String] = []
        for value in UInt32(0x80)...0x10FFFF {
            guard let scalar = Unicode.Scalar(value), ScalarClass.decimalDigit(scalar) != nil else { continue }
            let hasASCIIForm = String(scalar).decomposedStringWithCompatibilityMapping.unicodeScalars.allSatisfy(\.isASCII)
            if ScalarClass.isDigitWithoutASCIIForm(scalar) == hasASCIIForm { differ.append(String(format: "U+%04X", value)) }
        }
        #expect(differ.isEmpty, "\(differ)")
        #expect(!ScalarClass.isDigitWithoutASCIIForm("0") && !ScalarClass.isDigitWithoutASCIIForm("a"))
    }

    @Test("every native digit in place of or put into every secret name hides the value, and numbers keep theirs")
    func everyNativeDigit() {
        let redactor = SensitiveDataRedactor()
        var shown: [String] = []
        for zero in TwentyFifthReviewProbes.nativeZeros {
            for name in ["token", "password", "pin", "otp", "secret", "cookie"] {
                let scalars = name.unicodeScalars.map(String.init)
                for index in scalars.indices {
                    var replaced = scalars
                    replaced[index] = zero
                    var put = scalars
                    put.insert(zero, at: index)
                    for word in [replaced.joined(), put.joined()] {
                        for text in ["login \(word) Qz9Wk5m", "x \"\(word)\" Qz9Wk5m"] where redactor.redact(text).contains("Qz9Wk5m") {
                            shown.append(text)
                        }
                    }
                }
            }
            // A digit of another script is still a digit for numbers and the value detectors.
            let digits = String(repeating: zero, count: 3)
            #expect(redactor.redact("status=200 count \(digits) took 12:30") == "status=200 count \(digits) took 12:30")
        }
        #expect(shown.isEmpty, "\(shown.prefix(10))")
        #expect(redactor.redact("paid ४२४२ ४२४२ ४२४२ ४२४२ ok") == "paid •••• 4242 ok")
    }
}
