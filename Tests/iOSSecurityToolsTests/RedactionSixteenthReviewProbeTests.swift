import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the sixteenth review: its adversarial set (`a-16`) and the correctness review's
/// inputs (`c-16`). The adversarial set found the name matching missing a letter without an ASCII
/// form right before the last letter of a short secret name (`piꞏn`, `tokeın`) or before its
/// plural `s` (`tokenꞏs`), on every path that reads a word; names are now compared by their ASCII
/// skeleton. The correctness review found the words of a quoted key in free text never read
/// (`cache miss for "session Qz9Wk7rX": …`); a quoted key that is not allowed now cuts the text
/// at its opening quote. Every probe is checked by its claim, as the fifteenth review's are.
@Suite("SensitiveDataRedactor sixteenth review probes")
struct RedactionSixteenthReviewProbeTests {
    static let reviews = ["a-16", "c-16"]

    /// The probes that show their secret by design or as a limitation that "What it does not
    /// find" names, by review and number.
    static let shown: [String: String] = {
        var shown: [String: String] = [:]
        let byReason: [(String, [String])] = [
            ("a key that folds to an allowed key (`STATUS` is `status`)", ["a-16#217"]),
            ("text after a clean URL that no trigger comes before", ["a-16#283"]),
            ("the host of a URL passed to redact(url:), in which the detectors find nothing", ["a-16#300"]),
            ("the value of a key that names no secret, in structured input", ["a-16#309", "a-16#337", "a-16#362", "a-16#371"]),
        ]
        for (reason, names) in byReason {
            for name in names { shown[name] = reason }
        }
        return shown
    }()

    /// The limitations the review named that the ASCII skeleton finds: letters without an ASCII
    /// form put in between the letters of a name, however many (`tꞏkeꞏn`).
    static let fixed: Set<String> = ["a-16#58"]

    @Test("the resource holds every probe of the sixteenth review")
    func counts() {
        let counts = Dictionary(grouping: ReviewProbes.all.filter { Self.reviews.contains($0.review) }, by: \.review).mapValues(\.count)
        #expect(counts == ["a-16": 381, "c-16": 98])
    }

    @Test("a probe hides its secret unless it is a control or a documented limitation", arguments: reviews)
    func probesKeepTheirClaims(review: String) {
        for probe in ReviewProbes.of(review) where !(probe.isLarge && probe.claim == "C") {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim) \(probe.category): \(probe.text.prefix(200).debugDescription) -> \(output.prefix(200).debugDescription)"
            if probe.claim == "K" || Self.shown[probe.name] != nil {
                #expect(piece != nil, "\(description) is hidden")
            } else if probe.claim == "D", !Self.fixed.contains(probe.name) {
                #expect(piece != nil, "\(description) is found, so the documentation can drop it")
            } else {
                #expect(piece == nil, "\(description)")
            }
        }
    }
}
