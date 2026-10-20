import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the thirteenth review, both lenses, run against the safe alphabet of free text
/// and the key rule in every shape. Every probe is checked by its claim: one the documentation
/// says is hidden (`C`) and one written to explore (`X`) hides its secret unless it is a
/// limitation that "What it does not find" names; a control (`K`) shows its text; and one the
/// documentation says is not found (`D`) still shows, unless it is listed as found now.
@Suite("SensitiveDataRedactor thirteenth review probes")
struct RedactionThirteenthReviewProbeTests {
    static let reviews = ["a-13", "c-13"]

    /// The probes that show their secret as a limitation that "What it does not find" names, or
    /// by design, by review and number.
    static let shown: [String: String] = {
        var shown: [String: String] = [:]
        let byReason: [(String, [String])] = [
            ("a name disguised with two or more letters that have no ASCII form, without a separator", ["a-13#120", "a-13#121", "a-13#122"]),
            ("a name written with a space between its letters, without a separator", ["a-13#201"]),
            ("a name and its value in two different JSON arrays", ["a-13#251"]),
            ("a value with no label, as Go prints a struct", ["a-13#432"]),
            ("a card number grouped with + or .", ["a-13#513", "a-13#514"]),
            ("a value after a flag or a name not on the list, without a separator", ["c-13#118", "c-13#198", "c-13#199", "c-13#202"]),
            ("the value of status, which is allowed, also repeated", ["c-13#135", "c-13#138"]),
        ]
        for (reason, names) in byReason {
            for name in names { shown[name] = reason }
        }
        return shown
    }()

    /// The `D` probes that free text finds now: an octal escape cuts it.
    static let foundNow: Set<String> = ["a-13#183"]

    @Test("the resource holds every probe of the thirteenth review")
    func counts() {
        let counts = Dictionary(grouping: ReviewProbes.all.filter { Self.reviews.contains($0.review) }, by: \.review).mapValues(\.count)
        #expect(counts == ["a-13": 579, "c-13": 245])
        #expect(Self.shown.count == 14)
    }

    @Test("a probe hides its secret unless it is a control or a documented limitation", arguments: reviews)
    func probesKeepTheirClaims(review: String) {
        for probe in ReviewProbes.of(review) {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim) \(probe.category): \(probe.text.prefix(200).debugDescription) -> \(output.prefix(200).debugDescription)"
            if probe.claim == "K" || Self.shown[probe.name] != nil {
                #expect(piece != nil, "\(description) is hidden")
            } else {
                #expect(probe.claim != "D" || Self.foundNow.contains(probe.name), "\(description) is not documented")
                #expect(piece == nil, "\(description)")
            }
        }
    }

    // The review's usefulness list: text without a trigger, and the keys the app allows, are kept
    // exactly as they are.
    @Test("the review's usefulness inputs are kept as they are")
    func usefulInputsAreKept() {
        for probe in ReviewProbes.of("c-13") where probe.claim == "K" {
            #expect(probe.redacted() == probe.text, "\(probe.text.debugDescription)")
        }
    }
}
