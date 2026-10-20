import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the fifteenth review: its adversarial set (`a-15`), the inputs it ran by hand
/// (`a-15q`) and the correctness review's inputs (`c-15`). Most of them are URLs in free text
/// that the reading of their query, fragment and path parameters let a value past: an empty or
/// allowed section after a last segment that names a secret (`/password# hunter2`), an end in an
/// encoded `=` or `:` (`/user%3A hunter2`) and a character outside the safe alphabet inside the
/// URL (`/a→b/…?q=1`). A URL in free text is now shown only when it is clean, so every one of
/// them cuts the text where the URL starts. Every probe is checked by its claim, as the
/// fourteenth review's are.
@Suite("SensitiveDataRedactor fifteenth review probes")
struct RedactionFifteenthReviewProbeTests {
    static let reviews = ["a-15", "a-15q", "c-15"]

    /// The probes that show their secret by design or as a limitation that "What it does not
    /// find" names, by review and number.
    static let shown: [String: String] = {
        var shown: [String: String] = [:]
        let byReason: [(String, [String])] = [
            ("a `:` between digits after a number is part of the number", ["a-15#142", "a-15#147"]),
        ]
        for (reason, names) in byReason {
            for name in names { shown[name] = reason }
        }
        return shown
    }()

    @Test("the resource holds every probe of the fifteenth review")
    func counts() {
        let counts = Dictionary(grouping: ReviewProbes.all.filter { Self.reviews.contains($0.review) }, by: \.review).mapValues(\.count)
        #expect(counts == ["a-15": 300, "a-15q": 15, "c-15": 315])
    }

    // The large probes that the documentation says are hidden run in the probe set suite, each a
    // test case of its own.
    @Test("a probe hides its secret unless it is a control or a documented limitation", arguments: reviews)
    func probesKeepTheirClaims(review: String) {
        for probe in ReviewProbes.of(review) where !(probe.isLarge && probe.claim == "C") {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim) \(probe.category): \(probe.text.prefix(200).debugDescription) -> \(output.prefix(200).debugDescription)"
            if probe.claim == "K" || Self.shown[probe.name] != nil {
                #expect(piece != nil, "\(description) is hidden")
            } else if probe.claim == "D" {
                #expect(piece != nil, "\(description) is found, so the documentation can drop it")
            } else {
                #expect(piece == nil, "\(description)")
            }
        }
    }
}
