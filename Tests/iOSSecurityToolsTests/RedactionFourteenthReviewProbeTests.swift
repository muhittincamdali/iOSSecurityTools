import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the fourteenth review: its first set (`a-14`), its second (`a-14b`) and the
/// inputs it ran by hand (`a-14q`), most of them a URL in free text whose end names a value that
/// the text after it holds (`?token= hunter2`), and keys that end in digits before a `:`
/// (`user1:2345`). Every probe is checked by its claim, as the thirteenth review's are: one the
/// documentation says is hidden (`C`) and one written to explore (`X`) hides its secret unless it
/// is a limitation that "What it does not find" names, and a control (`K`) shows it.
@Suite("SensitiveDataRedactor fourteenth review probes")
struct RedactionFourteenthReviewProbeTests {
    static let reviews = ["a-14", "a-14b", "a-14q"]

    /// The probes that show their secret as a limitation that "What it does not find" names, or by
    /// design, by review and number.
    static let shown: [String: String] = {
        var shown: [String: String] = [:]
        let byReason: [(String, [String])] = [
            ("the value of an allowed query parameter, its name escaped", ["a-14#440"]),
            ("a label that the list does not know (pw, pass, sid)", ["a-14#593", "a-14#594", "a-14#595", "a-14#596"]),
            ("a token split by / or - into pieces shorter than 32 characters", ["a-14#672", "a-14#673", "a-14#674", "a-14#675"]),
            ("an IBAN written in lowercase", ["a-14#683", "a-14#684"]),
            ("a value written before its name", ["a-14b#384"]),
        ]
        for (reason, names) in byReason {
            for name in names { shown[name] = reason }
        }
        return shown
    }()

    @Test("the resource holds every probe of the fourteenth review")
    func counts() {
        let counts = Dictionary(grouping: ReviewProbes.all.filter { Self.reviews.contains($0.review) }, by: \.review).mapValues(\.count)
        #expect(counts == ["a-14": 758, "a-14b": 402, "a-14q": 60])
        #expect(Self.shown.count == 12)
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
            } else {
                #expect(probe.claim != "D", "\(description) is not documented")
                #expect(piece == nil, "\(description)")
            }
        }
    }

    /// Exploratory probes of earlier reviews that the rules of this one close: a key that ends in
    /// digits before a `:`, and a URL whose last segment, query name or host names a secret.
    static let closedExploratory = ["a-7#517", "a-7#522", "a-7#523", "a-14#756", "a-14#757", "a-14#758"] + (71...76).map { "a-14b#\($0)" }

    @Test("the exploratory probes that the fourteenth review's rules close stay hidden", arguments: closedExploratory)
    func exploratoryProbesStayHidden(name: String) throws {
        let probe = try #require(ReviewProbes.all.first { $0.name == name })
        #expect(probe.claim == "X")
        let output = probe.redacted()
        #expect(probe.leakedPiece(in: output) == nil, "\(probe.text.debugDescription) -> \(output.debugDescription)")
    }
}
