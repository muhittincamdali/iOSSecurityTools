import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of every adversarial review of the redesign — the third, fifth, seventh, ninth,
/// tenth and twelfth, and the correctness repros of the twelfth review's second lens — run
/// against the free-text rule of one cut. Each probe the documentation says is hidden is hidden,
/// apart from the limitations that "What it does not find" names.
@Suite("SensitiveDataRedactor review probe sets")
struct RedactionReviewProbeSetTests {
    static let reviews = ["a-3", "a-5", "a-7", "a-9", "a-10", "a-12", "c-12"]

    /// The probes that show their secret, by review and number, with the limitation each one is.
    static let documentedLimitations: [String: String] = {
        var limitations: [String: String] = [:]
        let twoLookAlikeLetters = Array(1...14) + Array(23...25) + Array(27...29) + Array(37...43) + [336]
        let byReason: [(String, [String])] = [
            ("a value written before its name", ["a-3#311"]),
            ("the value of an allowed query parameter, also repeated or in another case", ["a-3#379", "a-3#381"]),
            ("a card number glued to an ASCII letter", ["a-5#367"]),
            ("the value of `status`, which is allowed by default", ["a-7#496"]),
            ("a name with two or more letters that have no ASCII form, without a separator", twoLookAlikeLetters.map { "a-10#\($0)" }),
        ]
        for (reason, names) in byReason {
            for name in names { limitations[name] = reason }
        }
        return limitations
    }()

    @Test("the resource holds every probe of the reviews")
    func counts() {
        let counts = Dictionary(grouping: ReviewProbes.all, by: \.review).mapValues(\.count)
        #expect(counts == ["a-3": 453, "a-5": 452, "a-7": 560, "a-9": 353, "a-10": 475, "a-12": 613, "c-12": 66])
        #expect(Self.documentedLimitations.count == 33)
        #expect(Self.large.count == 42)
    }

    /// The probes of up to a few megabytes, each a test case of its own so that they run side by side.
    static let large = ReviewProbes.all.filter { $0.isLarge && $0.claim == "C" }.map(\.name)

    @Test("no probe the documentation says is hidden shows its secret", arguments: reviews)
    func probesHideTheirSecrets(review: String) {
        for probe in ReviewProbes.of(review) where !probe.isLarge {
            expectHidden(probe)
        }
    }

    @Test("no large probe the documentation says is hidden shows its secret", arguments: large)
    func largeProbesHideTheirSecrets(name: String) throws {
        expectHidden(try #require(ReviewProbes.all.first { $0.name == name }))
    }

    private func expectHidden(_ probe: ReviewProbe) {
        guard probe.claim == "C", Self.documentedLimitations[probe.name] == nil else { return }
        let output = probe.redacted()
        #expect(probe.leakedPiece(in: output) == nil, "\(probe.name) \(probe.category): \(probe.text.prefix(300).debugDescription) -> \(output.prefix(300).debugDescription)")
    }

    // A limitation that no longer shows its secret has been fixed: the list and the
    // documentation are updated with it.
    @Test("every documented limitation is still one")
    func limitationsAreCurrent() {
        let probes = Dictionary(uniqueKeysWithValues: ReviewProbes.all.map { ($0.name, $0) })
        for name in Self.documentedLimitations.keys.sorted() {
            guard let probe = probes[name] else {
                Issue.record("no probe \(name)")
                continue
            }
            #expect(probe.leakedPiece(in: probe.redacted()) != nil, "\(name) is fixed: \(probe.text.debugDescription)")
        }
    }
}
