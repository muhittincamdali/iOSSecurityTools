import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor review probes")
struct RedactionReviewProbeTests {
    /// The probes whose secret still shows, each one a limitation that the documentation names
    /// ("What is not found" in KeepingSecretsOutOfLogs), by probe number.
    static let documentedLimitations: [Int: String] = {
        var limitations: [Int: String] = [:]
        let byReason: [(String, [Int])] = [
            ("a name wholly in another script that only looks Latin, with no = or :", [17, 18, 19, 20, 21, 22, 169, 236, 257]),
            ("a name in letters without an ASCII form throughout, with no = or :", [23, 24, 25, 26, 28, 29]),
            ("a name spelled with ASCII digits and symbols, with no = or :", [30, 31, 32]),
            ("an octal escape", [77]),
            ("the value of an allowed key", [134, 379, 381]),
            ("a name and its value in two JSON objects", [177]),
            ("a name that is not on the list", [181]),
            ("a value before its name or glued to a flag", [311, 329]),
            ("a card number grouped by . or _, glued to letters or written as a JSON float", [354, 355, 356, 411]),
        ]
        for (reason, ids) in byReason {
            for id in ids { limitations[id] = reason }
        }
        return limitations
    }()

    @Test("the set has 453 probes")
    func count() {
        #expect(ReviewProbeSet.all.count == 453)
    }

    @Test("no probe outside the documented limitations shows its secret")
    func probesHideTheirSecrets() {
        for probe in ReviewProbeSet.all where Self.documentedLimitations[probe.id] == nil {
            let output = probe.redacted()
            #expect(probe.leakedPiece(in: output) == nil, "#\(probe.id) \(probe.category): \(probe.input.debugDescription) -> \(output.debugDescription)")
        }
    }

    // A limitation that no longer shows its secret has been fixed: the list and the
    // documentation are updated with it.
    @Test("every documented limitation is still one")
    func limitationsAreCurrent() {
        for probe in ReviewProbeSet.all where Self.documentedLimitations[probe.id] != nil {
            #expect(probe.leakedPiece(in: probe.redacted()) != nil, "#\(probe.id) is fixed: \(probe.input.debugDescription)")
        }
    }
}
