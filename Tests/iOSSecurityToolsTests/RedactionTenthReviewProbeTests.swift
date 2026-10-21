import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor tenth review probes")
struct RedactionTenthReviewProbeTests {
    /// The probes whose secret still shows, each one a limitation that the documentation names
    /// ("What it does not find" in KeepingSecretsOutOfLogs, and the members that stay beside a
    /// name), by probe number.
    static let documentedLimitations: [Int: String] = {
        var limitations: [Int: String] = [:]
        let byReason: [(String, [Int])] = [
            ("a value written before its name", [55, 56]),
            ("a member that holds a name stays beside a secret name", [171, 172]),
            ("a name and its value in two JSON objects", [175]),
            ("a value glued to a flag", [284]),
            ("a name wholly in another script that only looks Latin, with no = or :", [318]),
        ]
        for (reason, ids) in byReason {
            for id in ids { limitations[id] = reason }
        }
        return limitations
    }()

    /// The probes written as names in circled or squared letters, as the value of a JSON member,
    /// on every path a JSON object takes, that showed their secret when they were written.
    static let symbolNames = [141] + Array(331...337) + Array(339...348)

    @Test("the set has 353 probes")
    func count() {
        #expect(TenthReviewProbeSet.all.count == 353)
    }

    @Test("no probe outside the documented limitations shows its secret")
    func probesHideTheirSecrets() {
        for probe in TenthReviewProbeSet.all where Self.documentedLimitations[probe.id] == nil {
            let output = probe.redacted()
            #expect(probe.leakedPiece(in: output) == nil, "#\(probe.id) \(probe.category): \(probe.input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("names written only in circled or squared letters hide the other members on every path")
    func symbolNamesHideTheirValues() {
        #expect(Self.symbolNames.count == 18)
        for id in Self.symbolNames {
            let probe = TenthReviewProbeSet.all[id - 1]
            #expect(probe.leakedPiece(in: probe.redacted()) == nil, "#\(id) \(probe.input.debugDescription)")
        }
    }

    // A limitation that no longer shows its secret has been fixed: the list and the
    // documentation are updated with it.
    @Test("every documented limitation is still one")
    func limitationsAreCurrent() {
        for probe in TenthReviewProbeSet.all where Self.documentedLimitations[probe.id] != nil {
            #expect(probe.leakedPiece(in: probe.redacted()) != nil, "#\(probe.id) is fixed: \(probe.input.debugDescription)")
        }
    }

    @Test("a JSON body that is still JSON after redaction stays JSON")
    func jsonBodiesStayJSON() {
        for probe in TenthReviewProbeSet.all {
            guard case .body(let type) = probe.mode, type == "application/json",
                  (try? JSONSerialization.jsonObject(with: Data(probe.input.utf8), options: .fragmentsAllowed)) != nil
            else { continue }
            let output = probe.redacted()
            guard !output.hasPrefix("[body omitted") else { continue }
            #expect((try? JSONSerialization.jsonObject(with: Data(output.utf8), options: .fragmentsAllowed)) != nil, "#\(probe.id) -> \(output)")
        }
    }
}
