import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("SensitiveDataRedactor eleventh review probes")
struct RedactionEleventhReviewProbeTests {
    /// The probes whose secret still shows, each one a limitation that the documentation names
    /// ("What it does not find" in KeepingSecretsOutOfLogs, the threat model, and the members
    /// that stay beside a name), by probe number.
    static let documentedLimitations: [Int: String] = {
        var limitations: [Int: String] = [:]
        let byReason: [(String, [Int])] = [
            ("a name without a separator in two or more letters that have no ASCII form, on any path that reads free text",
             Array(1...14) + Array(23...25) + Array(27...33) + [35] + Array(37...43) + [336]),
            ("a name and its value in two JSON objects or arrays", [79, 93]),
            ("a name in another script as an element of an array of more than two", [92]),
            ("a label it does not know: a word in another language or a name not on the list", [121, 123, 169]),
            ("a member that holds a name stays beside a secret name", [122]),
            ("a control: the name written as a value shows, only what follows it is hidden", [147]),
            ("a name wholly in another script that only looks Latin, with no = or :", [202]),
            ("a value written before its name", [306, 308]),
            ("a value glued to a flag", [307]),
        ]
        for (reason, ids) in byReason {
            for id in ids { limitations[id] = reason }
        }
        return limitations
    }()

    /// The probes that showed their secret when they were written and are hidden now: values laid
    /// out over lines after a property list's key, an element that holds nothing or JSON after
    /// `name=`, multipart parts that hold a name that cannot be read as text, the value of an
    /// allowed key on the line after a name written without quotes (`name=password`, `label: Şifre`),
    /// and two names whose skeleton spells them (`ᴘwᴅ` as `pw` without its `p`, `passꞏwoꞏrd`).
    static let fixed = [184, 185, 186, 189, 328, 329, 354, 360] + Array(367...374) + Array(376...383) + [319, 337, 34, 36]

    @Test("the set has 475 probes")
    func count() {
        #expect(EleventhReviewProbeSet.all.count == 475)
        #expect(Self.documentedLimitations.count == 45)
    }

    @Test("no probe outside the documented limitations shows its secret")
    func probesHideTheirSecrets() {
        for probe in EleventhReviewProbeSet.all where Self.documentedLimitations[probe.id] == nil {
            let output = probe.redacted()
            #expect(probe.leakedPiece(in: output) == nil, "#\(probe.id) \(probe.category): \(probe.input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("the probes that showed their secret when they were written hide it")
    func fixedProbes() {
        #expect(Self.fixed.count == 28)
        for id in Self.fixed {
            let probe = EleventhReviewProbeSet.all[id - 1]
            #expect(probe.leakedPiece(in: probe.redacted()) == nil, "#\(id) \(probe.input.debugDescription)")
        }
    }

    // A limitation that no longer shows its secret has been fixed: the list and the
    // documentation are updated with it.
    @Test("every documented limitation is still one")
    func limitationsAreCurrent() {
        for probe in EleventhReviewProbeSet.all where Self.documentedLimitations[probe.id] != nil {
            #expect(probe.leakedPiece(in: probe.redacted()) != nil, "#\(probe.id) is fixed: \(probe.input.debugDescription)")
        }
    }

    @Test("a JSON body that is still JSON after redaction stays JSON")
    func jsonBodiesStayJSON() {
        for probe in EleventhReviewProbeSet.all {
            guard case .body(let type) = probe.mode, type == "application/json",
                  (try? JSONSerialization.jsonObject(with: Data(probe.input.utf8), options: .fragmentsAllowed)) != nil
            else { continue }
            let output = probe.redacted()
            guard !output.hasPrefix("[body omitted") else { continue }
            #expect((try? JSONSerialization.jsonObject(with: Data(output.utf8), options: .fragmentsAllowed)) != nil, "#\(probe.id) -> \(output)")
        }
    }
}
