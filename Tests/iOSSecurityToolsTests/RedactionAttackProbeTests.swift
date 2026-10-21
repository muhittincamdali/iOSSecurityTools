import Foundation
import Testing
@testable import iOSSecurityTools

/// One input written to get a secret past the redactor.
struct AttackProbe: Sendable {
    let id: Int
    let category: String
    let input: String
    /// Nil for free text; a body otherwise, with this content type (`.some(nil)`: none).
    let contentType: String??
    let secrets: [String]
    /// Whether the secret may still show: one of the limitations the documentation names.
    let isDocumentedLimitation: Bool

    func redacted(by redactor: SensitiveDataRedactor) -> String {
        guard let contentType else { return redactor.redact(input) }
        return redactor.redact(body: Data(input.utf8), contentType: contentType)
    }

    /// The parts of a secret that show in the output: the secret or six characters of it, also
    /// after removing invisible characters, percent escapes and backslashes; for a card number,
    /// more than its last four digits.
    static func leakedPieces(of secret: String, in output: String) -> [String] {
        let digits = secret.filter(\.isNumber)
        if !digits.isEmpty, secret.allSatisfy({ $0.isNumber || $0 == " " || $0 == "-" }) {
            let shown = String(Self.visible(output).unicodeScalars.filter { ("0"..."9").contains($0) }.map(Character.init))
            let hiddenPart = String(digits.dropLast(4).suffix(6))
            return shown.contains(hiddenPart) ? [hiddenPart] : []
        }
        let views = [output, visible(output), output.removingPercentEncoding ?? output, output.replacingOccurrences(of: "\\", with: "")]
        if views.contains(where: { $0.contains(secret) }) { return [secret] }
        let characters = Array(secret)
        guard characters.count >= 6 else { return [] }
        return (0...(characters.count - 6)).map { String(characters[$0..<($0 + 6)]) }.filter { piece in views.contains { $0.contains(piece) } }
    }

    /// The text after compatibility normalization without format characters and marks.
    private static func visible(_ text: String) -> String {
        var view = String.UnicodeScalarView()
        for scalar in text.precomposedStringWithCompatibilityMapping.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .format, .nonspacingMark, .enclosingMark: continue
            default: view.append(scalar)
            }
        }
        return String(view)
    }
}

/// Collects probes; `{S}` and `{S2}` in a template become secrets unique to the probe.
final class AttackProbeBuilder {
    private(set) var probes: [AttackProbe] = []

    func text(_ category: String, _ template: String) { add(category, template, nil, limitation: false) }

    func body(_ category: String, _ template: String, _ contentType: String?) { add(category, template, .some(contentType), limitation: false) }

    func limitation(_ category: String, _ template: String) { add(category, template, nil, limitation: true) }

    /// A probe with its own secrets: card numbers, addresses, tokens.
    func raw(_ category: String, _ input: String, _ contentType: String??, secrets: [String]) {
        append(category, input, contentType, secrets, limitation: false)
    }

    func limitationRaw(_ category: String, _ input: String, _ contentType: String??, secrets: [String]) {
        append(category, input, contentType, secrets, limitation: true)
    }

    private func add(_ category: String, _ template: String, _ contentType: String??, limitation: Bool) {
        let id = probes.count + 1
        let first = "Hx7Qz" + String(format: "%03d", id) + "Vb9"
        let second = "Wk3Mn" + String(format: "%03d", id) + "Pp"
        let input = template.replacingOccurrences(of: "{S2}", with: second).replacingOccurrences(of: "{S}", with: first)
        append(category, input, contentType, template.contains("{S2}") ? [first, second] : [first], limitation: limitation)
    }

    private func append(_ category: String, _ input: String, _ contentType: String??, _ secrets: [String], limitation: Bool) {
        probes.append(AttackProbe(
            id: probes.count + 1, category: category, input: input, contentType: contentType, secrets: secrets, isDocumentedLimitation: limitation
        ))
    }
}

enum AttackProbes {
    static let all: [AttackProbe] = {
        let builder = AttackProbeBuilder()
        addNamesSeparatorsAndValues(to: builder)
        addStructureLogsAndDetectors(to: builder)
        return builder.probes
    }()
}

@Suite("SensitiveDataRedactor adversarial probes")
struct RedactionAttackProbeTests {
    @Test("the set has 386 probes, one of them a documented limitation")
    func counts() {
        #expect(AttackProbes.all.count == 386)
        #expect(AttackProbes.all.filter(\.isDocumentedLimitation).map(\.input) == ["cc4111111111111111"])
    }

    @Test("no probe outside the documented limitations shows its secret")
    func probesHideTheirSecrets() {
        let redactor = SensitiveDataRedactor()
        for probe in AttackProbes.all where !probe.isDocumentedLimitation {
            let output = probe.redacted(by: redactor)
            let pieces = probe.secrets.flatMap { AttackProbe.leakedPieces(of: $0, in: output) }
            #expect(pieces.isEmpty, "#\(probe.id) \(probe.category): \(probe.input.debugDescription) -> \(output.debugDescription)")
        }
    }

    @Test("a JSON body that is still JSON after redaction stays JSON")
    func jsonBodiesStayJSON() throws {
        let redactor = SensitiveDataRedactor()
        for probe in AttackProbes.all where probe.contentType == .some("application/json") {
            guard (try? JSONSerialization.jsonObject(with: Data(probe.input.utf8), options: .fragmentsAllowed)) != nil else { continue }
            let output = probe.redacted(by: redactor)
            guard !output.hasPrefix("[body omitted") else { continue }
            #expect((try? JSONSerialization.jsonObject(with: Data(output.utf8), options: .fragmentsAllowed)) != nil, "#\(probe.id) -> \(output)")
        }
    }
}
