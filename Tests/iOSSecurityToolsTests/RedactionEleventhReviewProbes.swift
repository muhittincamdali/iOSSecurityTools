import Foundation
@testable import iOSSecurityTools

/// The adversarial probe set of the eleventh review: 475 inputs, each hiding a unique secret
/// (`{S}`) behind one trick: secret names with two or more letters that have no ASCII form, names
/// held by fields, flat fields, free text, markup and property lists spread over lines, and
/// bodies. 76 of them got their secret past the redactor when they were written. The probes are
/// in the `RedactionEleventhReviewProbes+…` files; they are read with the readings of the tenth
/// review's set (see ``TenthReviewProbeSet``).
final class EleventhReviewProbeSet {
    typealias Mode = TenthReviewProbeSet.Mode
    typealias Probe = TenthReviewProbeSet.Probe

    private(set) var probes: [Probe] = []
    private var category = ""

    static let all: [Probe] = {
        let set = EleventhReviewProbeSet()
        set.addWild()
        set.addHeld()
        set.addFlat()
        set.addText()
        set.addMarkup()
        set.addBodies()
        return set.probes
    }()

    /// Starts a category. The claim a probe was written with is not kept: every probe either
    /// hides its secret or is one of the documented limitations.
    func section(_ name: String, _ claim: String = "C") {
        category = name
    }

    /// Adds a probe; `{S}` becomes a secret unique to it, unless `secret` names another one.
    func p(_ input: String, _ mode: Mode = .text, secret: String? = nil, digits: Bool = false, width: Int = 6, claim: String? = nil) {
        let id = probes.count + 1
        let marker = "Xv\(String(format: "%03d", id))Jm0t"
        probes.append(Probe(
            id: id, category: category, mode: mode, input: input.replacingOccurrences(of: "{S}", with: marker),
            secret: secret ?? marker, digitsOnly: digits, width: width
        ))
    }

    let json = Mode.body("application/json")
    let form = Mode.body("application/x-www-form-urlencoded")
    let plain = Mode.body("text/plain")

    func multipart(_ parts: [String], boundary: String = "B0und") -> String {
        parts.map { "--\(boundary)\r\n" + $0 + "\r\n" }.joined() + "--\(boundary)--"
    }

    func mpType(_ boundary: String = "B0und") -> Mode { .body("multipart/form-data; boundary=\(boundary)") }
}
