import Foundation
@testable import iOSSecurityTools

/// The adversarial probe set of the review of the redesign: 453 inputs, each hiding a unique
/// secret behind one trick, in free text, bodies and URLs. 94 of them got their secret past the
/// redactor when they were written. The probes are in the `RedactionReviewProbes+…` files.
final class ReviewProbeSet {
    enum Mode {
        case text
        case body(String?)
        case rawBody([UInt8], String?)
        case url
        case urlAllowing([String])
        case textAllowing([String])
    }

    struct Probe {
        let id: Int
        let category: String
        let mode: Mode
        let input: String
        let secret: String
        /// Whether the secret is a card number, whose last four digits may show.
        let digitsOnly: Bool
    }

    private(set) var probes: [Probe] = []
    private var currentCategory = ""

    static let all: [Probe] = {
        let set = ReviewProbeSet()
        for add in [set.addA1, set.addA2, set.addA3, set.addA4, set.addA5, set.addA6, set.addB1, set.addB2, set.addB3, set.addB4,
                    set.addB5, set.addB6, set.addC1, set.addC2, set.addC3, set.addC4, set.addC5] {
            add()
        }
        return set.probes
    }()

    /// Starts a category. The claim the probe was written with is not needed any more: every
    /// probe either hides its secret or is one of the documented limitations.
    func cat(_ name: String, _ claim: String = "C") {
        currentCategory = name
    }

    /// Adds a probe; `{S}` becomes a secret unique to it, unless `secret` names another one.
    func p(_ input: String, _ mode: Mode = .text, secret: String? = nil, digits: Bool = false, claim: String? = nil) {
        let id = probes.count + 1
        let marker = "Vq\(String(format: "%03d", id))Lm8x"
        probes.append(Probe(
            id: id, category: currentCategory, mode: mode, input: input.replacingOccurrences(of: "{S}", with: marker),
            secret: secret ?? marker, digitsOnly: digits
        ))
    }

    // MARK: Values the probes use

    let card = "4242424242424242"
    let card2 = "4111111111111111"
    let iban = "DE89370400440532013000"
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    let hex40 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
    let jsonBody = Mode.body("application/json")
    let formBody = Mode.body("application/x-www-form-urlencoded")
    let plainBody = Mode.body("text/plain")
    let mpType = Mode.body("multipart/form-data; boundary=XyZ")

    func json(_ text: String) -> Mode { .body("application/json") }

    func multipart(_ parts: [(headers: [String], content: String)]) -> String {
        var body = ""
        for part in parts {
            body += "--XyZ\r\n" + part.headers.map { $0 + "\r\n" }.joined() + "\r\n" + part.content + "\r\n"
        }
        return body + "--XyZ--"
    }

    func field(_ name: String, _ content: String, extra: [String] = []) -> (headers: [String], content: String) {
        (["Content-Disposition: form-data; name=\"\(name)\""] + extra, content)
    }

    func grouped(_ digits: String, by separator: String, size: Int = 4) -> String {
        sprinkle(digits, every: size, with: separator)
    }

    func sprinkle(_ token: String, every count: Int, with separator: String) -> String {
        var output = ""
        for (index, character) in token.enumerated() {
            if index > 0, index % count == 0 { output += separator }
            output.append(character)
        }
        return output
    }
}

extension ReviewProbeSet.Probe {
    func redacted() -> String {
        switch mode {
        case .text: SensitiveDataRedactor().redact(input)
        case .textAllowing(let keys): SensitiveDataRedactor(allowedTextKeys: keys).redact(input)
        case .body(let type): SensitiveDataRedactor().redact(body: Data(input.utf8), contentType: type)
        case .rawBody(let bytes, let type): SensitiveDataRedactor().redact(body: Data(bytes + Array(input.utf8)), contentType: type)
        case .url: URL(string: input).map { SensitiveDataRedactor().redact(url: $0) } ?? "<URL(string:) nil>"
        case .urlAllowing(let names): URL(string: input).map { SensitiveDataRedactor(allowedQueryParameters: names).redact(url: $0) } ?? "<URL(string:) nil>"
        }
    }

    /// The piece of the secret that shows in the output: six characters of it, also once
    /// invisible characters, controls and escapes are taken out of the output and it is
    /// compatibility-normalized, so a value that only looks hidden counts; for a card number, its
    /// digits beyond the last four, read across any separators.
    func leakedPiece(in output: String) -> String? {
        let views = [output, Self.visible(output), Self.visible(Self.decodingEscapes(output)), Self.visible(Self.decodingEscapes(Self.visible(output)))]
        if digitsOnly {
            let needle = String(secret.prefix(secret.count > 8 ? secret.count - 4 : secret.count))
            for view in views {
                let digits = String(view.unicodeScalars.compactMap { scalar -> Character? in
                    guard scalar.properties.numericType == .decimal, let value = scalar.properties.numericValue else { return nil }
                    return Character(String(Int(value)))
                })
                if digits.contains(needle) { return needle }
            }
            return nil
        }
        let characters = Array(secret)
        let width = min(6, characters.count)
        for start in 0...(characters.count - width) {
            let piece = String(characters[start..<(start + width)])
            for view in views where view.contains(piece) || view.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "").contains(piece) {
                return piece
            }
        }
        return nil
    }

    private static func visible(_ text: String) -> String {
        var output = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let properties = scalar.properties
            if properties.isDefaultIgnorableCodePoint || properties.isVariationSelector || [0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800].contains(scalar.value) { continue }
            switch properties.generalCategory {
            case .format, .nonspacingMark, .enclosingMark, .spacingMark, .unassigned, .privateUse: continue
            case .control where scalar != "\n" && scalar != "\t": continue
            default: output.append(scalar)
            }
        }
        return String(output).precomposedStringWithCompatibilityMapping
    }

    /// Percent escapes, `\uXXXX` and numeric character references, decoded up to four times.
    private static func decodingEscapes(_ text: String) -> String {
        var current = Array(text.unicodeScalars)
        for _ in 0..<4 {
            let next = decodedOnce(current)
            if next == current { break }
            current = next
        }
        return String(String.UnicodeScalarView(current))
    }

    private static func decodedOnce(_ scalars: [Unicode.Scalar]) -> [Unicode.Scalar] {
        func hex(_ scalar: Unicode.Scalar) -> UInt32? { UInt32(String(scalar), radix: 16) }
        var output: [Unicode.Scalar] = []
        var i = 0
        while i < scalars.count {
            let scalar = scalars[i]
            if scalar == "%", i + 2 < scalars.count, hex(scalars[i + 1]) != nil, hex(scalars[i + 2]) != nil {
                var bytes: [UInt8] = []
                var k = i
                while k + 2 < scalars.count, scalars[k] == "%", let high = hex(scalars[k + 1]), let low = hex(scalars[k + 2]) {
                    bytes.append(UInt8(high << 4 | low))
                    k += 3
                }
                output += String(decoding: bytes, as: UTF8.self).unicodeScalars
                i = k
            } else if scalar == "\\", i + 5 < scalars.count, scalars[i + 1] == "u",
                      let value = UInt32(String(String.UnicodeScalarView(scalars[(i + 2)..<(i + 6)])), radix: 16), let decoded = Unicode.Scalar(value) {
                output.append(decoded)
                i += 6
            } else if scalar == "&", i + 2 < scalars.count, scalars[i + 1] == "#", let (decoded, end) = reference(scalars, at: i) {
                output.append(decoded)
                i = end
            } else {
                output.append(scalar)
                i += 1
            }
        }
        return output
    }

    private static func reference(_ scalars: [Unicode.Scalar], at start: Int) -> (Unicode.Scalar, Int)? {
        let isHex = scalars[start + 2] == "x" || scalars[start + 2] == "X"
        var k = start + (isHex ? 3 : 2)
        let digitsStart = k
        while k < scalars.count, k - digitsStart < 10, isHex ? UInt32(String(scalars[k]), radix: 16) != nil : ("0"..."9").contains(scalars[k]) { k += 1 }
        guard k > digitsStart, let value = UInt32(String(String.UnicodeScalarView(scalars[digitsStart..<k])), radix: isHex ? 16 : 10),
              let decoded = Unicode.Scalar(value)
        else { return nil }
        return (decoded, k < scalars.count && scalars[k] == ";" ? k + 1 : k)
    }
}
