import Foundation
@testable import iOSSecurityTools

/// The adversarial probe set of the tenth review: 353 inputs written against names written as
/// values, each hiding a unique secret (`{S}`) behind one trick in free text, markup, bodies and
/// URLs. 38 of them got their secret past the redactor when they were written, 18 of them names
/// written only in circled or squared letters. The probes are in the
/// `RedactionTenthReviewProbes+…` files.
final class TenthReviewProbeSet {
    enum Mode {
        case text
        case textAllowing([String])
        case body(String?)
        case bytes([UInt8], String?)
        case encoded(String.Encoding, String?)
        case bytesAfter([UInt8], String?)
        case url
        case urlAllowing([String])
    }

    struct Probe {
        let id: Int
        let category: String
        let mode: Mode
        let input: String
        let secret: String
        /// Whether the secret is a card number, whose last four digits may show.
        let digitsOnly: Bool
        /// The length of the pieces of the secret that count as shown.
        let width: Int

        func redacted() -> String {
            switch mode {
            case .text: return SensitiveDataRedactor().redact(input)
            case .textAllowing(let keys): return SensitiveDataRedactor(allowedTextKeys: keys).redact(input)
            case .body(let type): return SensitiveDataRedactor().redact(body: Data(input.utf8), contentType: type)
            case .bytes(let prefix, let type): return SensitiveDataRedactor().redact(body: Data(prefix + Array(input.utf8)), contentType: type)
            case .encoded(let encoding, let type):
                return SensitiveDataRedactor().redact(body: input.data(using: encoding) ?? Data(), contentType: type)
            case .bytesAfter(let suffix, let type): return SensitiveDataRedactor().redact(body: Data(Array(input.utf8) + suffix), contentType: type)
            case .url: return URL(string: input).map { SensitiveDataRedactor().redact(url: $0) } ?? "<no URL>"
            case .urlAllowing(let names): return URL(string: input).map { SensitiveDataRedactor(allowedQueryParameters: names).redact(url: $0) } ?? "<no URL>"
            }
        }

        /// A piece of the secret that shows in some reading of the output (see
        /// ``TenthReviewProbeSet/readings(of:)``), or nil.
        func leakedPiece(in output: String) -> String? {
            let views = TenthReviewProbeSet.readings(of: output)
            if digitsOnly {
                let digits = TenthReviewProbeSet.digits(of: secret)
                let needle = String(digits.prefix(digits.count > 8 ? digits.count - 4 : digits.count))
                return views.contains { TenthReviewProbeSet.digits(of: $0).contains(needle) } ? needle : nil
            }
            let characters = Array(secret)
            let length = min(width, characters.count)
            for start in 0...(characters.count - length) {
                let piece = String(characters[start..<(start + length)])
                let folded = TenthReviewProbeSet.visible(piece)
                if views.contains(where: { $0.contains(piece) || (!folded.isEmpty && $0.contains(folded)) }) { return piece }
            }
            return nil
        }
    }

    private(set) var probes: [Probe] = []
    private var category = ""

    static let all: [Probe] = {
        let set = TenthReviewProbeSet()
        set.addNames()
        set.addMarkup()
        set.addJSON()
        set.addBodies()
        set.addText()
        set.addSymbols()
        return set.probes
    }()

    // MARK: Writing probes

    /// Starts a category. The claim the probe was written with is not kept: every probe either
    /// hides its secret or is one of the documented limitations.
    func section(_ name: String, _ claim: String = "C") {
        category = name
    }

    /// Adds a probe; `{S}` becomes a secret unique to it, unless `secret` names another one.
    func p(_ input: String, _ mode: Mode = .text, secret: String? = nil, digits: Bool = false, width: Int = 6, claim: String? = nil) {
        let id = probes.count + 1
        let marker = "Qz\(String(format: "%03d", id))Wk9r"
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

    // MARK: Readings of the output

    /// The output as written, without invisible characters and compatibility-folded, with
    /// escapes undone (also after `+` is read as a space), and each of these without line breaks.
    static func readings(of output: String) -> [String] {
        let plus = output.replacingOccurrences(of: "+", with: " ")
        var views = [output, visible(output), visible(decodingEscapes(output)), visible(decodingEscapes(visible(output))), visible(decodingEscapes(plus))]
        views += views.map { $0.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "") }
        return views
    }

    static func visible(_ text: String) -> String {
        var view = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let properties = scalar.properties
            if properties.isDefaultIgnorableCodePoint || properties.isVariationSelector { continue }
            switch properties.generalCategory {
            case .format, .nonspacingMark, .enclosingMark, .spacingMark, .unassigned, .privateUse: continue
            case .control where scalar != "\n" && scalar != "\t": continue
            default: break
            }
            if [0x3164, 0xFFA0, 0x115F, 0x1160, 0x2800].contains(scalar.value) { continue }
            view.append(scalar)
        }
        return String(view).precomposedStringWithCompatibilityMapping
    }

    private static func digits(of text: String) -> String {
        String(text.unicodeScalars.compactMap { scalar -> Character? in
            let properties = scalar.properties
            guard properties.numericType == .decimal || properties.numericType == .digit, let value = properties.numericValue,
                  value >= 0, value <= 9
            else { return nil }
            return Character(String(Int(value)))
        })
    }

    /// Percent escapes (as UTF-8), `\uXXXX`, `\"`, `\\`, `\/` and HTML character references,
    /// undone up to eight times.
    static func decodingEscapes(_ text: String) -> String {
        var current = Array(text.unicodeScalars)
        for _ in 0..<8 {
            let decoded = decodedOnce(current)
            if decoded == current { break }
            current = decoded
        }
        return String(String.UnicodeScalarView(current))
    }

    private static func decodedOnce(_ scalars: [Unicode.Scalar]) -> [Unicode.Scalar] {
        var out: [Unicode.Scalar] = []
        var i = 0
        while i < scalars.count {
            if let (decoded, next) = percentEscapes(scalars, at: i) ?? backslashEscape(scalars, at: i) ?? characterReference(scalars, at: i) {
                out += decoded
                i = next
            } else {
                out.append(scalars[i])
                i += 1
            }
        }
        return out
    }

    private static func hex(_ scalar: Unicode.Scalar) -> UInt32? { UInt32(String(scalar), radix: 16) }

    private static func percentEscapes(_ s: [Unicode.Scalar], at i: Int) -> ([Unicode.Scalar], Int)? {
        var bytes: [UInt8] = []
        var k = i
        while k + 2 < s.count, s[k] == "%", let high = hex(s[k + 1]), let low = hex(s[k + 2]) {
            bytes.append(UInt8(high << 4 | low))
            k += 3
        }
        return bytes.isEmpty ? nil : (Array(String(decoding: bytes, as: UTF8.self).unicodeScalars), k)
    }

    private static func backslashEscape(_ s: [Unicode.Scalar], at i: Int) -> ([Unicode.Scalar], Int)? {
        guard s[i] == "\\", i + 1 < s.count else { return nil }
        if s[i + 1] == "u", i + 5 < s.count, let value = UInt32(String(String.UnicodeScalarView(s[(i + 2)..<(i + 6)])), radix: 16),
           let scalar = Unicode.Scalar(value) {
            return ([scalar], i + 6)
        }
        return ["\"", "\\", "/"].contains(s[i + 1]) ? ([s[i + 1]], i + 2) : nil
    }

    private static func characterReference(_ s: [Unicode.Scalar], at i: Int) -> ([Unicode.Scalar], Int)? {
        guard s[i] == "&", i + 2 < s.count, s[i + 1] == "#" else { return nil }
        let isHex = s[i + 2] == "x" || s[i + 2] == "X"
        let start = i + (isHex ? 3 : 2)
        var k = start
        while k < s.count, k - start < 12, isHex ? hex(s[k]) != nil : ("0"..."9").contains(s[k]) { k += 1 }
        guard k > start, let value = UInt32(String(String.UnicodeScalarView(s[start..<k])), radix: isHex ? 16 : 10),
              let scalar = Unicode.Scalar(value)
        else { return nil }
        return ([scalar], k < s.count && s[k] == ";" ? k + 1 : k)
    }
}
