import Foundation
@testable import iOSSecurityTools

/// One input of the adversarial reviews, as `Resources/ReviewProbes.jsonl` holds it: the review it
/// comes from and its number there, what the review claimed for it, how it is redacted and the
/// secret that must not show.
struct ReviewProbe: Decodable, Sendable {
    /// A long input written as a piece repeated between a prefix and a suffix.
    struct Repeat: Decodable, Sendable {
        let prefix: String
        let unit: String
        let count: Int
        let suffix: String
    }

    let review: String
    let id: Int
    let category: String
    /// `C`: the documentation says the secret is hidden. `D`: it says it is not found. `X`:
    /// exploratory, named neither way. `K`: a control that is meant to show.
    let claim: String
    /// `text`, `body` or `url`.
    let kind: String
    /// The allowed text keys for `text` and `body`, the allowed query parameters for `url`.
    let keys: [String]?
    /// The allowed query parameters for `text` and `body`, which free text does not use: a URL in
    /// it is shown only when it is clean.
    let queryKeys: [String]?
    /// The content type of a body; nil for none.
    let type: String?
    let input: String?
    let `repeat`: Repeat?
    /// The body in base64, when it is not the input as UTF-8.
    let data: String?
    let secret: String
    let digits: Bool?
    let width: Int?

    var name: String { "\(review)#\(id)" }

    /// Whether the probe is a long input written as a repeated piece.
    var isLarge: Bool { self.repeat != nil }

    var text: String {
        if let input { return input }
        guard let piece = self.repeat else { return "" }
        return piece.prefix + String(repeating: piece.unit, count: piece.count) + piece.suffix
    }

    func redacted() -> String {
        switch kind {
        case "url":
            let redactor = SensitiveDataRedactor(allowedQueryParameters: keys ?? [])
            return URL(string: text).map { redactor.redact(url: $0) } ?? "<URL(string:) nil>"
        case "body":
            let body = data.flatMap { Data(base64Encoded: $0) } ?? Data(text.utf8)
            return SensitiveDataRedactor(allowedTextKeys: keys ?? [], allowedQueryParameters: queryKeys ?? []).redact(body: body, contentType: type)
        default:
            return SensitiveDataRedactor(allowedTextKeys: keys ?? [], allowedQueryParameters: queryKeys ?? []).redact(text)
        }
    }

    /// The piece of the secret that shows in `output`, or nil: any `width` characters of it in
    /// any reading of the output (as written, without invisible characters, with escapes undone,
    /// form decoded and in compatibility form, also without line breaks). A card number shows when
    /// more than its last four digits do.
    func leakedPiece(in output: String) -> String? {
        let views = Self.readings(output)
        if digits == true {
            let all = Self.digits(of: secret)
            let needle = String(all.prefix(all.count > 8 ? all.count - 4 : all.count))
            return views.contains { Self.digits(of: $0).contains(needle) } ? needle : nil
        }
        let characters = Array(secret)
        let length = min(width ?? 6, characters.count)
        for start in 0...(characters.count - length) {
            let piece = String(characters[start..<(start + length)])
            let folded = Self.visible(piece)
            if views.contains(where: { $0.contains(piece) || (!folded.isEmpty && $0.contains(folded)) }) { return piece }
        }
        return nil
    }

    private static func digits(of text: String) -> String {
        String(text.unicodeScalars.compactMap { scalar -> Character? in
            guard let value = scalar.properties.numericValue, scalar.properties.numericType == .decimal || scalar.properties.numericType == .digit,
                  (0...9).contains(value)
            else { return nil }
            return Character(String(Int(value)))
        })
    }

    private static func readings(_ output: String) -> [String] {
        let plus = output.replacingOccurrences(of: "+", with: " ")
        var views = [output, visible(output), visible(decodingEscapes(output)), visible(decodingEscapes(visible(output))), visible(decodingEscapes(plus))]
        views += views.map { $0.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "") }
        return views
    }

    /// The text without invisible characters and marks, in compatibility form.
    static func visible(_ text: String) -> String {
        var output = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let properties = scalar.properties
            if properties.isDefaultIgnorableCodePoint || properties.isVariationSelector { continue }
            switch properties.generalCategory {
            case .format, .nonspacingMark, .enclosingMark, .spacingMark, .unassigned, .privateUse: continue
            case .control where scalar != "\n" && scalar != "\t": continue
            default: break
            }
            if [0x3164, 0xFFA0, 0x115F, 0x1160, 0x2800].contains(scalar.value) { continue }
            output.append(scalar)
        }
        return String(output).precomposedStringWithCompatibilityMapping
    }

    /// The text with `%XX`, `\uXXXX`, `\"`, `\\`, `\/` and `&#…;` undone, up to eight times.
    private static func decodingEscapes(_ text: String) -> String {
        var current = Array(text.unicodeScalars)
        for _ in 0..<8 {
            let decoded = decodedOnce(current)
            if decoded == current { break }
            current = decoded
        }
        return String(String.UnicodeScalarView(current))
    }

    private static func hex(_ scalar: Unicode.Scalar) -> UInt32? { UInt32(String(scalar), radix: 16) }

    private static func decodedOnce(_ scalars: [Unicode.Scalar]) -> [Unicode.Scalar] {
        var output: [Unicode.Scalar] = []
        var i = 0
        while i < scalars.count {
            let scalar = scalars[i]
            if scalar == "%", i + 2 < scalars.count, let high = hex(scalars[i + 1]), let low = hex(scalars[i + 2]) {
                var bytes = [UInt8(high << 4 | low)]
                var k = i + 3
                while k + 2 < scalars.count, scalars[k] == "%", let h = hex(scalars[k + 1]), let l = hex(scalars[k + 2]) {
                    bytes.append(UInt8(h << 4 | l))
                    k += 3
                }
                output += String(decoding: bytes, as: UTF8.self).unicodeScalars
                i = k
                continue
            }
            if scalar == "\\", i + 5 < scalars.count, scalars[i + 1] == "u",
               let value = UInt32(String(String.UnicodeScalarView(scalars[(i + 2)..<(i + 6)])), radix: 16), let decoded = Unicode.Scalar(value) {
                output.append(decoded)
                i += 6
                continue
            }
            if scalar == "\\", i + 1 < scalars.count, ["\"", "\\", "/"].contains(scalars[i + 1]) {
                output.append(scalars[i + 1])
                i += 2
                continue
            }
            if scalar == "&", i + 2 < scalars.count, scalars[i + 1] == "#" {
                let isHex = scalars[i + 2] == "x" || scalars[i + 2] == "X"
                var k = i + (isHex ? 3 : 2)
                let start = k
                while k < scalars.count, k - start < 12, isHex ? hex(scalars[k]) != nil : ("0"..."9").contains(scalars[k]) { k += 1 }
                if k > start, let value = UInt32(String(String.UnicodeScalarView(scalars[start..<k])), radix: isHex ? 16 : 10),
                   let decoded = Unicode.Scalar(value) {
                    output.append(decoded)
                    i = k < scalars.count && scalars[k] == ";" ? k + 1 : k
                    continue
                }
            }
            output.append(scalar)
            i += 1
        }
        return output
    }
}

enum ReviewProbes {
    /// Every probe of the resource, in order.
    static let all: [ReviewProbe] = {
        guard let url = Bundle.module.url(forResource: "ReviewProbes", withExtension: "jsonl"),
              let contents = try? String(contentsOf: url, encoding: .utf8)
        else { return [] }
        let decoder = JSONDecoder()
        return contents.split(separator: "\n").compactMap { try? decoder.decode(ReviewProbe.self, from: Data($0.utf8)) }
    }()

    static func of(_ review: String) -> [ReviewProbe] { all.filter { $0.review == review } }
}
