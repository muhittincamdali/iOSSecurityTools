import Foundation
import Testing
@testable import iOSSecurityTools

/// Generated multipart and form bodies, each read as it is and then with one thing planted that a
/// common server parser splits differently: the strict body is read, the planted one is omitted.
@Suite("SensitiveDataRedactor parser differential properties")
struct RedactionParserDifferentialPropertyTests {
    let redactor = SensitiveDataRedactor()
    static let names = ["note", "user", "status", "comment", "password", "token", "pin", "api_key"]
    static let words = ["hi", "ok", "Istanbul", "42", "see you", "a-b", "x_y"]

    /// What makes Werkzeug, PHP, Go or busboy find a delimiter, or a delimiter-like line, that a
    /// strict CRLF reading does not.
    static let plantedDelimiters = [
        "\n--B0und\r\n", "\r--B0und\r\n", "\r\n\n--B0und\r\n", " --B0und", "\r\n--b0und\r\n", "\r\n--B0UND--",
        "\r\n--B0und \r\n", "\r\n--B0und\t\r\n", "--B0und", "\n--B0und\n", "\r\n--B0und\n",
    ]

    @Test("a planted --boundary anywhere but on a CRLF delimiter line omits the multipart body")
    func multipart() {
        var random = SeededRandom(seed: 0xB0_0D1F)
        for _ in 0..<400 {
            let parts = (0..<Int.random(in: 1...4, using: &random)).map { _ in
                (Self.names.randomElement(using: &random)!, Self.words.randomElement(using: &random)! + "Qz\(Int.random(in: 100...999, using: &random))")
            }
            let strict = parts.map { "--B0und\r\nContent-Disposition: form-data; name=\"\($0.0)\"\r\n\r\n\($0.1)\r\n" }.joined() + "--B0und--"
            let contentType = "multipart/form-data; boundary=B0und"
            let read = redactor.redact(body: Data(strict.utf8), contentType: contentType)
            #expect(!read.hasPrefix("[body omitted"), "\(strict.debugDescription)")

            // Planted inside a part's content, its header block or just before the next delimiter.
            let planted = Self.plantedDelimiters.randomElement(using: &random)!
            let anchors = ["\r\n\r\n", "\r\n--B0und", "\"\r\n"].compactMap { strict.range(of: $0) }
            let anchor = anchors.randomElement(using: &random)!
            let body = strict.replacingCharacters(in: anchor.lowerBound..<anchor.lowerBound, with: planted)
            let output = redactor.redact(body: Data(body.utf8), contentType: contentType)
            #expect(output == "[body omitted: \(body.utf8.count) bytes, multipart/form-data]", "\(body.debugDescription) -> \(output.debugDescription)")
        }
    }

    /// What makes Rack, PHP, older Python or Go read other fields or names than a strict reading.
    /// Each `%` here is followed by a character that is not a hex digit, wherever it lands.
    static let plantedFormText = [";", " ", "\t", "\n", "%G0", "%4G", "%-", "\u{E9}", "\u{301}", "\u{200B}", "\u{7F}", "\u{0}"]

    @Test("a planted ;, space, bare %, character outside printable ASCII or second spelling omits the form")
    func form() {
        var random = SeededRandom(seed: 0xF0_43D1)
        for _ in 0..<400 {
            var used = Set<String>()
            let fields = (0..<Int.random(in: 1...4, using: &random)).compactMap { _ -> String? in
                let name = Self.names.randomElement(using: &random)!
                guard used.insert(name).inserted else { return nil }
                return name + "=" + (Self.words.randomElement(using: &random)!.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")
            }
            let strict = fields.joined(separator: "&")
            let contentType = "application/x-www-form-urlencoded"
            #expect(!redactor.redact(body: Data(strict.utf8), contentType: contentType).hasPrefix("[body omitted"), "\(strict)")

            let body: String
            if Bool.random(using: &random) {
                let offset = Int.random(in: 0...strict.unicodeScalars.count, using: &random)
                var scalars = Array(strict.unicodeScalars)
                scalars.insert(contentsOf: Self.plantedFormText.randomElement(using: &random)!.unicodeScalars, at: offset)
                body = String(String.UnicodeScalarView(scalars))
            } else {
                let name = fields[0].prefix { $0 != "=" }
                let respelled = [name.uppercased(), "%" + String(format: "%02X", name.utf8.first!) + name.dropFirst(), "+" + name]
                body = strict + "&" + respelled.randomElement(using: &random)! + "=Qz1"
            }
            let output = redactor.redact(body: Data(body.utf8), contentType: contentType)
            #expect(output == "[body omitted: \(body.utf8.count) bytes, application/x-www-form-urlencoded]", "\(body.debugDescription) -> \(output.debugDescription)")
        }
    }
}
