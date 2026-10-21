import Foundation
import Testing
@testable import iOSSecurityTools

/// A value detector reads a vertical tab, a form feed, U+0085, U+2028 and U+2029 in one of two
/// ways, each written once (see ``NormalizedText/isGap(_:)`` and
/// ``NormalizedText/readable(after:)``): as the white space between the groups of a card number or
/// an IBAN and after `Bearer`, and as nothing inside an email address, a token or the token after
/// `Bearer`. Each of them cuts free text; a finding that the cut falls inside joins the cut at its
/// start, in one place (``SensitiveDataRedactor/merged(_:)``). So a value is hidden from the same
/// start with every such separator, with every character that the scanning copy leaves out and,
/// where the detector takes white space, with every space outside ASCII, and on every path; and
/// that start is where the detector finds the value written whole.
@Suite("SensitiveDataRedactor cut inside a value")
struct RedactionCutInValueTests {
    let redactor = SensitiveDataRedactor(allowedTextKeys: ["note"], allowedQueryParameters: ["note"])

    /// The line separators the detectors read across, and characters the scanning copy leaves
    /// out; each cuts free text.
    static let cuts: [String] = ["\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}", "\u{200B}", "\u{7F}", "\u{1B}"]
    /// Spaces outside ASCII, which cut free text and which the scanning copy reads as a space.
    static let spaces: [String] = ["\u{A0}", "\u{2003}", "\u{3000}"]

    /// A value written in two pieces with a cut between them, the value as a detector reads it
    /// whole (with a space between the pieces, or nothing), and what of it shows before the cut:
    /// `Bearer`, which is not part of the finding.
    struct Split: Sendable, CustomTestStringConvertible {
        let before: String
        let after: String
        let spaced: Bool
        var shown = ""
        /// Where the detector's finding starts in the value written whole.
        var findingOffset = 0

        var testDescription: String { before + "|" + after }
        var whole: String { before + (spaced ? " " : "") + after }
    }

    static let splits: [Split] = [
        Split(before: "4111 1111 1111", after: "1111", spaced: true),
        Split(before: "4111", after: "1111 1111 1111", spaced: true),
        Split(before: "4111 11", after: "11 1111 1111", spaced: true),
        Split(before: "4111-1111-1111", after: "1111", spaced: true),
        Split(before: "411111111111", after: "1111", spaced: true),
        Split(before: "4111 1111 1111 ", after: "1111", spaced: false),
        Split(before: "DE89 3704 0044 0532", after: "0130 00", spaced: true),
        Split(before: "DE89", after: "3704 0044 0532 0130 00", spaced: true),
        Split(before: "GB82 WEST", after: "1234 5698 7654 32", spaced: true),
        Split(before: "bob.smith", after: "@example.com", spaced: false),
        Split(before: "bob.smith@", after: "example.com", spaced: false),
        Split(before: "bob.smith@example.c", after: "om", spaced: false),
        Split(before: "ayşe.yılmaz", after: "@gmail.com", spaced: false),
        Split(before: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", after: ".c2lnbmF0dXJlLXNpZ25hdHVyZQ", spaced: false),
        Split(before: "eyJhbGciOiJIUzI1NiJ9", after: ".eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXNpZ25hdHVyZQ", spaced: false),
        Split(before: "eyJhbGciOiJI", after: "UzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXNpZ25hdHVyZQ", spaced: false),
        Split(before: "ghp_A1b2A1b2A1b2A1b2", after: "C3d4C3d4C3d4C3d4C3d4", spaced: false),
        Split(before: "0123456789abcdef", after: "0123456789abcdef01", spaced: false),
        Split(before: "Bearer abcd", after: "efgh12345678", spaced: false, shown: "Bearer ", findingOffset: 7),
        Split(before: "Bearer", after: "abcdefgh12345678", spaced: true, shown: "Bearer", findingOffset: 7),
    ]

    static let prefix = "paid with "
    static let suffix = " ok"

    /// The text on every path that reads it as free text, and the text that comes back.
    func paths(_ text: String) -> [(String, String?)] {
        let encoded = RedactionDetectorDifferentialTests.encoded(text)
        let multipart = "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n\(text)\r\n--B0und--\r\n"
        let json = redactor.redact(body: RedactionDetectorDifferentialTests.json(["note": text]), contentType: "application/json")
        let form = redactor.redact(body: Data(("note=" + encoded).utf8), contentType: "application/x-www-form-urlencoded")
        let part = redactor.redact(body: Data(multipart.utf8), contentType: "multipart/form-data; boundary=B0und")
        let query = URL(string: "https://h.example/p?note=" + encoded).map { redactor.redact(url: $0) }
        let formValue = form.hasPrefix("note=") ? String(form.dropFirst(5)).replacingOccurrences(of: "+", with: " ").removingPercentEncoding : nil
        return [
            ("text", redactor.redact(text)),
            ("allowed key", String(redactor.redact("note=" + text).dropFirst(5))),
            ("text body", redactor.redact(body: Data(text.utf8), contentType: "text/plain")),
            ("JSON string", (try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: String])?["note"]),
            ("form value", formValue),
            ("multipart", part.components(separatedBy: "\r\n\r\n").dropFirst().first?.components(separatedBy: "\r\n--B0und").first),
            ("allowed query", query.flatMap(Self.queryValue)),
        ]
    }

    /// The value after `note=` in a URL written by ``SensitiveDataRedactor/redact(url:)``.
    static func queryValue(_ url: String) -> String? {
        guard let range = url.range(of: "?note=") else { return nil }
        return String(url[range.upperBound...]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }

    @Test("a value cut by a separator the detectors read across is hidden from where it is found whole", arguments: splits)
    func sameStart(split: Split) throws {
        let whole = Self.prefix + split.whole + Self.suffix
        let match = try #require(redactor.matches(in: whole).first, "\(whole.debugDescription) is found")
        let findingStart = whole.unicodeScalars.distance(from: whole.startIndex, to: match.range.lowerBound)
        #expect(findingStart == Self.prefix.unicodeScalars.count + split.findingOffset, "\(whole.debugDescription)")
        // The cut never starts after the finding: only `Bearer` before the token may show.
        #expect(split.shown.unicodeScalars.count <= split.findingOffset)
        let expected = Self.prefix + split.shown + SensitiveDataRedactor.replacement
        for cut in Self.cuts + (split.spaced ? Self.spaces : []) {
            let text = Self.prefix + split.before + cut + split.after + Self.suffix
            // A character the copy leaves out is inside the word around it, which cannot be read
            // and is cut where it starts: `Bearer` and a zero-width space before the token go too.
            let isLeftOut = ["\u{200B}", "\u{7F}", "\u{1B}"].contains(cut)
            let accepted = isLeftOut ? [expected, Self.prefix + SensitiveDataRedactor.replacement] : [expected]
            let outputs = paths(text)
            for (path, output) in outputs {
                #expect(output.map(accepted.contains) == true,
                        "\(path): \(text.debugDescription) -> \(String(describing: output).debugDescription)")
                // The same on every path.
                #expect(output == outputs[0].1, "\(path) and text: \(text.debugDescription)")
            }
        }
    }

    @Test("the detectors alone find a value across a line separator, as across white space or nothing", arguments: splits)
    func detectorsAlone(split: Split) {
        let detectors = SensitiveDataRedactor(kinds: SensitiveDataRedactor.Kinds.all.subtracting(.secretFields))
        let wholeOutput = detectors.redact(Self.prefix + split.whole + Self.suffix)
        for cut in ["\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}"] {
            let text = Self.prefix + split.before + cut + split.after + Self.suffix
            let output = detectors.redact(text)
            #expect(output != text, "\(text.debugDescription) -> \(output.debugDescription)")
            // The same mask or replacement as the value written whole, from the same start.
            #expect(output.hasSuffix(Self.suffix) && output.hasPrefix(Self.prefix + split.shown), "\(text.debugDescription) -> \(output.debugDescription)")
            #expect(output.count <= wholeOutput.count + 1, "\(output.debugDescription) and \(wholeOutput.debugDescription)")
        }
    }

    @Test("a value cut by an escape is hidden with the word the escape is glued to", arguments: splits.filter { !$0.spaced && !$0.before.contains(" ") })
    func escapes(split: Split) {
        for escape in ["%0B", "\\x0b", "\\u2028", "&#11;", "&#x2028;", "&NewLine;"] {
            let text = Self.prefix + split.before + escape + split.after + Self.suffix
            #expect(redactor.redact(text) == Self.prefix + SensitiveDataRedactor.replacement, "\(text.debugDescription)")
        }
    }

    /// The line separator probes of the twenty-fifth correctness review (`c-25`): every value
    /// detector and key around a vertical tab, a form feed, U+0085, U+2028 and U+2029, with the
    /// default keys and with `user` allowed. None shows the secret.
    @Test("the twenty-fifth review's line separator probes hide the secret")
    func reviewProbes() {
        let secret = "hunter2"
        let allowingUser = SensitiveDataRedactor(allowedTextKeys: ["user"])
        var shown: [String] = []
        for cut in ["\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}"] {
            let texts = [
                "status=1 4242 4242 4242" + cut + "4242 " + secret, "status=1 a@b" + cut + ".co " + secret,
                "status=1 Bearer" + cut + "abcdefgh" + secret, "status=1 eyJhbGciOi.eyJzdWIiOi" + cut + ".sig " + secret,
                "status=1 DE89 3704 0044 0532" + cut + "0130 00 " + secret, "pass" + cut + "word=" + secret,
                "status=1" + cut + "password=" + secret, "status=1 user" + cut + "=" + secret, "status" + cut + "=" + secret,
                "ok " + cut + secret, "status=1 abcdef0123456789abcdef0123456789" + cut + secret, "status=1 x:" + secret + cut + "@host",
                "status=1 bob:" + secret + "@x" + cut + ".example", "status=1 " + secret + "@x" + cut + ".com",
            ]
            for text in texts {
                for redactor in [SensitiveDataRedactor(), allowingUser] where redactor.redact(text).contains(secret) {
                    shown.append(text)
                }
            }
        }
        #expect(shown.isEmpty, "\(shown.map(\.debugDescription))")
    }

    @Test("the review's examples read as the documentation says")
    func examples() {
        let redactor = SensitiveDataRedactor()
        #expect(redactor.redact("paid with 4111 1111 1111\u{0B}1111 ok") == "paid with [redacted]")
        #expect(redactor.redact("paid with 4111 1111 1111 \u{0B}1111 ok") == "paid with [redacted]")
        #expect(redactor.redact("mail bob.smith\u{2028}@example.com") == "mail [redacted]")
        #expect(redactor.redact("mail bob@example.c\u{2028}om ok") == "mail [redacted]")
        #expect(redactor.redact("got ghp_A1b2A1b2A1b2A1b2\u{2029}C3d4C3d4C3d4C3d4C3d4 ok") == "got [redacted]")
        #expect(redactor.redact("sent Bearer abcd\u{0B}efgh12345678 ok") == "sent Bearer [redacted]")
        let detectors = SensitiveDataRedactor(kinds: SensitiveDataRedactor.Kinds.all.subtracting(.secretFields))
        #expect(detectors.redact("card 4242 4242\u{0B}4242 4242 ok") == "card •••• 4242 ok")
        #expect(detectors.redact("mail bob.smith\u{2028}@example.com ok") == "mail b•••@example.com ok")
        // A line feed written as such ends a finding, as it ends a line of the log.
        #expect(detectors.redact("card 4242 4242\n4242 4242 ok") == "card 4242 4242\n4242 4242 ok")
        // Usefulness: with no finding across it, a separator cuts the text where it stands.
        #expect(redactor.redact("status=200 done\u{2028}next") == "status=200 done[redacted]")
        #expect(redactor.redact("count=3\u{0B}ok") == "count=3[redacted]")
    }
}
