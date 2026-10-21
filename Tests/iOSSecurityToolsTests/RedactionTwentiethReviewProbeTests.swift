import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the twentieth review (`a-20`, 240 probes). It found a secret name written with a
/// braced escape of C++23, Perl or PCRE read as plain words and the value after it shown
/// (`login pa\x{73}sword …`, `pa\o{163}sword`, `\x{70}\x{69}\x{6e}`), on all six paths that read
/// free text: a log line, a text/plain body, a JSON string, a form value, an allowed query value
/// and a multipart text part. Free text listed the forms of backslash escapes, and the list left
/// these out. A backslash now cuts the text whatever follows it, unless an ASCII space, tab or
/// line break or the end of the text does (see ``RedactionBackslashEscapeTests``). Every probe is
/// checked by its claim, as the eighteenth review's are; the large ones are checked with those of
/// the other reviews (see ``RedactionReviewProbeSetTests``).
@Suite("SensitiveDataRedactor twentieth review probes")
struct RedactionTwentiethReviewProbeTests {
    static let review = "a-20"

    /// The probes that show their secret by design or as a limitation that "What it does not
    /// find" names, by number.
    static let shown: [String: String] = {
        var shown: [String: String] = [:]
        let byReason: [(String, [Int])] = [
            ("a name spelled with a digit, here one outside ASCII, as `passw0rd` is (`passw〇rd`, `p〡n`)", [34, 35, 37, 38, 43, 166, 181, 192, 238]),
            ("a name written in UTF-7 (`+AHM-ecret`), which is printable ASCII and no escape", [22]),
            ("a letter put into a name that reads as an ASCII letter (`passªword` reads as `passaword`)", [53]),
            ("a secret name split into two segments of a clean URL path (`/to/ken/`)", [125]),
        ]
        for (reason, numbers) in byReason {
            for number in numbers { shown["\(review)#\(number)"] = reason }
        }
        return shown
    }()

    /// The probes the review found shown that the backslash rule hides: a braced escape in a
    /// secret name on each of the six paths.
    static let braced = ([1, 2] + Array(5...20) + [165, 182, 193, 198, 239]).map { "\(review)#\($0)" }

    @Test("the resource holds every probe of the twentieth review")
    func counts() {
        let probes = ReviewProbes.of(Self.review)
        #expect(probes.count == 240)
        #expect(Dictionary(grouping: probes, by: \.claim).mapValues(\.count) == ["C": 230, "D": 2, "X": 8])
        #expect(Self.shown.count == 12)
        #expect(Self.braced.count == 23)
    }

    @Test("a probe hides its secret unless it is a documented limitation")
    func probesKeepTheirClaims() {
        for probe in ReviewProbes.of(Self.review) where !(probe.isLarge && probe.claim == "C") {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim) \(probe.category): \(probe.text.prefix(200).debugDescription) -> \(output.prefix(200).debugDescription)"
            if probe.claim == "K" || probe.claim == "D" || Self.shown[probe.name] != nil {
                #expect(piece != nil, "\(description) is hidden")
            } else {
                #expect(piece == nil, "\(description)")
            }
        }
    }

    @Test("the braced escapes the review found are hidden on the path it found them on", arguments: braced)
    func bracedEscapesAreHidden(name: String) throws {
        let probe = try #require(ReviewProbes.all.first { $0.name == name })
        let output = probe.redacted()
        #expect(probe.leakedPiece(in: output) == nil, "\(probe.text.debugDescription) -> \(output.debugDescription)")
    }

    @Test("a braced escape in a secret name cuts a log line at the start of its word", arguments: [
        "pa\\x{73}sword", "\\x{70}assword", "to\\x{6b}en", "p\\x{69}n", "secre\\x{74}", "pa\\o{163}sword", "to\\o{153}en", "pa\\x{0073}sword",
        "\\x{70}\\x{69}\\x{6e}", "pa\\X{73}sword", "pa\\O{163}sword",
    ])
    func bracedEscapesCutAtTheirWord(word: String) {
        let redactor = SensitiveDataRedactor()
        #expect(redactor.redact("login " + word + " Qx001Np7v") == "login [redacted]")
        #expect(redactor.redact("status=200 " + word + " Qx002Np7v") == "status=200 [redacted]")
    }
}
