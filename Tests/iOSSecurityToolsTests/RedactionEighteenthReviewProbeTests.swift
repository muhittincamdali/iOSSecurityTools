import Foundation
import Testing
@testable import iOSSecurityTools

/// The probes of the eighteenth review: its adversarial set (`a-18`, 1,084 probes) and the
/// correctness review's inputs (`c-18`, each with the default redactor, with allowed text keys and
/// in a JSON string). The adversarial set found element text shown after a `<` before `_` or a
/// digit outside ASCII (`<_id>…</_id>`, `<०>…`), which the markup rule did not count as a tag; a
/// `<` now cuts the text unless an ASCII space, tab, line break, digit, `=` or the end of the text
/// follows it. The correctness review found a `?`, `#` or `;` after a quote, `>` or backtick that
/// ended a URL neither in the URL nor a cut (`https://example.com/a'#…`), a key in single quotes or
/// backticks read as a word (`'x status': …`), and the last segment of a URL never read with the
/// next word (`…/to ken …`). A URL is now clean only before white space, a line break, the end of
/// the text or one mark that ends a sentence; a key in quotes of any kind follows the quoted-key
/// rule; and a URL's last segment is read with the next word. Every probe is checked by its
/// claim, as the sixteenth review's are; the large ones are checked with those of the other
/// reviews (see ``RedactionReviewProbeSetTests``). `a-18#751` (`https://Qx751Np7v.password.h.example/`)
/// showed its value in a host that names a secret until 2.1.1, which hides such a host.
@Suite("SensitiveDataRedactor eighteenth review probes")
struct RedactionEighteenthReviewProbeTests {
    static let reviews = ["a-18", "c-18"]

    /// The probes that show their secret by design or as a limitation that "What it does not
    /// find" names, by review and number.
    static let shown: [String: String] = {
        var shown: [String: String] = [:]
        let c18 = { (inputs: [Int]) in inputs.flatMap { first in (first..<(first + 3)).map { "c-18#\($0)" } } }
        let byReason: [(String, [String])] = [
            ("a `<` before an ASCII space, tab, line break or digit is a comparison", ["a-18#40", "a-18#41", "a-18#42", "a-18#44"] + c18([322])),
            ("a name with two or more letters that have no ASCII form, without a separator", ["a-18#174", "a-18#185"]),
            ("a letter or mark that looks like a separator is a letter or mark", ["a-18#303", "a-18#305", "a-18#307", "a-18#309", "a-18#311", "a-18#315"]
                + c18([130, 133, 139])),
            ("a key that folds to an allowed key (`sta-tus`, `durationMs`, `'status'`)",
             (366...378).map { "a-18#\($0)" } + ["a-18#400"]),
            ("a path segment written without a scheme, before a query cut at its value", ["a-18#471"]),
            ("a key of structured input, which is shown", ["a-18#700"]),
            ("the value of a key that names no secret, in structured input", ["a-18#788"]),
            ("text after JSON or a value that no trigger comes before", ["a-18#906"] + c18([409])),
            ("text without a trigger: `->` is no separator", ["a-18#959"]),
        ]
        for (reason, names) in byReason {
            for name in names { shown[name] = reason }
        }
        return shown
    }()

    /// Controls that are hidden on purpose: a backslash before anything but white space or the
    /// end of the text is an escape, which cuts the text, also before a quote (`\"status\":`,
    /// `\'status\'`) or another backslash (`\\"status\\"`). That rule made the first two controls
    /// (`a-18#932`, `a-18#933`) hidden too.
    static let hiddenControls: Set<String> = ["a-18#932", "a-18#933", "a-18#937", "a-18#938", "a-18#942", "a-18#943"]

    /// The limitations the review named that are found: a JSON object written as a form body.
    static let fixed: Set<String> = ["a-18#698"]

    @Test("the resource holds every probe of the eighteenth review")
    func counts() {
        let counts = Dictionary(grouping: ReviewProbes.all.filter { Self.reviews.contains($0.review) }, by: \.review).mapValues(\.count)
        #expect(counts == ["a-18": 1_084, "c-18": 417])
    }

    @Test("a probe hides its secret unless it is a control or a documented limitation", arguments: reviews)
    func probesKeepTheirClaims(review: String) {
        for probe in ReviewProbes.of(review) where !(probe.isLarge && probe.claim == "C") {
            let output = probe.redacted()
            let piece = probe.leakedPiece(in: output)
            let description = "\(probe.name) \(probe.claim) \(probe.category): \(probe.text.prefix(200).debugDescription) -> \(output.prefix(200).debugDescription)"
            if (probe.claim == "K" && !Self.hiddenControls.contains(probe.name)) || Self.shown[probe.name] != nil {
                #expect(piece != nil, "\(description) is hidden")
            } else if probe.claim == "D", !Self.fixed.contains(probe.name) {
                #expect(piece != nil, "\(description) is found, so the documentation can drop it")
            } else {
                #expect(piece == nil, "\(description)")
            }
        }
    }

    @Test("the correctness review's ordinary lines stay useful", arguments: [
        "GET /api/v1/items 200 OK in 35ms", "status=200 method=GET path=/v1/items duration_ms=12 count=3", "Kullanıcı girişi başarılı",
        "fetched https://api.example.com/v1/users/42 in 30ms", "fetched https://api.example.com/v1/items.", "a < b and c > d",
        "it's done, don't retry", "\"quoted text\" here", "[INFO] ready (3 items) {x}", "retry 3/5 after 250 ms", "took 12.5s (p99 40ms)",
        "a & b", "{\"status\":200,\"count\":3}", "[{\"status\":200},{\"status\":201}]",
    ])
    func usefulLines(line: String) {
        #expect(SensitiveDataRedactor().redact(line) == line)
    }

    @Test("the correctness review's lines keep what the allowed keys allow")
    func allowedLines() {
        let redactor = SensitiveDataRedactor(allowedTextKeys: ["user", "note", "name", "type", "id", "page", "q"])
        for line in ["user=alice logged in", "user=bob note=\"hello world\" id=42", "name=Bob type=admin", "{\"note\":\"hi\"}"] {
            #expect(redactor.redact(line) == line)
        }
        // Without them, the first key that is not allowed cuts the line.
        #expect(SensitiveDataRedactor().redact("user=alice logged in") == "user=[redacted]")
        #expect(SensitiveDataRedactor().redact("see <https://example.com/a>") == "see [redacted]")
    }

    @Test("the correctness review's bodies keep their structure and their ordinary values")
    func bodies() throws {
        let redactor = SensitiveDataRedactor()
        let json = #"{"name":"Bob","email":"bob@example.com","password":"hunter2","items":[1,2,3],"nested":{"city":"Paris","token":"abc","list":["a","b"]},"ok":true,"n":null,"status":"done","msg":"order shipped to warehouse 7"}"#
        let redacted = redactor.redact(body: Data(json.utf8), contentType: "application/json")
        #expect(redacted == #"{"name":"Bob","email":"b•••@example.com","password":"[redacted]","items":[1,2,3],"nested":{"city":"Paris","token":"[redacted]","list":["a","b"]},"ok":true,"n":null,"status":"done","msg":"order shipped to warehouse 7"}"#)
        #expect(try JSONSerialization.jsonObject(with: Data(redacted.utf8)) is [String: Any])
        let form = "name=Bob&page=2&password=hunter2&q=hello+world&city=Paris&empty=&status=ok"
        #expect(redactor.redact(body: Data(form.utf8), contentType: "application/x-www-form-urlencoded")
            == "name=Bob&page=2&password=[redacted]&q=hello+world&city=Paris&empty=&status=ok")
        let array = #"[{"id":1,"title":"Buy milk","done":false},{"id":2,"title":"Walk the dog","done":true}]"#
        #expect(redactor.redact(body: Data(array.utf8), contentType: "application/json; charset=utf-8") == array)
        let multipart = "--B0und\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello world\r\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--B0und--\r\n"
        #expect(redactor.redact(body: Data(multipart.utf8), contentType: "multipart/form-data; boundary=B0und")
            == "--B0und\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello world\r\n--B0und\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[redacted]\r\n--B0und--")
    }
}
