import Foundation
import Testing
@testable import iOSSecurityTools

/// Where a URL in free text ends. A clean URL may be followed only by white space, a line break or
/// the end of the text, or by one of `.`, `,`, `!` and `)` and then one of those. Any other
/// character after it — a quote, a backtick, `>`, `]`, `}`, a second mark, or a `?`, `#`, `;` or
/// `:` — leaves open where the URL ends, so the text is cut where the URL starts. The eighteenth
/// review found a URL ended at a quote, an angle bracket or a backtick and the text after it read
/// on, so a `?`, `#` or `;` glued to that character was neither part of the URL nor a cut
/// (`see https://example.com/a'#Qx31Sec`), while ``SensitiveDataRedactor/redact(url:)`` hid the
/// fragment of the same URL.
@Suite("SensitiveDataRedactor where a URL in text ends")
struct RedactionURLEndTests {
    static let secret = "Qx31Sec"
    /// The marks that may end a sentence right after a clean URL.
    static let sentenceEnds = [".", ",", "!", ")"]

    /// The review's inputs, with the default redactor, with allowed text keys, in a JSON string and
    /// in a text/plain body; all but the first seven were hidden before too.
    static let reviewInputs = [
        "see https://example.com/it's/a#Qx31Sec", "see https://example.com/a'?Qx31Sec tail", "see https://example.com/a';Qx31Sec tail",
        "see https://example.com/a>#Qx31Sec tail", "see https://example.com/a>?Qx31Sec", "see https://example.com/a\"#Qx31Sec\" tail",
        "see https://example.com/a`#Qx31Sec` tail", "see https://example.com/a'#Qx31Sec tail", "see https://example.com/it's?Qx31Sec",
        "see https://example.com/a'b?Qx31Sec", "see https://example.com'#Qx31Sec", "see https://example.com/a'/b?Qx31Sec",
        "see https://example.com/a' #Qx31Sec", "see https://example.com/a'\n#Qx31Sec", "see 'https://example.com/a'#Qx31Sec",
        "see https://example.com/a'?api_key=Qx31Sec", "see https://example.com/a'?page=1&Qx31Sec", "see https://example.com/a)#Qx31Sec",
        "see https://example.com/a.#Qx31Sec", "see https://example.com/a.?Qx31Sec", "see https://example.com/a,#Qx31Sec",
        "see https://example.com/a!#Qx31Sec", "see https://example.com/a?#Qx31Sec", "see https://[::1]/#Qx31Sec",
        "see https://[::1]:8080/a?x=Qx31Sec", "see https://example.com/a%23Qx31Sec", "see https://example.com/a%3Ftoken%3DQx31Sec",
        "see https://user:Qx31Sec@example.com/", "see https://Qx31Sec@example.com/", "see https://exa_mple.com/Qx31Sec",
        "see https://example.com/a;jsessionid=Qx31Sec", "see https://example.com/a#access_token=Qx31Sec",
        "see https://example.com/a?page=2&token=Qx31Sec", "see https://example.com/a?page=Qx31Sec", "see https://example.com/Qx31Sec?",
        "see https://example.com/a:Qx31Sec", "see https://example.com/pass word Qx31Sec",
        "see https://example.com/pwd/Qx31Sec", "(https://example.com/a)?Qx31Sec", "[docs](https://example.com/a)#Qx31Sec",
        "see https://example.com/a>?Qx31Sec", "see https://example.com/a]#Qx31Sec", "see https://example.com/a}?Qx31Sec",
        "see https://example.com/a).Qx31Sec", "see https://example.com/a)#Qx31Sec tail", "see https://example.com/a!?Qx31Sec",
    ]

    /// Every place the review's inputs are read: the seven of ``RedactionWrittenURLTests/places(_:)``
    /// and the six of ``RedactionCutRuleTests/everyPath(_:)``.
    static func outputs(_ line: String) -> [(String, String)] {
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["user", "note", "page", "q"], allowedQueryParameters: ["page", "q"])
        let json = try! JSONSerialization.data(withJSONObject: ["note": line])
        let unprefixed = line.hasPrefix("see ") ? String(line.dropFirst(4)) : line
        return RedactionWrittenURLTests.places(unprefixed) + RedactionCutRuleTests.everyPath(line).map { ($0.path, $0.output) } + [
            ("allowed keys", allowing.redact(line)),
            ("JSON string, allowed keys", allowing.redact(body: json, contentType: "application/json")),
        ]
    }

    @Test("the review's inputs hide their secret in every place", arguments: reviewInputs)
    func reviewInputsAreHidden(input: String) {
        for (place, output) in Self.outputs(input) {
            #expect(!output.contains(Self.secret), "\(place): \(input.debugDescription) -> \(output.debugDescription)")
        }
    }

    static let urls = [
        "https://example.com/a", "https://example.com", "http://10.0.0.1/health", "myapp://callback/x", "https://example.com/it",
        "https://x.example/v1/items/42",
    ]
    /// What may come right after a URL and make it not clean.
    static let followers = [
        "'", "\"", "`", ">", "<", "]", "}", "?", "#", ";", ":", "=", "&", "|", "~", "*", "^", "{", "[", "\\", ").", "..", ".,", ",.",
        "!?", "!!", ".'", ")'", ".\"", ",x", "!x", ")x", "'s", "?.", ";.", ":.",
    ]

    @Test("a URL followed by anything but white space or one mark that ends a sentence cuts the text where it starts", arguments: followers)
    func followersCut(follower: String) {
        // Dots glued to more text are part of the URL's last segment (`/a..b`).
        let glues = follower == ".." ? ["#", "?", ";", " ", "\n"] : ["", "#", "?", ";", " ", "\n"]
        for url in Self.urls {
            for glue in glues {
                let line = "see " + url + follower + glue + Self.secret + " tail"
                #expect(SensitiveDataRedactor().redact(line) == "see [redacted]", "\(line.debugDescription)")
                for (place, output) in Self.outputs(line) {
                    #expect(!output.contains(Self.secret), "\(place): \(line.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    @Test("a URL followed by white space, a line break, the end of the text or one mark that ends a sentence keeps the text")
    func cleanEnds() {
        let redactor = SensitiveDataRedactor()
        var ends = ["", " tail", "\ntail", "\r\ntail", "\ttail"]
        for mark in Self.sentenceEnds { ends += [mark, mark + " tail", mark + "\ntail"] }
        for url in Self.urls {
            for end in ends {
                let line = "see " + url + end
                #expect(redactor.redact(line) == line, "\(line.debugDescription)")
            }
        }
    }

    /// URLs with the secret after a character that may end them, and clean ones.
    static func differentialURLs() -> [String] {
        var urls: [String] = []
        for url in Self.urls {
            for follower in ["'", ">", "`", "\"", ")", ".", "!", ",", "]", "}"] {
                for glue in ["#", "?", ";", "?x=", "#a=", ";a="] { urls.append(url + follower + glue + Self.secret) }
            }
            urls += [url, url + "/" + Self.secret, url + "#" + Self.secret, url + "?q=" + Self.secret, url + ";s=" + Self.secret]
        }
        return urls
    }

    @Test("free text never shows more of a URL than redact(url:) does, and shows a clean URL as it does")
    func differentialWithRedactURL() {
        let redactor = SensitiveDataRedactor()
        var compared = 0
        for written in Self.differentialURLs() {
            guard let url = URL(string: written) else { continue }
            compared += 1
            let structured = redactor.redact(url: url)
            let free = redactor.redact("see " + written)
            if !structured.contains(Self.secret) {
                #expect(!free.contains(Self.secret), "\(written.debugDescription): redact(url:) -> \(structured.debugDescription), text -> \(free.debugDescription)")
            }
            // Free text either cuts the URL where it starts or shows it as redact(url:) writes it.
            #expect(free == "see [redacted]" || free == "see " + structured, "\(written.debugDescription): \(structured.debugDescription) / \(free.debugDescription)")
        }
        #expect(compared > 300)
    }

}
