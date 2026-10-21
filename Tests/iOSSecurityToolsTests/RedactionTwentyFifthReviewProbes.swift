import Foundation
@testable import iOSSecurityTools

/// The probes of the twenty-fifth review (`a-25`) that this release answers, numbered as the
/// review numbered them, and made the way the review made them: the one wildcard rule, probed
/// with every kind of character it names and with the decimal digits of other scripts.
enum TwentyFifthReviewProbes {
    static let review = "a-25"
    private static let json = "application/json"
    private static let form = "application/x-www-form-urlencoded"
    private static let plain = "text/plain"
    private static let multipartType = "multipart/form-data; boundary=B0und"

    /// Decimal digits of other scripts, without an ASCII form under compatibility decomposition:
    /// Myanmar, Devanagari, Bengali, Thai, Lao, NKo, Khmer, Mongolian, Gujarati, Tamil, Telugu,
    /// Kannada, Malayalam, Tibetan, Osmanya, Ol Chiki, Saurashtra, Adlam and two Arabic ones.
    static let nativeZeros: [String] = [
        "\u{1040}", "\u{0966}", "\u{09E6}", "\u{0E50}", "\u{0ED0}", "\u{07C0}", "\u{17E0}", "\u{1810}", "\u{0AE6}", "\u{0BE6}",
        "\u{0C66}", "\u{0CE6}", "\u{0D66}", "\u{0F20}", "\u{104A0}", "\u{1C50}", "\u{A8D0}", "\u{1E950}", "\u{0660}", "\u{06F0}",
    ]
    /// The other kinds the rule names: Ll, Lo, Lo (Han), Lo (Hangul), Mn, Mc, Me, Nl, No, No.
    static let otherWildcards: [String] = ["\u{0251}", "\u{01C0}", "\u{53E3}", "\u{3147}", "\u{0366}", "\u{0903}", "\u{20DD}", "\u{3007}", "\u{10107}", "\u{0BF0}"]

    /// Probes 1 to 273: a wildcard in place of a letter of a name or put in it, on every path,
    /// digits with an ASCII form (documented as read as that digit) and words that keep their
    /// value.
    static let wildcards: [ReviewProbe] = {
        var probes = Builder(firstID: 1)
        let names: [(String, Int)] = [("token", 1), ("password", 5), ("cookie", 1), ("otp", 0), ("session", 5), ("passcode", 5),
                                      ("pin", 1), ("secret", 3), ("api_key", 4), ("iban", 3), ("card", 1), ("credential", 3)]
        probes.section("n25-wild-nd-in-place")
        for (name, at) in names {
            for zero in nativeZeros.prefix(6) { probes.text("login \(replaced(name, at: at, with: zero)) {S}") }
        }
        probes.section("n25-wild-nd-all-scripts")
        for zero in nativeZeros { probes.text("INFO passw\(zero)rd {S} ok") }
        probes.section("n25-wild-nd-put-in")
        for (name, _) in names {
            for zero in ["\u{1040}", "\u{0966}"] { probes.text("login \(inserted(name, at: 2, zero)) {S}") }
        }
        probes.section("n25-wild-nd-paths")
        for word in ["t\u{1040}ken", "passw\u{0966}rd", "c\u{0E50}okie"] { paths(word, into: &probes) }
        probes.section("n25-wild-other-in-place")
        let letterNames: [(String, Int)] = [("token", 1), ("password", 5), ("pin", 1), ("secret", 3), ("cookie", 2), ("otp", 0),
                                            ("session", 5), ("api_key", 5)]
        for (name, at) in letterNames {
            for wildcard in otherWildcards { probes.text("login \(replaced(name, at: at, with: wildcard)) {S}") }
        }
        probes.section("n25-wild-other-paths")
        for word in ["t\u{0366}ken", "passw\u{3007}rd", "p\u{10107}n", "s\u{0903}cret"] {
            let encoded = word.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
            probes.body(#"{"msg":"login \#(word) {S}"}"#, json)
            probes.body("note=login+\(encoded)+{S}", form)
            probes.body(multipart(["Content-Disposition: form-data; name=\"note\"\r\n\r\nlogin \(word) {S}"]), multipartType)
            probes.url("https://x.example/a?q=\(encoded)+{S}", allowing: ["q"])
            probes.body(#"{"title":"\#(word)","value":"{S}"}"#, json)
            probes.body(#"["a","\#(word)","{S}"]"#, json)
            probes.url("https://x.example/v1/\(encoded)/{S}")
        }
        probes.section("n25-wild-ascii-form")
        for zero in ["0", "\u{FF10}", "\u{2070}", "\u{2080}", "\u{1D7CE}", "\u{1FBF0}", "\u{24EA}"] {
            probes.text("login passw\(zero)rd {S}", claim: "D")
        }
        probes.text("login pɑsswoʀd {S}", claim: "D")
        probes.text("login tɵkɛn {S}", claim: "D")
        probes.section("n25-wild-control")
        for text in ["café au lait {S}", "naïve résumé {S}", "bjørn {S}", "pinto beans {S}"] { probes.text(text, claim: "K") }
        return probes.probes
    }()

    /// Probe 850, a query value on the allowlist, and 897, a digit of another script at the end
    /// of 300 KB of text.
    static let followUps: [ReviewProbe] = {
        var probes = Builder(firstID: 850)
        probes.section("n25-url-query")
        probes.url("https://x.example/a?q=t%E1%81%80ken+{S}", allowing: ["q"])
        var big = Builder(firstID: 897)
        big.section("n25-big")
        big.text(String(repeating: "ok ", count: 100_000) + "t\u{1040}ken {S}")
        return probes.probes + big.probes
    }()

    private static func paths(_ word: String, into probes: inout Builder) {
        let encoded = word.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        probes.body(#"{"msg":"login \#(word) {S}"}"#, json)
        probes.body("note=login+\(encoded)+{S}", form)
        probes.body(multipart(["Content-Disposition: form-data; name=\"note\"\r\n\r\nlogin \(word) {S}"]), multipartType)
        probes.body("login \(word) {S}", plain)
        probes.url("https://x.example/a?q=\(encoded)+{S}", allowing: ["q"])
        probes.body(#"{"title":"\#(word)","value":"{S}"}"#, json)
        probes.body(#"{"ParameterKey":"\#(word)","ParameterValue":"{S}"}"#, json)
        probes.body(#"["a","\#(word)","{S}"]"#, json)
        probes.body("title=\(encoded)&value={S}", form)
        probes.body(multipart(["Content-Disposition: form-data; name=\"title\"\r\n\r\n\(word)",
                               "Content-Disposition: form-data; name=\"value\"\r\n\r\n{S}"]), multipartType)
        probes.text("status=200 \"\(word)\" {S}")
        probes.text("status=200 [\(word)] {S}")
    }

    private static func replaced(_ name: String, at index: Int, with wildcard: String) -> String {
        var scalars = name.unicodeScalars.map { String($0) }
        scalars[index] = wildcard
        return scalars.joined()
    }

    private static func inserted(_ name: String, at index: Int, _ wildcard: String) -> String {
        var scalars = name.unicodeScalars.map { String($0) }
        scalars.insert(wildcard, at: index)
        return scalars.joined()
    }

    private static func multipart(_ parts: [String]) -> String {
        parts.map { "--B0und\r\n" + $0 + "\r\n" }.joined() + "--B0und--"
    }

    /// Numbers the probes in order, as the review did, and writes the marker of each into it.
    private struct Builder {
        private(set) var probes: [ReviewProbe] = []
        private var nextID: Int
        private var category = ""

        init(firstID: Int) {
            nextID = firstID
        }

        mutating func section(_ name: String) { category = name }

        mutating func text(_ input: String, claim: String = "C") {
            add("text", input, type: nil, keys: nil, claim: claim)
        }

        mutating func body(_ input: String, _ type: String) {
            add("body", input, type: type, keys: nil, claim: "C")
        }

        mutating func url(_ input: String, allowing keys: [String] = []) {
            add("url", input, type: nil, keys: keys, claim: "C")
        }

        private mutating func add(_ kind: String, _ input: String, type: String?, keys: [String]?, claim: String) {
            let marker = "Qz\(String(format: "%03d", nextID))Wk5m"
            probes.append(ReviewProbe(
                review: review, id: nextID, category: category, claim: claim, kind: kind, keys: keys, queryKeys: nil, type: type,
                input: input.replacingOccurrences(of: "{S}", with: marker), repeat: nil, data: nil, secret: marker,
                digits: false, width: 6
            ))
            nextID += 1
        }
    }
}
