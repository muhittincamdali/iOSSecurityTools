import Foundation

// swiftlint:disable line_length
extension EleventhReviewProbeSet {
    // secret names in free text with two or more letters that have no ASCII form (Latin
    // small capitals, ɑ, ɛ, ɵ, ø, ı, ŧ, ...). The guide reads such a letter "as any one letter" and
    // names only names written in them "throughout" as not found, so a name with two of eight such
    // letters is claimed hidden.

    static let noASCIIForm: [Character: [String]] = [
        "a": ["\u{0251}", "\u{1D00}"], "c": ["\u{1D04}", "\u{1D04}"], "d": ["\u{1D05}", "\u{0111}"], "e": ["\u{025B}", "\u{1D07}"],
        "i": ["\u{0131}", "\u{026A}"], "k": ["\u{1D0B}", "\u{0138}"], "n": ["\u{0274}", "\u{0274}"], "o": ["\u{0275}", "\u{00F8}"],
        "p": ["\u{1D18}", "\u{01A5}"], "r": ["\u{0280}", "\u{027C}"], "s": ["\u{A731}", "\u{0282}"], "t": ["\u{1D1B}", "\u{0167}"],
        "w": ["\u{1D21}", "\u{1D21}"], "y": ["\u{028F}", "\u{028F}"], "h": ["\u{029C}", "\u{0127}"], "g": ["\u{0262}", "\u{0261}"],
        "u": ["\u{1D1C}", "\u{0289}"], "l": ["\u{029F}", "\u{0142}"], "v": ["\u{1D20}", "\u{1D20}"], "b": ["\u{0299}", "\u{0180}"],
    ]

    /// `name` with the letters at `positions` written as letters without an ASCII form.
    func wild(_ name: String, _ positions: [Int], choice: Int = 0) -> String {
        var chars = Array(name).map(String.init)
        for k in positions where k < chars.count {
            if let options = Self.noASCIIForm[Character(chars[k].lowercased())] { chars[k] = options[choice % options.count] }
        }
        return chars.joined()
    }

    func addWild() {
        section("n10-wild-two-letters")
        let long = ["password", "passphrase", "passcode", "secret", "credential", "authorization", "signature", "client_secret",
                    "refresh_token", "private_key", "access_token"]
        for name in long {
            let n = name.count
            p("\(wild(name, [1, n - 2])) {S}")
            p("INFO login \(wild(name, [2, n - 3], choice: 1)) {S} ok")
        }
        p("\(wild("session", [1, 4])) {S}")
        p("\(wild("cookie", [1, 4])) {S}")
        p("\(wild("token", [1, 3])) {S}")
        p("\(wild("api_key", [0, 5])) {S}")
        p("\(wild("authorization", [0, 4, 9])) {S}")              // three letters of thirteen
        p("\(wild("credentials", [2, 5, 8])) {S}")
        p("\(wild("client_secret", [1, 8, 11])) {S}")

        section("n10-wild-short", "X")
        p("\(wild("pin", [0, 1])) {S}")
        p("\(wild("otp", [0, 2])) {S}")
        p("\(wild("cvv", [0, 1])) {S}")
        p("\(wild("key", [0, 1])) {S}")
        p("\(wild("pwd", [0, 2])) {S}")
        p("p\u{0251}\u{0251}sword {S}")                                  // one read as a letter, one as none
        p("pass\u{A78F}wo\u{A78F}rd {S}")                                // two read as none

        section("n10-wild-paths")
        p("{\"msg\":\"\(wild("password", [1, 6])) {S}\"}", json)
        p("{\"msg\":\"\(wild("secret", [1, 4])) {S}\"}", json)
        p("note=\(wild("password", [1, 6]).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)+{S}", form)
        p("\(wild("token", [1, 3])) {S}", plain)
        p(multipart(["Content-Disposition: form-data; name=\"note\"\r\n\r\n\(wild("passcode", [1, 5])) {S}"]), mpType())
        p("https://x.example/a?q=\(wild("password", [1, 6]).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)+{S}", .urlAllowing(["q"]))
        p("https://x.example/v1/\(wild("password", [1, 6]).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)/{S}", .url)
        p("<key>\(wild("password", [1, 6]))</key><string>{S}</string>")
        p("\(wild("password", [1, 6])): {S}")                           // with a separator: control
        p("name=\"\(wild("password", [1, 6]))\" {S}")
    }

    // names held by fields in JSON (the newest rule), disguised and moved around: case, order,
    // repetition, escapes, invisibles, marks, confusables, pairs, patches and real-world shapes.

    func addHeld() {
        section("n10-held-json-disguise")
        p("{\"LABEL\":\"\u{015E}ifre\",\"value\":\"{S}\"}", json)
        p("{\"Type\":\"\u{24DF}\u{24D8}\u{24DD}\",\"value\":\"{S}\"}", json)
        p("{\"value\":\"{S}\",\"label\":\"\u{015E}ifre\"}", json)                       // value before the name
        p("{\"label\":\"\\u015eifre\",\"value\":\"{S}\"}", json)                        // escaped name
        p("{\"label\":\"Pass\\u0077ord\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"P\u{430}ssword\",\"value\":\"{S}\"}", json)                     // Cyrillic a
        p("{\"label\":\"Pass\u{AD}word\",\"value\":\"{S}\"}", json)                     // soft hyphen
        p("{\"label\":\"Pass\u{200D}word\",\"value\":\"{S}\"}", json)                   // ZWJ
        p("{\"label\":\"Pass\u{200C}word\",\"value\":\"{S}\"}", json)                   // ZWNJ
        p("{\"label\":\"Pas\u{301}sword\",\"value\":\"{S}\"}", json)                    // combining acute
        p("{\"label\":\"\u{FF30}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\u{1D40F}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\u{24C5}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3}\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\(wild("password", [1, 6]))\",\"value\":\"{S}\"}", json)         // letters without ASCII form
        p("{\"label\":\"pass&#119;ord\",\"input\":\"{S}\"}", json)
        p("{\"label\":\"pass%77ord\",\"input\":\"{S}\"}", json)
        p("{\"label\":\"Password\u{2028}\",\"value\":\"{S}\"}", json)                   // line separator in the name
        p("{\"label\":\" Password \",\"value\":\"{S}\"}", json)
        p("{\"label\":\"PASS-WORD\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\u{1F511} Key\",\"value\":\"{S}\"}", json)
        p("{\"lab\\u0065l\":\"\u{015E}ifre\",\"value\":\"{S}\"}", json)                 // escaped field name

        section("n10-held-json-structure")
        p("{\"label\":\"\u{015E}ifre\",\"value\":{\"inner\":\"{S}\"}}", json)
        p("{\"label\":\"\u{015E}ifre\",\"value\":[\"{S}\"]}", json)
        p("{\"label\":\"\u{015E}ifre\",\"value\":48291377}", json, secret: "48291377", width: 8)
        p("{\"label\":\"\u{015E}ifre\",\"label\":\"status\",\"value\":\"{S}\"}", json)   // repeated name
        p("{\"label\":\"status\",\"label\":\"\u{015E}ifre\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"status\",\"Label\":\"password\",\"value\":\"{S}\"}", json)
        p("{\"a\":{\"b\":[{\"c\":[{\"label\":\"PIN\",\"value\":\"{S}\"}]}]}}", json)
        p("[[[[{\"name\":\"api_key\",\"value\":\"{S}\"}]]]]", json)
        p("{\"label\":{\"en\":\"Password\",\"tr\":\"\u{015E}ifre\"},\"value\":\"{S}\"}", json)
        p("{\"field\":{\"type\":\"password\"},\"value\":\"{S}\"}", json)
        p("{\"label\":null,\"x\":1,\"value\":\"{S}\",\"name\":\"pin\"}", json)
        p("[{\"label\":\"\u{015E}ifre\"},{\"value\":\"{S}\"}]", json, claim: "D")         // two objects

        section("n10-held-json-pairs")
        p("[[\"x-api-key\",\"{S}\",\"extra\"]]", json)
        p("[[\"\u{015E}ifre\",\"{S}\"]]", json)
        p("[\"\u{015E}ifre\",\"{S}\"]", json)
        p("[[\"\\u24df\\u24d8\\u24dd\",\"{S}\"]]", json)
        p("[[\"Pass\u{200B}word\",\"{S}\"]]", json)
        p("[[\" password \",\"{S}\"]]", json)
        p("[[\"password\",{\"v\":\"{S}\"}]]", json)
        p("[[\"password\",[\"{S}\"]]]", json)
        p("[\"note\",\"password\",\"{S}\"]", json)
        p("[\"note\",\"PIN code\",\"{S}\",\"x\"]", json)
        p("[[\"Authorization\",\"Basic {S}\"],[\"Accept\",\"*/*\"]]", json)
        p("{\"headers\":[[\"Cookie\",\"a=1; sid={S}\"]]}", json)
        p("[[\"\u{015E}ifre\",\"{S}\",\"x\"]]", json, claim: "X")                        // three elements
        p("[[\"\u{015E}ifre\"],[\"{S}\"]]", json, claim: "D")

        section("n10-held-json-patch")
        p("{\"op\":\"replace\",\"path\":\"/user/pass\\u0077ord\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"/user/pass~1word\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"/user/PASSWORD\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"/user/password/\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"//password\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"add\",\"path\":\"/credentials/-\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"password\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"urn:ietf:params:scim:schemas:core:2.0:User:password\",\"value\":\"{S}\"}", json)
        p("{\"Operations\":[{\"op\":\"replace\",\"value\":{\"password\":\"{S}\"}}]}", json)
        p("{\"op\":\"test\",\"path\":\"/pin\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"Path\":\"/password\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"copy\",\"from\":\"/password\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"/user/p\u{430}ssword\",\"value\":\"{S}\"}", json)
        p("{\"op\":\"replace\",\"path\":\"/user/\u{15E}ifre\",\"value\":\"{S}\"}", json)
        p("[{\"op\":\"replace\",\"path\":\"/status\",\"value\":\"ok\"},{\"op\":\"replace\",\"path\":\"/secret\",\"value\":\"{S}\"}]", json)

        section("n10-held-json-real")
        p("{\"ParameterKey\":\"DB_PASS\",\"ParameterValue\":\"{S}\"}", json)
        p("{\"Name\":\"/prod/db/password\",\"Value\":\"{S}\",\"Type\":\"SecureString\"}", json)
        p("{\"env\":[{\"name\":\"API_TOKEN\",\"value\":\"{S}\"}]}", json)
        p("{\"key\":\"x-api-key\",\"value\":\"{S}\",\"type\":\"text\"}", json)
        p("{\"cookies\":[{\"name\":\"sessionid\",\"value\":\"{S}\"}]}", json)
        p("{\"queryString\":[{\"name\":\"access_token\",\"value\":\"{S}\"}]}", json)
        p("{\"postData\":{\"params\":[{\"name\":\"password\",\"value\":\"{S}\"}]}}", json)
        p("{\"headers\":[{\"name\":\"X-Hub-Signature-256\",\"value\":\"sha256={S}\"}]}", json)
        p("{\"variables\":[{\"key\":\"DB_PASSWORD\",\"value\":\"{S}\",\"masked\":true}]}", json)
        p("{\"Parameters\":[{\"Name\":\"MasterUserPassword\",\"Value\":\"{S}\"}]}", json)
        p("{\"attributes\":[{\"Name\":\"custom:pin\",\"Value\":\"{S}\"}]}", json)
        p("{\"UserAttributes\":[{\"Name\":\"custom:\u{015F}ifre\",\"Value\":\"{S}\"}]}", json)
        p("{\"fields\":[{\"id\":\"cc-number\",\"answer\":\"{S}\"}]}", json, claim: "X")
        p("{\"name\":\"password\",\"k\":\"{S}\"}", json, claim: "D")                      // the name of a pair stays
        p("{\"name\":\"_gh_sess\",\"value\":\"{S}\"}", json, claim: "D")                  // unknown cookie name
    }
}
