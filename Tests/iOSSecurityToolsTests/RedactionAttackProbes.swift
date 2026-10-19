import Foundation
@testable import iOSSecurityTools

// The adversarial probe set written against the first fixes after 2.0.0, before this redesign:
// every probe hides a unique secret behind one trick. 127 of the 386 got their secret past the
// redactor then.

extension AttackProbes {
    // swiftlint:disable:next function_body_length
    static func addNamesSeparatorsAndValues(to b: AttackProbeBuilder) {
        let json = Optional("application/json")
        let form = Optional("application/x-www-form-urlencoded")
        let mp = Optional("multipart/form-data; boundary=XyZ")

        // MARK: 1. Confusable names (free text, `=`)
        let confusables: [String] = [
            "p\u{0430}ssword", "\u{0440}assword", "passw\u{043E}rd", "pa\u{0455}\u{0455}word", "t\u{03BF}ken",
            "\u{03C1}assw\u{03BF}rd", "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}",
            "\u{1D5C9}\u{1D5BA}\u{1D5CC}\u{1D5CC}", "\u{24DF}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3}",
            "\u{24C5}\u{24B6}\u{24C8}\u{24C8}\u{24CC}\u{24C4}\u{24C7}\u{24B9}",
            "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}", "\u{1D18}\u{1D00}ss\u{1D21}\u{1D0F}\u{0280}\u{1D05}",
            "AP\u{0130}_KEY", "\u{0131}d_token", "\u{2170}d_token", "pass\u{2010}word", "pass\u{2212}word", "pass\u{FF3F}word",
            "\u{13E2}assword", "\u{0440}\u{0430}\u{0455}\u{0455}\u{051D}\u{043E}\u{0433}d", "\u{1D52D}\u{1D51E}\u{1D530}\u{1D530}",
            "\u{1D561}\u{1D552}\u{1D564}\u{1D564}", "\u{1D699}\u{1D68A}\u{1D69C}\u{1D69C}", "\u{24AB}\u{249C}\u{24AE}\u{24AE}",
            "\u{1D56}\u{1D43}\u{02E2}\u{02E2}\u{02B7}\u{1D52}\u{02B3}\u{1D48}", "\u{202E}drowssap", "\u{2066}password\u{2069}",
        ]
        for name in confusables { b.text("confusable-name", "\(name)={S} next") }
        // Same names as JSON keys, form names, multipart names, XML elements, YAML.
        for name in confusables.prefix(8) { b.text("confusable-json", "{\"\(name)\":\"{S}\",\"u\":1}") }
        for name in ["p\u{0430}ssword", "\u{FF50}\u{FF41}\u{FF53}\u{FF53}", "pass\u{200B}word"] {
            let encoded = name.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? name
            b.body("confusable-form", "a=1&\(encoded)={S}", form)
            b.body("confusable-multipart",
                   "--XyZ\r\nContent-Disposition: form-data; name=\"\(name)\"\r\n\r\n{S}\r\n--XyZ--", mp)
            b.text("confusable-xml", "<\(name)>{S}</\(name)>")
            b.text("confusable-yaml", "config:\n  \(name): {S}\n  user: bob")
        }

        // MARK: 2. Invisible / format characters (Cf, ZWJ, ZWNJ, soft hyphen, tags, fillers)
        let invisibles: [String] = ["\u{200D}", "\u{200C}", "\u{00AD}", "\u{2060}", "\u{FEFF}", "\u{200E}", "\u{034F}",
                                    "\u{E0077}", "\u{115F}", "\u{3164}", "\u{2800}", "\u{180E}", "\u{17B4}", "\u{1D173}"]
        for mark in invisibles { b.text("invisible-in-name", "pass\(mark)word={S} next") }
        b.text("invisible-around-sep", "password\u{200B}=\u{200B}{S} next")
        b.text("invisible-around-sep", "password\u{FEFF}:\u{FEFF} {S} next")
        b.text("invisible-before-value", "token=\u{2060}\u{200D}{S} next")
        b.text("invisible-bearer", "auth: Bea\u{200B}rer \u{00AD}{S}{S2}")
        b.text("invisible-key-split", "api\u{200C}_\u{200D}key: {S}")

        // MARK: 3. Combining marks
        for mark in ["\u{0301}", "\u{0336}", "\u{0338}", "\u{20DD}", "\u{0903}"] {
            b.text("combining-in-name", "pa\(mark)ssword={S} next")
        }
        b.text("combining-after-sep", "password=\u{0338}{S} next")
        b.text("combining-on-sep", "password=\u{0338} {S} next")
        b.text("combining-on-quote", "password=\"\u{0301}{S}\" next")
        b.text("combining-on-json-quote", "{\"password\u{0301}\":\"{S}\"}")

        // MARK: 4. Escapes (\u, %, &#) in names and separators
        let escapedSeps = ["\\u003D", "\\u003d", "\\x3D", "\\x3a", "%3D", "%3d", "%253D", "%25253A", "&#61;", "&#0061;",
                           "&#x3D;", "&#X3d;", "&equals;", "&colon;", "&#58;"]
        for sep in escapedSeps { b.text("escaped-separator", "password\(sep){S} next") }
        for sep in ["&#61", "\\u{3D}", "\\075", "%u003D", "&amp;#61;", "\\N{EQUALS SIGN}", "%EF%BC%9D"] {
            b.text("escaped-separator-unlisted", "password\(sep){S} next")
        }
        let escapedNames = ["\\u0070assword", "pass\\x77ord", "%70assword", "&#112;assword", "&#x70;assword", "pass&#119;ord",
                            "pass%2577ord", "\\u{70}assword", "pass\\\\u0077ord"]
        for name in escapedNames { b.text("escaped-name", "\(name)={S} next") }
        b.text("escaped-json-name", "{\"\\u0070\\u0061\\u0073\\u0073\\u0077\\u006f\\u0072\\u0064\":\"{S}\"}")
        b.text("escaped-json-name", "{\"\\ud835\\udc29assword\":\"{S}\"}")
        b.text("escaped-json-name", "{\"pass\\/word\":\"{S}\"}")
        b.text("escaped-json-name", "{\"password\\u0000\":\"{S}\"}")
        b.text("escaped-json-value", "{\"msg\":\"password\\u003d{S}\"}")
        b.text("escaped-json-value", "{\"msg\":\"password=\\u0020{S}\"}")

        // MARK: 5. Separators
        let separators = [":=", "==", "=>", " = ", " : ", "::=", "?=", "!=", "+=", "<=", ">=", "= =", "\u{2254}", "\u{2236}",
                          "\u{FF1D}", "\u{FF1A}", "\u{FE13}", "\u{2A74}", "\u{2A75}", "\u{FE55}", "\u{FE66}",
                          "\u{A789}", "\u{02F8}", "\u{0589}", "\u{05C3}", "\u{205A}", "\u{1804}", "\u{2255}", "\u{2982}",
                          "\u{1400}", "\u{2E40}", "\u{30A0}", "\u{2550}", "\u{FE30}"]
        for sep in separators { b.text("separator", "password\(sep){S} next") }
        // Look-alike separators that are letters or spacing marks, not punctuation or symbols.
        for sep in ["\u{02D0}", "\u{A4FD}", "\u{01C2}", "\u{A60C}", "\u{0903}", "\u{02BA}"] {
            b.text("separator-letter-lookalike", "password\(sep){S} next")
        }
        // Look-alike separators after names that are not plain.
        b.text("lookalike-sep-mixed-name", "p\u{0430}ssword\u{A789}{S} next")
        b.text("lookalike-sep-mixed-name", "\u{0440}assword\u{2550}{S} next")
        b.text("lookalike-sep-mixed-name", "t\u{043E}ken\u{0589} {S} next")
        b.text("lookalike-sep-punct-name", "pass.word\u{A789}{S} next")
        b.text("lookalike-sep-punct-name", "p@ssword\u{A789}{S} next")
        b.text("lookalike-sep-punct-name", "user[password]\u{A789}{S} next")
        b.text("lookalike-sep-punct-name", "pass%77ord\u{A789}{S} next")
        b.text("lookalike-sep-split-name", "pass word\u{A789}{S} next")
        b.text("lookalike-sep-allscript", "\u{0440}\u{0430}\u{0455}\u{0455}\u{051D}\u{043E}\u{0433}\u{0501}\u{A789}{S} next")
        b.text("separator-pipe", "| password | {S} |")
        b.text("separator-arrow", "password -> {S}")
        b.text("separator-tab", "password\t{S}")

        // MARK: 6. Values that start or are wrapped oddly
        b.text("value-shape", "password=,{S} next")
        b.text("value-shape", "password=;{S} next")
        b.text("value-shape", "password: &anchor {S}")
        b.text("value-shape", "password: ) {S}")
        b.text("value-shape", "password=`{S} {S2}` next")
        b.text("value-shape", "password=\u{201C}{S} {S2}\u{201D} next")
        b.text("value-shape", "password=\u{00AB}{S} {S2}\u{00BB} next")
        b.text("value-shape", "password=\"{S} {S2}\" next")
        b.text("value-shape", "password=\\'{S} {S2}\\' next")
        b.text("value-shape", "password=$'{S}\\x20{S2}' next")
        b.text("value-shape", "password=({S} {S2}) next")
        b.text("value-shape", "password=\"{S}\\\"{S2}\" next")
        b.text("value-shape", "password=Optional(\"{S}\") next")
        b.text("value-shape", "password: Swift.Optional<Swift.String>.some(\"{S}\")")

        // MARK: 7. Authorization schemes
        for scheme in ["Bearer", "Basic", "Digest", "Token", "Negotiate", "NTLM"] {
            b.text("auth-scheme-listed", "Authorization: \(scheme) {S}")
        }
        for scheme in ["DPoP", "GNAP", "Bot", "ApiKey", "SSWS", "Splunk", "AWS4-HMAC-SHA256", "OAuth", "Key", "Bearer\u{00A0}"] {
            b.text("auth-scheme-other", "Authorization: \(scheme) {S}")
        }
        b.text("auth-scheme-other", "Proxy-Authorization: DPoP {S}")
        b.text("auth-scheme-quoted", "Authorization: Bearer \"{S}{S2}\"")
        b.text("auth-scheme-confusable", "Authorization: B\u{0435}arer {S}{S2}")
        b.text("auth-scheme-folded", "Authorization: Bearer\r\n {S}{S2}")
        b.text("bearer-free", "sending Bearer {S}{S2} to api")
        b.text("bearer-free", "sending BEARER\u{3000}{S}{S2} to api")
        b.text("bearer-free", "sending B\u{0435}arer {S}{S2} to api")

        // MARK: 8. Repeated keys
        b.text("repeated", "{\"password\":\"a\",\"password\":\"{S}\"}")
        b.text("repeated", "{\"password\":\"a\",\"pass\\u0077ord\":\"{S}\"}")
        b.text("repeated", "password=a password={S} next")
        b.text("repeated", "password=password={S} next")
        b.text("repeated", "token: password: {S}")
        b.body("repeated", "password=a&password={S}&password=b", form)
        b.body("repeated",
               "--XyZ\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nbob\r\n--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S}\r\n--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{S2}\r\n--XyZ--", mp)
        b.body("repeated", "{\"a\":{\"token\":1},\"a\":{\"token\":\"{S}\"}}", json)

        // MARK: 9. Nesting and arrays
        b.text("nested", "{\"a\":[{\"b\":[{\"c\":{\"password\":[\"{S}\",{\"x\":\"{S2}\"}]}}]}]}")
        b.text("nested", "[[[[{\"api_key\":{\"v\":\"{S}\"}}]]]]")
        let deep = 300
        b.text("nested-deep", String(repeating: "[", count: deep) + "{\"password\":\"{S}\"}" + String(repeating: "]", count: deep))
        b.body("nested-deep", String(repeating: "[", count: deep) + "{\"password\":\"{S}\"}" + String(repeating: "]", count: deep), json)
        b.text("json-key-holds-field", "{\"https://api.example.com/login?password={S}\":200}")
        b.text("json-key-holds-field", "{\"requests\":{\"POST /auth token={S}\":3}}")
        b.body("json-key-holds-field", "{\"password={S}\":null}", json)
        b.text("json-key-holds-field", "{\"pass\\u0077ord={S}\":1}")
        b.raw("json-key-holds-detector", "{\"Authorization: Bearer abcdefgh1234567890\":1}", nil, secrets: ["abcdefgh1234567890"])
        b.raw("json-key-holds-detector", "{\"4111 1111 1111 1111\":1}", nil, secrets: ["4111 1111 1111 1111"])
        b.text("name-value-pairs", "{\"headers\":[{\"name\":\"X-Api-Key\",\"value\":\"{S}\"}]}")
        b.text("name-value-pairs", "{\"env\":[{\"name\":\"DB_PASSWORD\",\"value\":\"{S}\"}]}")
        b.text("name-value-pairs", "[[\"password\",\"{S}\"]]")
        b.text("json-array-next-string", "{\"lines\":[\"password:\",\"{S}\"]}")
    }
}
