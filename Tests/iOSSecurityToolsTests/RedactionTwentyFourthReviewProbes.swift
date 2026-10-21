import Foundation
@testable import iOSSecurityTools

/// The probes of the twenty-fourth review (`a-24`) that this release answers, numbered as the
/// review numbered them, and made the way the review made them.
enum TwentyFourthReviewProbes {
    static let review = "a-24"
    private static let json = "application/json"
    private static let form = "application/x-www-form-urlencoded"
    private static let multipartType = "multipart/form-data; boundary=B0und"

    /// Names written as values beside fields that hold no name, with line breaks, on every
    /// structured path (probes 1 to 45 and 1009 to 1054).
    static let names: [ReviewProbe] = {
        var probes = Builder(firstID: 1)
        probes.section("n24-held-linebreak")
        let names = ["DbPassword\\n", "DbPassword\\r\\n", "\\nDbPassword", "Db\\nPassword", "DbPassword\\r", "pin\\n",
                     "api_key\\n", "\\r\\ntoken", "DbPassword\\u2028", "DbPassword\\u0085", "DbPassword\\u000b",
                     "DbPassword\\f", "DbPassword\\t", " DbPassword ", "\\tpin\\t", "DbPassword\\u00a0"]
        for name in names {
            probes.body(#"{"ParameterKey":"\#(name)","ParameterValue":"{S}"}"#, json)
            probes.body(#"{"OptionName":"\#(name)","Value":"{S}"}"#, json)
        }
        probes.body(#"{"Parameters":[{"ParameterKey":"DbPassword\n","ParameterValue":"{S}"}]}"#, json)
        probes.body(#"[{"attribute":"pin\n","value":"{S}"}]"#, json)
        probes.body(#"{"settings":{"OptionName":"\nclient_secret","Value":"{S}"}}"#, json)
        probes.section("n24-held-linebreak-paths")
        probes.body("ParameterKey=DbPassword%0A&ParameterValue={S}", form)
        probes.body("ParameterKey=DbPassword%0D%0A&ParameterValue={S}", form)
        probes.body("ParameterKey=%0Apin&ParameterValue={S}", form)
        probes.body("OptionName=Db%0APassword&Value={S}", form)
        probes.body(multipart(["name=\"ParameterKey\"\r\n\r\nDbPassword\n", "name=\"ParameterValue\"\r\n\r\n{S}"]), multipartType)
        probes.body(multipart(["name=\"ParameterKey\"\r\n\r\n\npin", "name=\"ParameterValue\"\r\n\r\n{S}"]), multipartType)
        probes.url("https://x.example/a?ParameterKey=DbPassword%0A&ParameterValue={S}", allowing: ["ParameterKey", "ParameterValue"])
        probes.url("https://x.example/a?ParameterKey=%0Apin&ParameterValue={S}", allowing: ["ParameterKey", "ParameterValue"])
        probes.text(#"log {"ParameterKey":"DbPassword\n","ParameterValue":"{S}"}"#)
        probes.body(#"{"msg":"{\"ParameterKey\":\"DbPassword\\n\",\"ParameterValue\":\"{S}\"}"}"#, json)

        probes = Builder(firstID: 1009, probes: probes.probes)
        probes.section("n24f-held-linebreak")
        let fields = [("ParameterKey", "ParameterValue"), ("OptionName", "Value"), ("attribute", "value"), ("Parameter", "Value"),
                      ("setting", "value"), ("env", "val"), ("SecretName", "SecretValue")]
        for (field, valueField) in fields {
            for name in ["password\\n", "\\r\\npin", "api\\nkey", "client_secret\\r", "token\\n\\n"] {
                probes.body(#"{"\#(field)":"\#(name)","\#(valueField)":"{S}"}"#, json)
            }
        }
        probes.body(#"[{"ParameterKey":"DbUser","ParameterValue":"bob"},{"ParameterKey":"DbPassword\n","ParameterValue":"{S}"}]"#, json)
        probes.body(#"{"Parameters":[{"ParameterKey":"DbPassword\r\n","ParameterValue":"{S}","UsePreviousValue":false}]}"#, json)
        probes.body(#"{"OptionSettings":[{"Namespace":"aws:rds","OptionName":"\nDBPassword","Value":"{S}"}]}"#, json)
        probes.body("OptionName=DBPassword%0D&Value={S}", form)
        probes.body("OptionName=%0D%0Apin&Value={S}", form)
        probes.body(multipart(["name=\"OptionName\"\r\n\r\nDBPassword\r", "name=\"Value\"\r\n\r\n{S}"]), multipartType)
        probes.url("https://x.example/a?OptionName=DBPassword%0A&Value={S}", allowing: ["OptionName", "Value"])
        probes.text(#"note {"OptionName":"pin\n","Value":"{S}"}"#)
        probes.body(#"{"data":"{\"OptionName\":\"pin\\n\",\"Value\":\"{S}\"}"}"#, json)
        // Controls: a sentence beside the field keeps the value, a plain name hides it.
        probes.body(#"{"OptionName":"Error: pin","Value":"{S}"}"#, json, claim: "K")
        probes.body(#"{"OptionName":"DBPassword","Value":"{S}"}"#, json)
        return probes.probes
    }()

    /// Card numbers, IBANs, email addresses and tokens cut by a control character or a line
    /// separator at every place, on every path (probes 909 to 1008).
    static let findings: [ReviewProbe] = {
        var probes = Builder(firstID: 909)
        probes.section("n24f-card-cut")
        let card = "4111111111111111"
        let groups = ["4111", "1111", "1111", "1111"]
        let cuts = ["\u{000B}", "\u{000C}", "\u{0085}", "\u{2028}", "\u{2029}", "\u{001C}", "\u{001F}", "\u{007F}", "\u{001B}",
                    "\u{0007}", "\u{0080}", "\u{009F}", "\u{0000}"]
        for cut in cuts {
            for position in 1...3 {
                let text = groups[0..<position].joined(separator: " ") + cut + groups[position...].joined(separator: " ")
                probes.text("paid with \(text) ok", secret: card, digits: true)
            }
        }
        for position in 1...3 {
            let text = groups[0..<position].joined() + "\u{000B}" + groups[position...].joined()
            let encoded = text.replacingOccurrences(of: "\u{000B}", with: "%0B")
            probes.text("paid with \(text) ok", secret: card, digits: true)
            probes.body(#"{"note":"\#(text.replacingOccurrences(of: "\u{000B}", with: "\\u000b"))"}"#, json, secret: card, digits: true)
            probes.body("note=\(encoded)", form, secret: card, digits: true)
            probes.body("paid with \(text) ok", "text/plain", secret: card, digits: true)
            probes.body(multipart(["name=\"note\"\r\n\r\n\(text)"]), multipartType, secret: card, digits: true)
            probes.url("https://x.example/v1/\(encoded)/x", secret: card, digits: true)
            probes.url("https://x.example/a?q=\(encoded)", allowing: ["q"], secret: card, digits: true)
        }
        probes.text("paid with 4111 1111 1111\n1111 ok", secret: card, digits: true, claim: "X")
        probes.text("paid with 4111 1111 1111\r\n1111 ok", secret: card, digits: true, claim: "X")

        probes.section("n24f-iban-cut")
        let iban = "89370400440532013000"
        for cut in ["\u{000B}", "\u{0085}", "\u{2028}", "\u{007F}"] {
            probes.text("to DE89 3704 0044 0532\(cut)0130 00 ok", secret: iban, digits: true)
            probes.text("to DE89\(cut)3704 0044 0532 0130 00 ok", secret: iban, digits: true)
        }

        probes.section("n24f-email-cut")
        for cut in ["\u{000B}", "\u{000C}", "\u{0085}", "\u{2028}", "\u{007F}", "\u{001B}"] {
            probes.text("mail {S}\(cut)@example.com ok")
            probes.text("mail x{S}\(cut)@example.com ok", width: 9)
            probes.body(#"{"to":"{S}\#(cut == "\u{000B}" ? "\\u000b" : cut)@example.com"}"#, json)
        }

        probes.section("n24f-token-cut")
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
        let github = "ghp_" + String(repeating: "A1b2", count: 4) + String(repeating: "C3d4", count: 5)
        for cut in ["\u{000B}", "\u{0085}", "\u{2028}", "\u{007F}"] {
            probes.text("got eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0\(cut).c2lnbmF0dXJlLXNpZ25hdHVyZQ ok", secret: jwt, width: 10)
            probes.text("got eyJhbGciOiJIUzI1NiJ9\(cut).eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXNpZ25hdHVyZQ ok", secret: "eyJhbGciOiJIUzI1NiJ9", width: 10)
            probes.text("got ghp_\(String(repeating: "A1b2", count: 4))\(cut)\(String(repeating: "C3d4", count: 5)) ok", secret: github, width: 12)
        }
        return probes.probes
    }()

    private static func multipart(_ parts: [String]) -> String {
        parts.map { "--B0und\r\nContent-Disposition: form-data; " + $0 + "\r\n" }.joined() + "--B0und--"
    }

    /// Numbers the probes in order, as the review did, and writes the marker of each into it.
    private struct Builder {
        private(set) var probes: [ReviewProbe]
        private var nextID: Int
        private var category = ""

        init(firstID: Int, probes: [ReviewProbe] = []) {
            nextID = firstID
            self.probes = probes
        }

        mutating func section(_ name: String) { category = name }

        mutating func text(_ input: String, secret: String? = nil, digits: Bool = false, width: Int = 6, claim: String = "C") {
            add("text", input, type: nil, keys: nil, secret: secret, digits: digits, width: width, claim: claim)
        }

        mutating func body(_ input: String, _ type: String, secret: String? = nil, digits: Bool = false, claim: String = "C") {
            add("body", input, type: type, keys: nil, secret: secret, digits: digits, width: 6, claim: claim)
        }

        mutating func url(_ input: String, allowing keys: [String] = [], secret: String? = nil, digits: Bool = false) {
            add("url", input, type: nil, keys: keys, secret: secret, digits: digits, width: 6, claim: "C")
        }

        private mutating func add(
            _ kind: String, _ input: String, type: String?, keys: [String]?, secret: String?, digits: Bool, width: Int, claim: String
        ) {
            let marker = "Qz\(String(format: "%03d", nextID))Wk5m"
            probes.append(ReviewProbe(
                review: review, id: nextID, category: category, claim: claim, kind: kind, keys: keys, queryKeys: nil, type: type,
                input: input.replacingOccurrences(of: "{S}", with: marker), repeat: nil, data: nil, secret: secret ?? marker,
                digits: digits, width: width
            ))
            nextID += 1
        }
    }
}
