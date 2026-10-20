import Foundation
@testable import iOSSecurityTools

// swiftlint:disable line_length
extension TenthReviewProbeSet {
    // Line separators, log lines, confusable and invisible keys in pairs, URLs.
    func addText() {
        section("n9-line-separator")
        p("name=\"password\"\u{2028}{S}")
        p("name=\"password\"\u{85}{S}")
        p("name=\"password\"\u{0B}{S}")
        p("name=\"password\"\u{0C}{S}")
        p("name=\"password\"\u{2029}\u{2029}{S}")
        p("password:\u{2029}{S}")
        p("password=\u{2028}  {S}")
        p("password = \"x\u{2028}{S}\"")
        p("token:\r{S}")
        p("token \u{85}\u{85}{S}")
        p("token\u{0B}\u{0C}{S}")
        p("\u{2028}pin\u{2028}{S}")
        p("pin\r\n\u{2028}\r\n{S}")
        p("<string name=\"token\">\u{0C}{S}\u{0C}</string>")

        section("n9-log-line")
        p("2026-10-20T06:00:00Z INFO auth ok user=bob name=\"password\" {S}")
        p("defaults write com.x apiKey {S}")
        p("Keychain: saved account=bob service=api kSecValueData={S}")
        p("header Authorization: Basic {S}")
        p("curl -H 'X-Api-Key: {S}' https://x.example/")
        p("curl -u bob:{S} https://x.example/")
        p("mysql -u root -p{S}", claim: "X")
        p("I/Auth(1234): onSuccess(pin=\u{2068}{S}\u{2069})")
        p("E/Net: \u{202E}drowssap{S}")                            // format character
        p("[auth] p\u{455}\u{455}\u{455} {S}")                     // mixes scripts
        p("app[123]: \u{1D42D}\u{1D428}\u{1D424}\u{1D41E}\u{1D427} refreshed {S}")
        p("app[123]: ⓒⓞⓞⓚⓘⓔ set {S}")
        p("user=bob \u{2502} password \u{2502} {S}")
        p("user=bob\u{2003}pass\u{2003}word\u{2003}{S}")
        p("export AWS_SECRET_ACCESS_KEY\u{3000}{S}")
        p("export AWS_SECRET_ACCESS_KEY=\\\n  {S}")
        p("Set-Cookie: sid={S}; Path=/; HttpOnly")
        p("> Cookie: a=1; sessionid={S}")
        p("--password\u{FF1D}{S}")
        p("--pass\u{2011}word {S}")
        p("PASS\u{2027}WORD {S}")
        p("pass\u{2E31}word {S}")
        p("pass\u{30FB}word {S}")
        p("pass\u{FF65}word {S}")
        p("pass\u{A78F}word {S}", claim: "X")
        p("pass\u{1427}word {S}")                                 // Canadian syllabics letter: mixes scripts

        section("n9-pair-confusable")
        p("\u{24DF}\u{24D8}\u{24DD}: {S}")
        p("\u{1D599}\u{1D594}\u{1D590}\u{1D58A}\u{1D593} {S}")
        p("\u{FF21}\u{FF30}\u{FF29}\u{FF3F}\u{FF2B}\u{FF25}\u{FF39}\u{FF1D}{S}")
        p("\u{3A1}\u{1D670}\u{1D682}\u{1D682}\u{1D686}\u{1D67E}\u{1D681}\u{1D673} {S}")
        p("password\u{301}={S}")
        p("t\u{336}o\u{336}k\u{336}e\u{336}n\u{336} {S}")
        p("pass\u{FE0F}word {S}")
        p("pass\u{E0020}word {S}")
        p("pass\u{180E}word {S}")
        p("pass\u{17B4}word {S}")
        p("pass\u{1D173}word {S}")
        p("\u{1D5C9}\u{1D5BA}\u{1D5CC}\u{1D5CC}\u{1D5D0}\u{1D5C8}\u{1D5CB}\u{1D5BD}\u{2236}{S}")
        p("\u{1F18}\u{1F10}cret: {S}")
        p("s\u{0435}cr\u{0435}t {S}")
        p("\u{2CA3}\u{2C81}\u{2CA5}\u{2CA5} {S}", claim: "X")                 // Coptic look-alikes
        p("user=bob pa\u{AD}ss=1 {S}")
        p("note=\u{FF5B}\u{FF02}pin\u{FF02}\u{FF1A}\u{FF02}{S}\u{FF02}\u{FF5D}")

        section("n9-url")
        p("https://x.example/cb#access_token={S}&state=1", .url)
        p("see https://x.example/a?q=1 password={S}")
        p("https://x.example/a?redirect=https%3A%2F%2Fy.example%2F%3Ftoken%3D{S}", .urlAllowing(["redirect"]))
        p("https://x.example/a?data=%7B%22label%22%3A%22Password%22%2C%22value%22%3A%22{S}%22%7D", .urlAllowing(["data"]))
        p("https://x.example/a?q=%E2%80%8Bpassword%E2%80%8B+{S}", .urlAllowing(["q"]))
        p("https://x.example/a?q=%F0%9D%90%A9%F0%9D%90%9A%F0%9D%90%AC%F0%9D%90%AC+{S}", .urlAllowing(["q"]))
        p("https://x.example/api/keys/password/{S}", .url, claim: "X")
        p("open https://x.example/a?q=ok\u{2028}token {S}")
        p("https://bob:{S}@x.example/", .urlAllowing(["q"]))
        p("go to https://x.example/a then pin\u{FF1A}{S}")
    }

    // Names written only with symbols whose compatibility form is letters (circled and
    // squared Latin letters), as the value of a JSON member, on every path a JSON object takes.
    func addSymbols() {
        let circledPin = "\u{24DF}\u{24D8}\u{24DD}"
        let circledToken = "\u{24E3}\u{24DE}\u{24DA}\u{24D4}\u{24DD}"
        let circledPassword = "\u{24DF}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3}"
        let squaredPin = "\u{1F13F}\u{1F138}\u{1F13D}"
        let circledApiKey = "\u{24B6}\u{24C5}\u{24BE} \u{24C0}\u{24BA}\u{24CE}"

        section("n9-symbol-name-json")
        p("{\"label\":\"\(circledPin)\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\(circledPassword)\",\"value\":\"{S}\"}", json)
        p("{\"type\":\"\(circledPassword)\",\"input\":\"{S}\"}", json)
        p("{\"ParameterKey\":\"\(circledToken)\",\"ParameterValue\":\"{S}\"}", json)
        p("{\"label\":\"\(squaredPin)\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\(circledApiKey)\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\(circledPin):\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\(circledPin)1\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\\u24df\\u24d8\\u24dd\",\"value\":\"{S}\"}", json)
        p("{\"label\":\"\(circledPin)\",\"value\":{\"a\":[\"{S}\"]}}", json)
        p("[{\"label\":\"\(circledPin)\",\"value\":\"{S}\"}]", json)

        section("n9-symbol-name-paths")
        p("{\"label\":\"\(circledPin)\",\"value\":\"{S}\"}")
        p("status=200 {\"label\":\"\(circledToken)\",\"value\":\"{S}\"} done")
        p("{\"label\":\"\(circledPin)\",\"value\":\"{S}\"}", plain)
        p("{\"log\":\"{\\\"label\\\":\\\"\(circledPin)\\\",\\\"value\\\":\\\"{S}\\\"}\"}", json)
        p("data=%7B%22label%22%3A%22%E2%93%9F%E2%93%98%E2%93%9D%22%2C%22value%22%3A%22{S}%22%7D", form)
        p("https://x.example/a?data=%7B%22label%22%3A%22%E2%93%9F%E2%93%98%E2%93%9D%22%2C%22value%22%3A%22{S}%22%7D", .urlAllowing(["data"]))
        p(multipart(["Content-Disposition: form-data; name=\"blob\"\r\nContent-Type: application/json\r\n\r\n{\"label\":\"\(circledPin)\",\"value\":\"{S}\"}"]), mpType())

        section("n9-symbol-name-controls")                                         // the same names on paths that read them
        p("[\"\(circledPin)\",\"{S}\"]", json)
        p("{\"name\":\"\(circledPin)\",\"value\":\"{S}\"}", json)
        p("label=\"\(circledPin)\" {S}")
        p("\(circledPin) {S}")
        p("{\"\(circledPin)\":\"{S}\"}", json)
    }
}
