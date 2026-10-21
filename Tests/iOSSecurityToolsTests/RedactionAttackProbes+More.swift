import Foundation
@testable import iOSSecurityTools

extension AttackProbes {
    // swiftlint:disable:next function_body_length
    static func addStructureLogsAndDetectors(to b: AttackProbeBuilder) {
        let json = Optional("application/json")
        let form = Optional("application/x-www-form-urlencoded")
        let plain = Optional("text/plain")
        let mp = Optional("multipart/form-data; boundary=XyZ")

        // MARK: 10. JSON inside strings
        b.text("embedded-json", "{\"variables\":\"{\\\"password\\\":\\\"{S}\\\"}\"}")
        b.text("embedded-json", "{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"password\\\\\\\":\\\\\\\"{S}\\\\\\\"}\\\"}\"}")
        b.text("embedded-json", "{\"query\":\"mutation { login(password: \\\"{S}\\\") }\"}")
        b.text("embedded-json", "{\"v\":\"{\\\"pass\\\\u0077ord\\\":\\\"{S}\\\"}\"}")
        b.text("embedded-json", "{\"v\":\"{\\\"password\\\":\\\"{S}\\\",}\"}")
        b.text("embedded-json", "body={\"password\":\"{S}\"} status=500")
        b.text("embedded-json", "msg=\"{\\\"password\\\":\\\"{S}\\\"}\" next")
        b.text("embedded-json", "msg=\"{\\\\\\\"password\\\\\\\":\\\\\\\"{S}\\\\\\\"}\" next")
        b.text("embedded-json", "<data>{\"password\":\"{S}\"}</data>")
        b.text("embedded-json", "{\"log\":\"password:\\n{S}\"}")
        b.text("embedded-json", "{\"log\":\"password:\u{2028}{S}\"}")

        // MARK: 11. Form + JSON mixtures
        b.body("form-json-mix", "a=1&json={\"password\":\"{S}\"}", form)
        b.body("form-json-mix", "a=1&json=%7B%22password%22%3A%22{S}%22%7D", form)
        b.body("form-json-mix", "{\"password\":\"{S}\"}", form)
        b.body("form-json-mix", "password:{S}", form)
        b.body("form-json-mix", "a=1&{\"password\":\"{S}\"}", nil)
        b.body("form-json-mix", "a=1&token:{S}", nil)
        b.body("form-name-leak", "password%3D{S}=x", form)
        b.raw("form-name-leak", "users[zqmail001x@example.com]=admin", .some(form), secrets: ["mail001x"])
        b.raw("form-name-leak", "a=1&4111111111111111", .some(form), secrets: ["4111111111111111"])
        b.raw("form-name-leak", "a=1&Authorization: Bearer abcdefgh1234567890", .some(form), secrets: ["abcdefgh1234567890"])
        b.body("form-shape", "a=1;password={S}", form)
        b.body("form-shape", "pass+word={S}", form)
        b.body("form-shape", "q=token%3D{S}", form)
        b.body("form-shape", "password[]={S}", form)
        b.body("form-shape", "%70assword={S}", form)

        // MARK: 12. Multipart headers
        func part(_ headers: String, _ content: String) -> String { "--XyZ\r\n\(headers)\r\n\r\n\(content)\r\n--XyZ--" }
        b.body("multipart", part("Content-Disposition: form-data; name=password", "{S}"), mp)
        b.body("multipart", part("Content-Disposition: Form-Data; NAME=\"password\"", "{S}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"pass\\\"word\"", "{S}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"=?utf-8?B?cGFzc3dvcmQ=?=\"", "{S}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"", "password: {S}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"\r\nContent-Type: application/json", "{\"token\":\"{S}\"}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"\r\nContent-Type: application/x-www-form-urlencoded", "{\"token\":\"{S}\"}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"\r\nX-Api-Key: {S}", "x"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"f\"; filename=\"token={S}.txt\"", "x"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain; charset=utf-8", "Authorization: DPoP {S}"), mp)
        b.body("multipart", "--XyZ \r\n" + "Content-Disposition: form-data; name=\"note\"\r\n\r\n{S}\r\n--XyZ--", mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"", "a\r\n--XyZX\r\npassword={S}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"password\"; filename=\"\"", "{S}"), mp)
        b.body("multipart", part("Content-Disposition: form-data; name=\"note\"\r\nContent-Type: multipart/mixed; boundary=a", "password={S}"), "multipart/form-data; boundary=\"XyZ\"")

        // MARK: 13. Broken bodies
        b.body("broken", "{\"password\":\"{S}\"", json)
        b.body("broken", "{\"password\":\"{S}\",}", json)
        b.body("broken", "password={S}", json)
        b.body("broken", "\u{FEFF}{\"password\":\"{S}\"}", json)
        b.body("broken", "\u{FEFF}{\"password\":\"{S}\"}", nil)
        b.body("broken", "password: {S}", nil)
        b.text("broken", "{\"password\":\"{S}\",}")
        b.text("broken", "{password: {S}}")
        b.text("broken", "{'password': '{S}'}")
        b.text("broken", "{\"password\":/*c*/\"{S}\"}")
        b.text("broken", "{\"password\"://c\n\"{S}\"}")
        b.text("broken", "{\"password\":\"{S}")
        b.text("broken", "{\"a\":\"\\ud800\",\"password\":\"{S}\"}")
        b.text("broken-multiline-quote", "private_key=\"-----BEGIN PRIVATE KEY-----\n{S}\n-----END PRIVATE KEY-----\"")

        // MARK: 14. Huge bodies
        let filler = String(repeating: "lorem ipsum dolor sit amet ", count: 40_000)
        b.text("huge", filler + "password={S}")
        b.body("huge", "{\"pad\":\"" + String(repeating: "x", count: 1_000_000) + "\",\"password\":\"{S}\"}", json)
        b.body("huge", String(repeating: "a=1&", count: 100_000) + "token={S}", form)
        b.text("huge", String(repeating: "x", count: 200_000) + " pass word={S}")
        b.text("huge", "pass" + String(repeating: " ", count: 100_000) + "word={S}")
        b.text("huge", "password" + String(repeating: " ", count: 100_000) + "= {S}")
        b.text("huge", String(repeating: "=", count: 50_000) + "password={S}")
        b.text("huge", String(repeating: "\u{00B7}", count: 50_000) + "password\u{A789}{S}")

        // MARK: 15. Line separators
        for lb in ["\u{2028}", "\u{2029}", "\u{0085}", "\u{000B}", "\u{000C}", "\r\n", "\r"] {
            b.text("line-separator", "password:\(lb){S} next")
        }
        b.text("line-separator", "pass\u{000B}word={S}")
        b.text("line-separator", "\"password\"\u{2028}:\u{2028}\"{S}\"")
        b.text("line-separator", "<password>\u{2028}{S}\u{2028}</password>")
        b.text("line-separator", "password=\"{S}\u{2028}{S2}\"")

        // MARK: 16. Free-text log lines
        b.text("log", "2026-10-15 12:00:00 [INFO] login user=bob password={S} ok")
        b.text("log", "{:password=>\"{S}\"}")
        b.text("log", "LoginRequest(username: \"bob\", password: \"{S}\")")
        b.text("log", "{\n    password = {S};\n}")
        b.text("log", "Array\n(\n    [password] => {S}\n)")
        b.text("log", "array(1) {\n  [\"password\"]=>\n  string(11) \"{S}\"\n}")
        b.text("log", "curl -H 'Authorization: Bearer {S}' https://x")
        b.text("log", "curl -d 'password={S}' https://x")
        b.text("log", "git clone https://bob:{S}@github.com/x/y.git")
        b.text("log", "url=admin:{S}@10.0.0.5:5432")
        b.text("log", "{User:bob Password:{S}}")
        b.text("log", "Login{password='{S}'}")
        b.text("log", "Error Domain=Auth Code=1 UserInfo={NSLocalizedDescription=bad, token={S}}")
        b.text("log", "GET /cb#access_token={S}&state=1")
        b.text("log", "GET /x?user%5Bpassword%5D={S}")
        b.text("log", "\u{25BF} LoginRequest\n  - username: \"bob\"\n  \u{25BF} password: Optional(\"{S}\")\n    - some: \"{S}\"")
        b.text("log", "\u{25BF} 1 key/value pair\n  \u{25BF} (2 elements)\n    - key: \"password\"\n    - value: \"{S}\"")
        b.text("log", "<dict>\n<key>password</key>\n<string>{S}</string>\n</dict>")
        b.text("log", "Set-Cookie: __Host-session={S}; Path=/; Secure")
        b.text("log", "Cookie: user_session={S}; logged_in=yes")
        b.text("log", "Cookie: laravel_session={S}")
        b.text("log", "api_keys:\n  - {S}\n  - {S2}")
        b.text("log", "password: |2\n   {S}\nuser: bob")
        b.text("log", "password: |-\n  {S}\nuser: bob")
        b.text("log", "password: !!binary {S}")
        b.text("log", "<wsse:Password Type=\"t\">{S}</wsse:Password>")
        b.text("log", "<a:b:password>{S}</a:b:password>")
        b.text("log", "<password>ab<!-- c -->{S}</password>")
        b.text("log", "<password><![CDATA[{S}]]></password>")
        b.text("log", "export DB_PASSWORD=\"{S}\"")
        b.text("log", "--password={S}")
        b.text("log", "X-Amz-Security-Token: {S}")

        // MARK: 17. Detector evasions
        b.raw("card", "card 4111 1111 1111 1111 ok", nil, secrets: ["4111 1111 1111 1111"])
        b.raw("card", "card \u{FF14}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11} ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card \u{0664}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661} ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card 4111\u{200B}1111\u{200B}1111\u{200B}1111 ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card 4111\u{00A0}1111\u{00A0}1111\u{00A0}1111 ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card 4111-1111-1111-1111 ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card 4111\u{2010}1111\u{2010}1111\u{2010}1111 ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card 4111\t1111\t1111\t1111 ok", nil, secrets: ["4111111111111111"])
        b.raw("card", "card 4111.1111.1111.1111 ok", nil, secrets: ["4111111111111111"])
        b.limitationRaw("card", "cc4111111111111111", nil, secrets: ["4111111111111111"])
        b.raw("email", "mail zqmail001x@example.com ok", nil, secrets: ["mail001x"])
        b.raw("email", "mail zqmail001x\u{FF20}example.com ok", nil, secrets: ["mail001x"])
        b.raw("email", "mail zqmail\u{200B}001x@example.com ok", nil, secrets: ["mail001x"])
        b.raw("email", "mail zqmail001x@ex\u{00E4}mple.com ok", nil, secrets: ["mail001x"])
        b.raw("email", "mail zqmail001x\\u0040example.com ok", nil, secrets: ["mail001x"])
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6cTAwMSJ9.c2lnbmF0dXJlMDAx"
        b.raw("jwt", "t=\(jwt) ok", nil, secrets: ["eyJzdWIiOiJ6cTAwMSJ9"])
        b.raw("jwt", "t=" + jwt.replacingOccurrences(of: ".", with: "\u{200B}.\u{00AD}") + " ok", nil, secrets: ["eyJzdWIiOiJ6cTAwMSJ9"])
        b.raw("jwt", "{\"x\":\"" + jwt.replacingOccurrences(of: ".", with: "\\u002e") + "\"}", nil, secrets: ["eyJzdWIiOiJ6cTAwMSJ9"])
        b.raw("jwt", "id_" + jwt, nil, secrets: ["eyJzdWIiOiJ6cTAwMSJ9"])
        b.raw("jwt", "t " + jwt.replacingOccurrences(of: ".", with: "%2E"), nil, secrets: ["eyJzdWIiOiJ6cTAwMSJ9"])

        // MARK: 18. Round 2: follow-ups on weak spots
        for invisible in ["\u{200B}", "\u{FEFF}", "\u{2060}", "\u{00AD}", "\u{034F}", "\u{200D}\u{200C}", "\u{E0001}", "\u{0301}"] {
            b.text("r2-invisible-only-value", "password: \(invisible) {S} next")
        }
        b.text("r2-invisible-only-value", "api_key=\u{200B} {S}")
        b.text("r2-invisible-only-value", "{\"msg\":\"token: \u{2060} {S}\"}")
        for name in ["pa(ss)word", "pass[]word", "pass{}word", "pass<>word", "pass<b>word", "pass`word", "pass``word", "\\u{70}assword",
                     "pass}word", "pa(s)s_word", "api[]_key", "acc(ess)Token"] {
            b.text("r2-bracket-split-name", "\(name)={S} next")
        }
        for sep in ["\u{FE30}", "\u{FE19}", "\u{2025}", "\u{FE52}", "\u{2024}", "\u{FF0E}"] {
            b.text("r2-lookalike-ascii-nfkc", "password\(sep){S} next")
        }
        b.text("r2-question-split", "pass?word={S} next")
        b.text("r2-comma-split", "pass,word={S} next")
        b.text("r2-continuation", "ENV API_KEY=\\\n  {S}")
        b.text("r2-quote-newline", "password: \"\n  {S}\"")
        b.text("r2-auth-dict", "[\"Authorization\": \"DPoP {S}\"]")
        b.body("r2-auth-text-body", "Authorization: DPoP {S}", plain)
        b.text("r2-auth-curl", "> Authorization: ApiKey {S}\n> Accept: */*")
        b.text("r2-json-key", "{\"GET https://x/?api_key={S}\":\"ok\"}")
        b.body("r2-form-json-eq", "{\"a\":\"b=c\",\"password\":\"{S}\"}", form)
        b.body("r2-form-name-jwt", "a=1&eyJhbGciOiJIUzI1NiJ9.eyJ{S}.sig", form)
    }
}
