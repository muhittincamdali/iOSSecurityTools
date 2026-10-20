import Foundation

// swiftlint:disable line_length
extension EleventhReviewProbeSet {
    // names held by fields in forms, URL queries and multipart bodies, and the paths of a URL.

    func part(_ name: String, _ content: String, headers: String = "") -> String {
        "Content-Disposition: form-data; name=\"\(name)\"\r\n\(headers)\r\n\(content)"
    }

    func addFlat() {
        section("n10-flat-form")
        p("value={S}&label=Password", form)
        p("Label=Password&value={S}", form)
        p("label=Pass%77ord&value={S}", form)
        p("label=P%D0%B0ssword&value={S}", form)
        p("label=%E2%93%9F%E2%93%98%E2%93%9D&value={S}", form)
        p("label=%F0%9F%94%91&value={S}", form)
        p("label=Pass+word&value={S}", form)
        p("label=&value={S}", form)
        p("label=Password%3A&value={S}", form)
        p("type=password&input={S}", form)
        p("field%5Blabel%5D=Password&field%5Bvalue%5D={S}", form)
        p("data=%7B%22label%22%3A%22%C5%9Eifre%22%2C%22value%22%3A%22{S}%22%7D", form)
        p("name=Pass%C2%ADword&value={S}", form)
        p("n=pin&v={S}", form)
        p("k=PIN&v={S}", form)
        p("param=api_key&val={S}", form)
        p("header=Authorization&content={S}", form)
        p("id=password&x={S}", form)
        p("path=%2Fuser%2Fpassword&value={S}", form)
        p("label=Password&value={S}&value=x", form)
        p("label=\(wild("password", [1, 6]).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)&value={S}", form)
        p("label=%5B%22pin%22%5D&value={S}", form)                       // JSON array as the name
        p("label=%E2%80%8Bstatus&value={S}", form)                        // ZWSP before a plain name
        p("label=Password", form, secret: "Password", claim: "K")

        section("n10-flat-query")
        let lv = Mode.urlAllowing(["label", "value"])
        p("https://x.example/a?value={S}&label=Password", lv)
        p("https://x.example/a?label=%C5%9Eifre&value={S}", lv)
        p("https://x.example/a?label=Pass%E2%80%8Bword&value={S}", lv)
        p("https://x.example/a?label=&value={S}", lv)
        p("https://x.example/a?LABEL=Password&value={S}", lv)
        p("https://x.example/a?label=Password&label=status&value={S}", lv)
        p("https://x.example/a?type=password&value={S}", .urlAllowing(["value"]))
        p("https://x.example/a?k=pin&v={S}", .urlAllowing(["k", "v"]))
        p("https://x.example/a?label=Pass+word&value={S}", lv)
        p("https://x.example/a?label=%F0%9F%94%91&value={S}", lv)
        p("https://x.example/a?label=\(wild("token", [1, 3]).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)&value={S}", lv)
        p("https://x.example/a?label=Password#value={S}", lv)
        p("https://x.example/a?q=1&password={S}", .urlAllowing(["q"]))
        p("https://x.example/a?q=label%3DPassword%26value%3D{S}", .urlAllowing(["q"]))

        section("n10-flat-path")
        p("https://x.example/api/pass%E2%80%8Bword/{S}", .url)
        p("https://x.example/api/p%D0%B0ssword/{S}", .url)
        p("https://x.example/v1/token;sig={S}", .url)
        p("https://x.example/v1/users;password={S}/x", .url)
        p("https://x.example/v1/PASSWORD/{S}/reset", .url)
        p("https://x.example/v1/pass%2Dword/{S}", .url)
        p("https://x.example/v1/api_keys/{S}", .url)
        p("https://x.example/api/%C5%9Eifre/{S}", .url, claim: "X")
        p("https://x.example/api/%E2%93%9F%E2%93%98%E2%93%9D/{S}", .url, claim: "X")

        section("n10-flat-multipart")
        p(multipart([part("label", "\u{015E}ifre"), part("value", "{S}")]), mpType())
        p(multipart([part("value", "{S}"), part("label", "Password")]), mpType())
        p(multipart([part("label", "Password", headers: "Content-Type: text/plain; charset=utf-8\r\n"), part("value", "{S}")]), mpType())
        p(multipart([part("Label", "PIN"), part("value", "{S}")]), mpType())
        p(multipart([part("label[0]", "\u{015E}ifre"), part("value[0]", "{S}")]), mpType())
        p(multipart([part("type", "password"), part("input", "{S}")]), mpType())
        p(multipart([part("label", " \u{015E}ifre "), part("value", "{S}")]), mpType())
        p(multipart([part("label", "Pass\u{AD}word"), part("value", "{S}")]), mpType())
        p(multipart([part("label", "\(wild("secret", [1, 4]))"), part("value", "{S}")]), mpType())
        p(multipart([part("label", ""), part("value", "{S}")]), mpType())
        p(multipart([part("label", "{\"en\":\"Password\"}"), part("value", "{S}")]), mpType())
        p(multipart([part("meta", "{\"label\":\"\u{015E}ifre\",\"value\":\"{S}\"}", headers: "Content-Type: application/json\r\n")]), mpType())
        p(multipart([part("meta", "label=%C5%9Eifre&value={S}", headers: "Content-Type: application/x-www-form-urlencoded\r\n")]), mpType())
        // A name the redactor does not read as text: base64, another charset, a JSON part, a file.
        p(multipart([part("label", "xZ5pZnJl", headers: "Content-Transfer-Encoding: base64\r\n"), part("value", "{S}")]), mpType(), claim: "X")
        p(multipart([part("label", "c2VjcmV0", headers: "Content-Transfer-Encoding: base64\r\n"), part("value", "{S}")]), mpType(), claim: "X")
        p(multipart([part("label", "\"password\"", headers: "Content-Type: application/json\r\n"), part("value", "{S}")]), mpType(), claim: "X")
        p(multipart([part("label", "UGFzc3dvcmQ=", headers: "Content-Transfer-Encoding: base64\r\n"), part("value", "{S}")]), mpType())
        p(multipart([part("label", "Pass=77ord", headers: "Content-Transfer-Encoding: quoted-printable\r\n"), part("value", "{S}")]), mpType())
        let latin5Label: [UInt8] = Array("--B0und\r\nContent-Disposition: form-data; name=\"label\"\r\nContent-Type: text/plain; charset=iso-8859-9\r\n\r\n".utf8)
            + [0xDE] + Array("ifre\r\n".utf8)
        p("--B0und\r\nContent-Disposition: form-data; name=\"value\"\r\n\r\n{S}\r\n--B0und--", .bytes(latin5Label, "multipart/form-data; boundary=B0und"), claim: "X")
    }

    // free text — confusables, invisible and format characters, marks, escapes, separators,
    // line breaks other than LF, log lines, and allowed keys that hold a name.

    func addText() {
        section("n10-text-confusable")
        p("auth failed: \u{440}\u{430}ssword {S}")                      // Cyrillic p, a (mixed)
        p("\u{3C1}assword {S}")                                         // Greek rho (mixed)
        p("\u{1D5FD}\u{1D5EE}\u{1D600}\u{1D600}\u{1D604}\u{1D5FC}\u{1D5FF}\u{1D5F1} {S}")  // math sans bold
        p("\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44} {S}")         // full width
        p("\u{1D56}\u{1D43}\u{2E2}\u{2E2}\u{2B7}\u{1D52}\u{2B3}\u{1D48} {S}")             // modifier letters
        p("pass\u{1D430}ord {S}")                                       // one math letter
        p("t\u{3BF}ken {S}")                                            // Greek omicron
        p("s\u{435}cret {S}")                                           // Cyrillic e
        p("\u{1D42D}\u{1D428}\u{1D424}\u{1D41E}\u{1D427} {S}")          // math bold token
        p("\u{2170}ban {S}")                                            // small roman numeral one as i
        p("p\u{2170}n {S}")
        p("\u{24C5}\u{24D0}\u{24E2}\u{24E2}\u{24E6}\u{24DE}\u{24E1}\u{24D3} {S}", claim: "D")   // enclosed throughout
        p("\u{440}\u{430}\u{455}\u{455}\u{51D}\u{43E}\u{433}\u{501} {S}", claim: "D")           // Cyrillic throughout

        section("n10-text-invisible")
        for (code, label) in [(0x034F, "CGJ"), (0xFE00, "VS1"), (0xE0101, "VS17"), (0x1160, "HJF"), (0x2064, "invisible plus"),
                              (0x061C, "ALM"), (0x200E, "LRM"), (0x13430, "hieroglyph joiner"), (0x1BCA0, "shorthand"),
                              (0xFFF9, "annotation"), (0x110BD, "Kaithi"), (0x0600, "Arabic number"), (0x070F, "Syriac"),
                              (0x180B, "FVS1"), (0xFFA0, "HW filler"), (0x2061, "function application"), (0x206A, "ISS")] {
            _ = label
            p("login pass\(String(Unicode.Scalar(code)!))word {S}")
        }
        p("login pass\u{2066}word\u{2069} {S}")
        p("login \u{202E}drowssap\u{202C} {S}")
        p("pass\u{2800}word {S}", claim: "X")                           // braille blank is a symbol

        section("n10-text-space")
        for code in [0x3000, 0x205F, 0x1680, 0x00A0, 0x2007, 0x202F, 0x2002] {
            p("pass\(String(Unicode.Scalar(code)!))word {S}")
        }

        section("n10-text-mark")
        p("Pass\u{335}word {S}")
        p("p\u{336}a\u{336}s\u{336}s\u{336}w\u{336}o\u{336}r\u{336}d\u{336} {S}")
        p("to\u{30A}ke\u{30A}n {S}")
        p("se\u{F3E}cret {S}")                                          // Tibetan mark (Mc)
        p("pass\u{1AB0}word {S}")
        p("api\u{20E3}_key {S}")                                        // enclosing keycap

        section("n10-text-escape")
        p("p\\u0061ssw\\u006Frd {S}")
        p("p&#x61;ssw&#111;rd {S}")
        p("%70%61%73%73%77%6F%72%64 {S}")
        p("p&#97;ss&#119;ord {S}")
        p("password\\u003D{S}")
        p("user%3D{S}")
        p("note&#61;{S}")
        p("note%u003D{S}")
        p("note\\u003a {S}")
        p("token&#x3A;{S}")
        p("&#112&#97&#115&#115&#119&#111&#114&#100 {S}", claim: "X")    // decimal escapes without ;
        p("pass%2577ord {S}", claim: "X")
        p("pa\\u{73}sword {S}", claim: "X")
        p("pa%u0073sword {S}", claim: "X")

        section("n10-text-separator")
        for code in [0x2236, 0xA789, 0x05C3, 0x1361, 0xFE55, 0xFF1A, 0x2A74, 0x2A75, 0x2A76, 0x207C, 0x208C, 0x30A0, 0x2E40,
                     0x21D2, 0x27F6, 0x0703, 0xFE13, 0x2254, 0x2255, 0x225D, 0x229C] {
            p("user\(String(Unicode.Scalar(code)!)){S}")
        }
        p("user \u{2192} {S}", claim: "X")
        p("user\u{2B62}{S}", claim: "X")
        p("user\u{2D0}{S}", claim: "X")

        section("n10-text-lines")
        p("login ok user=bob\u{2028}password {S}")
        p("status=200\u{2028}password={S}")
        p("status=200\u{85}token {S}")
        p("method=GET\u{B}secret={S}")
        p("path=/a\u{C}pin {S}")
        p("name=\"password\"\u{2029}{S}")
        p("label=\"\u{015E}ifre\"\u{2028}{S}")
        p("password:\u{2028}{S}")
        p("password:\u{85}{S}")
        p("password=\u{B}{S}")
        p("password:\u{C}{S}")
        p("password:\r{S}")
        p("user=bob\rpassword {S}")
        p("{\"note\":\"ok\u{2028}password {S}\"}", json)
        p("note=ok%E2%80%A8password+{S}", form)
        p("status=200\u{85}password={S}", plain)

        section("n10-text-log")
        p("curl -H 'Authorization: Bearer {S}' https://api.example.com/v1")
        p("curl -u bob:{S} https://api.example.com")
        p("psql postgresql://bob:{S}@db:5432/app")
        p("connecting to redis://:{S}@cache:6379/0")
        p("amqp://guest:{S}@rabbit:5672//")
        p("DATABASE_URL=postgres:" + "//u:{S}@h/d")  // in two pieces, so secret scanners do not flag test data
        p("export AWS_SECRET_ACCESS_KEY={S}")
        p("set PASSWORD {S}")
        p("Authorization header was {S}")
        p("X-Api-Key {S}")
        p("Cookie: sessionid={S}; csrftoken=abc")
        p("the token is {S}")
        p("2026-10-20T10:00:00Z ERROR auth failed for bob, password {S} rejected")
        p("[INFO] [Auth] pin code entered: {S}")
        p("E/OkHttp: --> POST /login {\"username\":\"bob\",\"password\":\"{S}\"}")
        p("NSURLError: url=https://x.example/cb?code=1&token={S}")
        p("Optional(\"{S}\") <- keychain password", claim: "D")         // value before its name
        p("mysql -ubob -p{S} db", claim: "D")
        p("{S} is the password", claim: "D")

        section("n10-text-allowed-names")
        let nv = Mode.textAllowing(["name", "value"])
        p("name=\u{015E}ifre value={S}", nv)
        p("name=\(wild("password", [1, 6])) value={S}", nv)
        p("name: \"PIN\"\nvalue: {S}", nv)
        p("name=pin value={S}", nv)
        p("name = \u{41F}\u{430}\u{440}\u{43E}\u{43B}\u{44C}, value = {S}", nv)
        p("name=[ \"pin\" ] value={S}", nv)
        p("name=(password) value={S}", nv)
        p("name=pass%77ord value={S}", nv)
        p("name=\"Pass\u{200B}word\" value={S}", nv)
        p("name='ⓟⓘⓝ'\nvalue={S}", nv)
        p("name=password\nvalue={S}", nv, claim: "X")                  // unquoted name at the end of its line
        p("status={\"password\":\"{S}\"}")
        p("status=ok password {S}")
        p("\u{200D}status={S}")
        p("\u{455}tatus={S}")
        p("status_password={S}")
        p("status=200,password={S}")
        p("status=200;token={S}")
        p("status=200&pin={S}")

        section("n10-text-held-lines")
        p("name=[\n\"pin\"\n] {S}")                                       // JSON over lines after a name key
        p("name={\"a\":\n\"pin\"} {S}")
        p("log {\"label\":\"\u{015E}ifre\",\"value\":\"{S}\"}")
        p("\"label\":\"\u{015E}ifre\",\"value\":\"{S}\"")
        p("label=\u{015E}ifre&value={S}")
        p("- label: \u{015E}ifre\n  value: {S}")
        p("path=/cb#access_token={S}")
        p("path=/login?user=bob&pw={S}")
        p("path=/a/\(wild("password", [1, 6]))/{S}")
        p("label: \u{015E}ifre\nvalue: {S}", .textAllowing(["value"]), claim: "X")
    }
}
