import Foundation
import Testing
@testable import iOSSecurityTools

/// The free-text rule: the first trigger hides everything after it, to the end of the text. A
/// trigger is a key that is not on the allowlist, a secret name with or without a separator, a
/// word that cannot be read and a quote or bracket that does not close.
@Suite("SensitiveDataRedactor free-text rule")
struct RedactionFreeTextRuleTests {
    let redactor = SensitiveDataRedactor()

    @Test("only allowed keys are read on", arguments: [
        ("status=200 method=GET path=/a duration_ms=12 count=3", "status=200 method=GET path=/a duration_ms=12 count=3"),
        ("status: 500, count: 2, method: GET", "status: 500, count: 2, method: GET"),
        ("--status=1 (count=2) [path=/a]", "--status=1 (count=2) [path=/a]"),
        ("\"status\":\"ok\" 'count':5", "\"status\":\"ok\" 'count':5"),
        ("Status=1 STATUS=2 Duration-MS=3 duration.ms=4", "Status=1 STATUS=2 Duration-MS=3 duration.ms=4"),
        ("status==200 x", "status==200 x"),
        ("status=200 user=bob", "status=200 user=[redacted]"),
        ("user=bob status=200", "user=[redacted]"),
        ("status=200 attempt=2 level=warn", "status=200 attempt=[redacted]"),
        ("--status=1 (count=2) [page=3]", "--status=1 (count=2) [page=[redacted]"),
        ("x=hunter2", "x=[redacted]"),
        ("\u{FF53}\u{FF54}\u{FF41}\u{FF54}\u{FF55}\u{FF53}=200", "\u{FF53}\u{FF54}\u{FF41}\u{FF54}\u{FF55}\u{FF53}=[redacted]"),
        ("st%61tus=200", "[redacted]"),
        ("status\u{0301}=200", "status\u{0301}=[redacted]"),
        ("status=200&user=bob", "status=200&user=[redacted]"),
        ("status=200;user=bob", "status=200;user=[redacted]"),
        ("status=200,user=bob", "status=200,user=[redacted]"),
        ("path=/x?token=abc", "path=/x?token=[redacted]"),
        ("status=200 password=x", "status=200 password=[redacted]"),
        ("user=\"bob smith\" status=1", "user=[redacted]"),
        ("data={\"a\":[1,2]} status=1", "data=[redacted]"),
        ("Error: connection refused", "Error: [redacted]"),
        ("[INFO] app: started", "[INFO] app: [redacted]"),
        ("curl -u bob:Vq302Lm8x https://x.example", "curl -u bob:[redacted]"),
    ])
    func allowlist(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("the app can allow more keys, but never a secret one")
    func customAllowlist() {
        let custom = SensitiveDataRedactor(allowedTextKeys: ["user", "request_id", "token"])
        #expect(custom.redact("user=bob request-id=7 token=abc") == "user=bob request-id=7 token=[redacted]")
        #expect(custom.redact("login user=bob status=401 password=hunter2") == "login user=bob status=401 password=[redacted]")
    }

    // A separator outside ASCII is outside the safe alphabet: it cuts the text where it is,
    // whatever key comes before it.
    @Test("separators are = and :, and runs of them; one outside ASCII cuts the text; a : between digits is a time", arguments: [
        ("user:=bob", "user:=[redacted]"),
        ("user == bob", "user == [redacted]"),
        ("user => bob", "user => [redacted]"),
        ("user ::= bob", "user ::= [redacted]"),
        ("user\u{FF1D}bob", "user[redacted]"),
        ("user\u{FF1A}bob", "user[redacted]"),
        ("user\u{FE13}bob", "user[redacted]"),
        ("user\u{2260}bob", "user[redacted]"),
        ("user\u{203F}bob", "user[redacted]"),
        ("a \u{203F} b", "a [redacted]"),
        ("status\u{A789} ok", "status[redacted]"),
        ("at 12:30:45 done", "at 12:30:45 done"),
        ("2026-10-19T12:30:45Z ok", "2026-10-19T12:30:45Z ok"),
        ("host:8080", "host:[redacted]"),
        ("=bob", "=[redacted]"),
        ("x = = bob", "x = [redacted]"),
    ])
    func separators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // Nothing is carried from one line to the next: the cut covers them all.
    @Test("everything after the first trigger is hidden, to the end of the text", arguments: [
        ("status=200\nlogin ok\nuser=bob\nstatus=201\nmore text", "status=200\nlogin ok\nuser=[redacted]"),
        ("password:\n  hunter2\nnext", "password:[redacted]"),
        ("config:\n  password: x\n  user: bob\nstatus=1", "config:[redacted]"),
        ("key: |\n  line one\n  line two\nstatus=1", "key: [redacted]"),
        ("export TOKEN=abc \\\ndef\nstatus=1", "export TOKEN=[redacted]"),
        ("password=\"abc\ndef\" status=1", "password=[redacted]"),
        ("password\n= hunter2", "password\n= [redacted]"),
        ("password\n:\n\"hunter2\" status=1", "password\n:[redacted]"),
        ("status=1 msg=\"a\nb\" status=2\nlast line", "status=1 msg=[redacted]"),
        ("done in 12 ms\nError: x\nstatus=200", "done in 12 ms\nError: [redacted]"),
        ("status=1\r\nuser=bob\r\nstatus=2", "status=1\r\nuser=[redacted]"),
        ("status=1\r\nuser=bob\rstatus=2", "status=1\r\nuser=[redacted]"),
        ("password=hunter\u{2028}2", "password=[redacted]"),
        ("password=hunter\u{0B}2\nstatus=3", "password=[redacted]"),
    ])
    func cutToTheEnd(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret name without a separator hides everything after it", arguments: [
        ("password hunter2", "password [redacted]"),
        ("password hunter2\nnext line", "password [redacted]"),
        ("login secret e32", "login secret [redacted]"),
        ("login api_key e33", "login api_key [redacted]"),
        ("--client-secret k128", "--client-secret [redacted]"),
        ("export AWS_SECRET_ACCESS_KEY k129", "export AWS_SECRET[redacted]"),
        ("PIN 1234 entered", "PIN [redacted]"),
        ("the token expired", "the token [redacted]"),
        ("Session ID abc123", "Session [redacted]"),
        ("my_password_is_hunter2 x", "my_password[redacted]"),
        ("setPassword(hunter2)", "setPassword[redacted]"),
        ("\"password\" hunter2", "\"password\" [redacted]"),
        ("password\u{A789}hunter2 next", "password[redacted]"),
        ("password \u{2236} hunter2", "password [redacted]"),
        ("password\u{2254}hunter2", "password[redacted]"),
        ("pass word=hunter2", "pass [redacted]"),
        ("<password>hunter2</password>", "[redacted]"),
        ("<password>\nhunter2\n</password>", "[redacted]"),
        ("<key>password</key>\n<string>hunter2</string>", "[redacted]"),
        ("password\nhunter2", "password[redacted]"),
        ("wrong password", "wrong password"),
    ])
    func secretNameWithoutSeparator(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("secret names are found behind styles, invisible characters, marks and escapes", arguments: [
        "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D} hunter2", "\u{24DF}assword hunter2",
        "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44} hunter2", "pass\u{200B}word hunter2",
        "pa\u{0301}ssword hunter2", "pass\u{00AD}word hunter2", "PASS-WORD hunter2", "pass.word hunter2",
        "p&#97;ssword hunter2", "p&#x61;ssword hunter2", "pass%77ord hunter2", "pass%2577ord hunter2", "\\u0070assword hunter2",
        "\\u{70}assword hunter2", "pass\\x77ord hunter2", "password%3Dhunter2", "password&#61;hunter2", "password\\u003Dhunter2",
    ])
    func disguisedSecretNames(input: String) {
        let output = redactor.redact(input)
        #expect(!output.contains("hunter2"), "\(input.debugDescription) -> \(output.debugDescription)")
        #expect(output.hasSuffix("[redacted]"))
    }

    @Test("a word that mixes scripts, or a quote that does not close, hides everything after it", arguments: [
        ("login p\u{0430}ssword hunter2", "login [redacted]"),
        ("\u{0440}\u{0430}\u{0455}\u{0455}\u{051D}\u{043E}\u{0433}d hunter2", "[redacted]"),
        ("t\u{03BF}ken hunter2", "[redacted]"),
        ("p%D0%B0ssword hunter2", "[redacted]"),
        ("status=\u{043E}k", "status=[redacted]"),
        ("say \"hunter2", "say \"[redacted]"),
        ("say \"hi\" and 5\" more", "say \"hi\" and 5\"[redacted]"),
    ])
    func ambiguity(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // Review probes 71, 80 and 401–414: the scanning copy leaves out an invisible character, so a
    // key or word that starts with one was read without it, as the allowed key `status` or a
    // plain word. An invisible character is outside the safe alphabet: it cuts the text there.
    @Test("an invisible character cuts the text where it is", arguments: [
        ("\u{200D}status=Qz080Wk7r", "[redacted]"),
        ("x \u{200B}status=hunter2", "x [redacted]"),
        ("\u{2060}status=hunter2", "[redacted]"),
        ("\u{115F}status=hunter2", "[redacted]"),
        ("\u{AD}status: hunter2", "[redacted]"),
        ("\u{FEFF}status=200", "[redacted]"),
        ("status=200 \u{200B}", "status=200 [redacted]"),
        ("status=2\u{200B}00", "status=[redacted]"),
        ("\u{202E}drowssap Qz071Wk7r", "[redacted]"),
        ("login \u{202E}zyx2retnuh drowssap", "login [redacted]"),
        ("\u{2066}\u{202E}drowssap hunter2", "[redacted]"),
    ])
    func invisibleBeforeKeyOrWord(input: String, expected: String) {
        let output = redactor.redact(input)
        #expect(Array(output.unicodeScalars) == Array(expected.unicodeScalars), "\(output.debugDescription)")
    }

    @Test("text without a trigger stays as it is", arguments: [
        "Merhaba Kullanıcı giriş yaptı", "Straße naïve café", "заказ отправлен", "東京 ログイン成功", "iPhoneで決済しました",
        "say \"hi\" now", "[INFO] started in 12 ms", "keyboard layout changed", "tokenizer ready", "bypass mode",
        "user logged in at 12:30 from 10.0.0.1", "status=200 method=GET path=/api/items",
    ])
    func unchanged(input: String) {
        #expect(redactor.redact(input) == input)
    }

    // Only LF and CR end a line of the safe alphabet; any other line break is a control character
    // or a separator outside ASCII, which cuts the text.
    @Test("U+2028, U+2029, U+0085, VT and FF cut the text; LF and CR are kept")
    func lineSeparators() {
        #expect(redactor.redact("a\nb\r\nc\rd") == "a\nb\r\nc\rd")
        #expect(redactor.redact("a\u{2029}b\u{85}c\u{0B}d\u{0C}e") == "a[redacted]")
        #expect(redactor.redact("a\u{85}b") == "a[redacted]")
        #expect(redactor.redact("a\u{0B}b") == "a[redacted]")
        #expect(redactor.redact("a\u{0C}b") == "a[redacted]")
        #expect(redactor.redact("password\u{2028}=hunter2") == "password[redacted]")
        #expect(redactor.redact("user\u{2028}=bob") == "user[redacted]")
        #expect(redactor.redact("status=1\u{2029}user=bob\u{85}status=2") == "status=1[redacted]")
    }

    @Test("JSON in a line follows the allowlist member by member", arguments: [
        ("{\"status\":200,\"count\":3} tail", "{\"status\":200,\"count\":3} tail"),
        ("{\"status\":200,\"user\":\"bob\"} tail", "{\"status\":200,[redacted]"),
        ("{\"status\":\"ok\",\"items\":[1,2]} {\"count\":1}", "{\"status\":\"ok\",[redacted]"),
        ("{\"path\":\"/a\",\"items\":[{\"count\":1},{\"name\":\"x\"}]} tail", "{\"path\":\"/a\",[redacted]"),
        ("{\"status\":\"x password=1\"} tail", "{\"status\":\"[redacted]"),
        ("[\"a\",\"b\"] ok", "[[redacted]"),
        ("[\"a\",\"b\",\"c\"] ok", "[\"a\",\"b\",\"c\"] ok"),
        ("[[\"\u{15E}ifre\",\"1234\"]] ok", "[[[redacted]"),
    ])
    func jsonMembers(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }
}
