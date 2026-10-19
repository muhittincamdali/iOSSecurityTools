import Foundation
import Testing
@testable import iOSSecurityTools

/// The free-text rule: an allowlist of keys, values hidden to where they surely end, secret names
/// without a separator, and the rest of a line hidden where the rule cannot tell.
@Suite("SensitiveDataRedactor free-text rule")
struct RedactionFreeTextRuleTests {
    let redactor = SensitiveDataRedactor()

    @Test("only allowed keys keep their value", arguments: [
        ("status=200 method=GET path=/a duration_ms=12 count=3", "status=200 method=GET path=/a duration_ms=12 count=3"),
        ("status: 500, attempt: 2, level: warn", "status: 500, attempt: 2, level: warn"),
        ("--status=1 (count=2) [page=3]", "--status=1 (count=2) [page=3]"),
        ("\"status\":\"ok\" 'limit':5", "\"status\":\"ok\" 'limit':5"),
        ("status=200 user=bob", "status=200 user=[redacted]"),
        ("user=bob status=200", "user=[redacted]"),
        ("db_pw=ft1 pw=ft2", "db_pw=[redacted]"),
        ("refresh=ft42", "refresh=[redacted]"),
        ("Status=1 STATUS_CODE=2 status-code=3", "Status=1 STATUS_CODE=2 status-code=3"),
        ("ｓｔａｔｕｓ=200", "ｓｔａｔｕｓ=[redacted]"),
        ("st%61tus=200", "st%61tus=[redacted]"),
        ("status\u{0301}=200", "status\u{0301}=[redacted]"),
        ("status=200&user=bob", "status=200&user=[redacted]"),
        ("status=200;user=bob", "status=200;user=[redacted]"),
        ("status=200,user=bob", "status=200,user=[redacted]"),
        ("path=/x?token=abc", "path=/x?token=[redacted]"),
        ("status=200 password=x", "status=200 password=[redacted]"),
    ])
    func allowlist(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("the app can allow more keys, but never a secret one")
    func customAllowlist() {
        let custom = SensitiveDataRedactor(allowedTextKeys: ["user", "request_id", "token"])
        #expect(custom.redact("user=bob request-id=7 token=abc") == "user=bob request-id=7 token=[redacted]")
    }

    @Test("separators are = and :, runs of them, and their compatibility forms; a : between digits is a time", arguments: [
        ("user:=bob", "user:=[redacted]"),
        ("user == bob", "user == [redacted]"),
        ("user => bob", "user => [redacted]"),
        ("user ::= bob", "user ::= [redacted]"),
        ("user\u{FF1D}bob", "user\u{FF1D}[redacted]"),
        ("user\u{FF1A}bob", "user\u{FF1A}[redacted]"),
        ("user\u{FE13}bob", "user\u{FE13}[redacted]"),
        ("user\u{2260}bob", "user\u{2260}[redacted]"),
        ("at 12:30:45 done", "at 12:30:45 done"),
        ("2026-10-19T12:30:45Z ok", "2026-10-19T12:30:45Z ok"),
        ("host:8080", "host:[redacted]"),
        ("=bob", "=[redacted]"),
        ("x = = bob", "x = [redacted]"),
    ])
    func separators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a hidden value runs to its closing quote, over its JSON, or to the end of the line", arguments: [
        ("user=\"bob smith\" status=1", "user=\"[redacted]\" status=1"),
        ("user='bob smith' status=1", "user='[redacted]' status=1"),
        ("user=`bob` status=1", "user=`[redacted]` status=1"),
        ("user=\"a\\\"b\" status=1", "user=\"[redacted]\" status=1"),
        ("{\\\"password\\\":\\\"x\\\"}", "{\\\"password\\\":\\\"[redacted]\\\"}"),
        ("data={\"a\":[1,2]} status=1", "data=[redacted] status=1"),
        ("data=[\"a\",\"b\"],status=1", "data=[redacted],status=1"),
        ("password=hunter 2 status=ok", "password=[redacted]"),
        ("password=(hunter2)tail", "password=[redacted]"),
        ("token=abc) tail", "token=[redacted]"),
        ("password=[hunter]2 x", "password=[redacted]"),
        ("password={hunter}2 x", "password=[redacted]"),
        ("password=\"x\"y z", "password=\"[redacted]\"[redacted]"),
        ("password='x'\"y\" z", "password='[redacted]'[redacted]"),
        ("password=\"x\", status=1", "password=\"[redacted]\", status=1"),
        ("password=", "password="),
    ])
    func valueExtent(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a value goes on in later lines: after an empty separator, in indented lines, after a backslash or a comment", arguments: [
        ("password:\n  hunter2\nnext", "password:\n  [redacted]\nnext"),
        ("password:\n\n\nhunter2", "password:\n\n\n[redacted]"),
        ("config:\n  password: x\n  user: bob\nstatus=1", "config:\n  [redacted]\n  [redacted]\nstatus=1"),
        ("key: |\n  line one\n  line two\nstatus=1", "key: [redacted]\n  [redacted]\n  [redacted]\nstatus=1"),
        ("export TOKEN=abc \\\ndef\nstatus=1", "export TOKEN=[redacted]\n[redacted]\nstatus=1"),
        ("password: // rotate\nhunter2", "password: [redacted]\n[redacted]"),
        ("password: /* x */\nhunter2", "password: [redacted]\n[redacted]"),
        ("password: # later\nhunter2", "password: [redacted]\n[redacted]"),
        // The line where a quoted value closes is hidden whole.
        ("password=\"abc\ndef\" status=1", "password=\"[redacted]\n[redacted]"),
        ("password=\"abc\nnext line", "password=\"[redacted]\n[redacted]"),
        ("password\n= hunter2", "password\n= [redacted]"),
        ("password\n:\n\"hunter2\" status=1", "password\n:\n[redacted]"),
    ])
    func laterLines(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret name without a separator hides the rest of its line", arguments: [
        ("password hunter2", "password [redacted]"),
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
        ("<password>hunter2</password>", "<password>[redacted]"),
        ("wrong password", "wrong password"),
    ])
    func secretNameWithoutSeparator(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret name that ends its line, or markup after it, hides the next line too", arguments: [
        ("<password>\nhunter2\n</password>", "<password>\n[redacted]\n</password>"),
        ("<key>password</key>\n<string>hunter2</string>", "<key>[redacted]\n[redacted]"),
        ("password\nhunter2", "password\n[redacted]"),
        // A value that ends at a line break other than LF may go on below it.
        ("<password>\u{2028}hunter2\u{2028}</password>", "<password>\n[redacted]\n[redacted]"),
    ])
    func secretNameBeforeNextLine(input: String, expected: String) {
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

    @Test("a word that mixes scripts, or an unbalanced double quote, hides the rest of the line", arguments: [
        ("login p\u{0430}ssword hunter2", "login [redacted]"),
        ("\u{0440}\u{0430}\u{0455}\u{0455}\u{051D}\u{043E}\u{0433}d hunter2", "[redacted]"),
        ("t\u{03BF}ken hunter2", "[redacted]"),
        ("p%D0%B0ssword hunter2", "[redacted]"),
        ("status=\u{043E}k", "status=[redacted]"),
        ("say \"hunter2", "say [redacted]"),
        ("say \"hi\" and 5\" more", "say \"hi\" and 5[redacted]"),
    ])
    func ambiguity(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // Review probes 71, 80 and 401–414: the scanning copy leaves out an invisible character, so a
    // key or word that starts with one was read without it, as the allowed key `status` or a
    // plain word.
    @Test("an invisible character right before a key or a word belongs to it", arguments: [
        ("\u{200D}status=Qz080Wk7r", "\u{200D}status=[redacted]"),
        ("x \u{200B}status=hunter2", "x \u{200B}status=[redacted]"),
        ("\u{2060}status=hunter2", "\u{2060}status=[redacted]"),
        ("\u{115F}status=hunter2", "\u{115F}status=[redacted]"),
        ("\u{AD}status: hunter2", "\u{AD}status: [redacted]"),
        ("\u{FEFF}status=200", "\u{FEFF}status=[redacted]"),
        ("status=200 \u{200B}", "status=200 \u{200B}"),
        ("\u{202E}drowssap Qz071Wk7r", "\u{202E}[redacted]"),
        ("login \u{202E}zyx2retnuh drowssap", "login \u{202E}[redacted]"),
        ("\u{2066}\u{202E}drowssap hunter2", "\u{2066}\u{202E}[redacted]"),
    ])
    func invisibleBeforeKeyOrWord(input: String, expected: String) {
        let output = redactor.redact(input)
        #expect(Array(output.unicodeScalars) == Array(expected.unicodeScalars), "\(output.debugDescription)")
    }

    @Test("prose, other scripts and quoted text stay as they are", arguments: [
        "Merhaba Kullanıcı giriş yaptı", "Straße naïve café", "заказ отправлен", "東京 ログイン成功", "iPhoneで決済しました",
        "say \"hi\" now", "[INFO] started in 12 ms", "keyboard layout changed", "tokenizer ready", "bypass mode",
    ])
    func unchanged(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("U+2028, U+2029, U+0085, VT and FF end a line and are written as line feeds; CR and CRLF are kept")
    func lineSeparators() {
        #expect(redactor.redact("password\u{2028}=hunter2") == "password\n=[redacted]")
        #expect(redactor.redact("user\u{2028}=bob") == "user\n=[redacted]")
        #expect(redactor.redact("a\u{2029}b\u{85}c\u{0B}d\u{0C}e") == "a\nb\nc\nd\ne")
        #expect(redactor.redact("status=1\r\nuser=bob\r\nstatus=2") == "status=1\r\nuser=[redacted]\r\nstatus=2")
        // A value hidden to the end of a line that ends at any other break may go on below it.
        #expect(redactor.redact("status=1\r\nuser=bob\rstatus=2") == "status=1\r\nuser=[redacted]\r[redacted]")
        #expect(redactor.redact("password=hunter\u{2028}2") == "password=[redacted]\n[redacted]")
        #expect(redactor.redact("password=hunter\u{0B}2\nstatus=3") == "password=[redacted]\n[redacted]\nstatus=3")
    }
}
