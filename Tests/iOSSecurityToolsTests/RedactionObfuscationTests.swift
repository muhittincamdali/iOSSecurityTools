import Testing
@testable import iOSSecurityTools

/// Field names and separators written to get past the redactor: look-alike letters, styled
/// letters, escapes and unusual whitespace.
@Suite("SensitiveDataRedactor obfuscated names")
struct RedactionObfuscationTests {
    let redactor = SensitiveDataRedactor()

    @Test("reads look-alike, styled and accented letters as Latin", arguments: [
        ("p\u{0430}ssword=hunter2", "p\u{0430}ssword=[redacted]"),
        ("\u{0440}assword=hunter2", "\u{0440}assword=[redacted]"),
        ("passw\u{043E}rd=hunter2", "passw\u{043E}rd=[redacted]"),
        ("{\"p\u{0430}ssword\":\"hunter2\"}", "{\"p\u{0430}ssword\":\"[redacted]\"}"),
        ("t\u{043E}ken=hunter2", "t\u{043E}ken=[redacted]"),
        ("s\u{0435}cret=hunter2", "s\u{0435}cret=[redacted]"),
        ("\u{0430}pi_key=hunter2", "\u{0430}pi_key=[redacted]"),
        ("\u{0420}\u{0410}SSWORD=hunter2", "\u{0420}\u{0410}SSWORD=[redacted]"),
        ("t\u{03BF}ken=hunter2", "t\u{03BF}ken=[redacted]"),
        ("\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=hunter2",
         "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=[redacted]"),
        ("\u{24DF}assword=hunter2", "\u{24DF}assword=[redacted]"),
        ("p\u{00E1}ssword=hunter2", "p\u{00E1}ssword=[redacted]"),
        ("password\u{FE13}hunter2", "password\u{FE13}[redacted]"),
        ("pa\u{00DF}word=hunter2", "pa\u{00DF}word=[redacted]"),
    ])
    func lookAlikeLetters(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a value spelled with letters that expand keeps whole characters")
    func expandedLetters() {
        #expect(redactor.redact("password=stra\u{00DF}e next") == "password=[redacted] next")
        #expect(redactor.redact("token=\u{FB01}le next") == "token=[redacted] next")
    }

    @Test("words in other scripts stay as they are", arguments: [
        "\u{0442}\u{043E}\u{043A}\u{0435}\u{043D}: \u{043D}\u{0435}\u{0442}",
        "caf\u{00E9}=open",
        "stra\u{00DF}e=Hauptstra\u{00DF}e 1",
        "\u{30D1}\u{30B9}\u{30EF}\u{30FC}\u{30C9}\u{3092}\u{5909}\u{66F4}\u{3057}\u{307E}\u{3057}\u{305F}",
    ])
    func otherScripts(input: String) {
        #expect(redactor.redact(input) == input)
    }

    // A name that mixes Latin with a letter the redactor cannot read as Latin may spell a secret
    // name it does not recognize, so the redactor fails closed and hides the value.
    @Test("hides the value of a name that mixes Latin with letters it cannot read", arguments: [
        ("passw\u{0434}rd=hunter2", "passw\u{0434}rd=[redacted]"),
        ("{\"p\u{0444}ss\":\"hunter2\"}", "{\"p\u{0444}ss\":\"[redacted]\"}"),
        ("user_\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}: hunter2", "user_\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}: [redacted]"),
        ("t\u{0254}ken=hunter2", "t\u{0254}ken=[redacted]"),
        ("<passw\u{0434}rd>hunter2</passw\u{0434}rd>", "<passw\u{0434}rd>[redacted]</passw\u{0434}rd>"),
    ])
    func mixedScripts(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a name written in one other script is not mixed")
    func singleScript() {
        let russian = "\u{0441}\u{0442}\u{0430}\u{0442}\u{0443}\u{0441}=ok"
        #expect(redactor.redact(russian) == russian)
        #expect(redactor.redact("user=\u{0430}\u{043B}\u{0438}\u{0441}\u{0430}") == "user=\u{0430}\u{043B}\u{0438}\u{0441}\u{0430}")
    }

    @Test("decodes escaped letters in a name", arguments: [
        ("pass%77ord=hunter2", "pass%77ord=[redacted]"),
        ("%70%61%73%73%77%6F%72%64=hunter2", "%70%61%73%73%77%6F%72%64=[redacted]"),
        ("p&#97;ssword=hunter2", "p&#97;ssword=[redacted]"),
        ("p&#x61;ssword=hunter2", "p&#x61;ssword=[redacted]"),
        ("{\"pass\\u0077ord\":\"hunter2\"}", "{\"pass\\u0077ord\":\"[redacted]\"}"),
        ("password&#61;hunter2", "password&#61;[redacted]"),
        ("password\\u003Ahunter2", "password\\u003A[redacted]"),
        ("password=abc&#100;ef next", "password=[redacted] next"),
        ("password=hunter%32 next", "password=[redacted] next"),
    ])
    func escapedLetters(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("escapes of characters that end a value are not decoded")
    func escapedTerminators() {
        #expect(redactor.redact("password=a%26b%20c next") == "password=[redacted] next")
        #expect(redactor.redact("note=50%25 of %ZZ & more") == "note=50%25 of %ZZ & more")
    }

    @Test("reads a secret word split by a dot or by spaces", arguments: [
        ("pass.word=hunter2", "pass.word=[redacted]"),
        ("api.key=hunter2", "api.key=[redacted]"),
        ("client.secret=hunter2", "client.secret=[redacted]"),
        ("user.session=abc", "user.session=[redacted]"),
        ("pass word=hunter2", "pass word=[redacted]"),
        ("pass  word=hunter2", "pass  word=[redacted]"),
        ("p a s s w o r d=hunter2", "p a s s w o r d=[redacted]"),
        ("API key: hunter2", "API key: [redacted]"),
        ("Session ID: abc123", "Session ID: [redacted]"),
        ("{\"api key\":\"hunter2\"}", "{\"api key\":\"[redacted]\"}"),
    ])
    func splitNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret word that ends before the last part of a name names something else", arguments: [
        "token.type=Bearer",
        "token.example.com:443",
        "password.length=12",
        "pass rate=0.9",
        "the token count: 5",
        "a long bypassword x=1",
    ])
    func dottedAndSpacedNonSecrets(input: String) {
        #expect(redactor.redact(input) == input)
    }
}
