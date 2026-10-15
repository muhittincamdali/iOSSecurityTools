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
}
