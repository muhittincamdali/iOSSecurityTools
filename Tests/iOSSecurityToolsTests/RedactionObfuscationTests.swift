import Testing
@testable import iOSSecurityTools

/// Field names written to get past the redactor: look-alike letters, styled letters, invisible
/// characters, escapes, punctuation and unusual whitespace.
@Suite("SensitiveDataRedactor obfuscated names")
struct RedactionObfuscationTests {
    let redactor = SensitiveDataRedactor()

    @Test("hides the value of a name with letters outside ASCII", arguments: [
        ("p\u{0430}ssword=hunter2", "p\u{0430}ssword=[redacted]"),
        ("\u{0440}assword=hunter2", "\u{0440}assword=[redacted]"),
        ("{\"p\u{0430}ssword\":\"hunter2\"}", "{[redacted]"),
        ("\u{0420}\u{0410}SSWORD=hunter2", "\u{0420}\u{0410}SSWORD=[redacted]"),
        ("t\u{03BF}ken=hunter2", "t\u{03BF}ken=[redacted]"),
        ("t\u{0254}ken=hunter2", "t\u{0254}ken=[redacted]"),
        ("\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=hunter2",
         "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=[redacted]"),
        ("\u{24DF}assword=hunter2", "[redacted]"),
        ("\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}=hunter2", "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}=[redacted]"),
        ("p\u{00E1}ssword=hunter2", "p\u{00E1}ssword=[redacted]"),
        ("pa\u{00DF}word=hunter2", "pa\u{00DF}word=[redacted]"),
        ("user_\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}: hunter2", "user_\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}: [redacted]"),
        // Markup cuts the text at its tag, whatever the tag spells.
        ("<passw\u{0434}rd>hunter2</passw\u{0434}rd>", "[redacted]"),
    ])
    func lettersOutsideASCII(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // No list of look-alikes is complete, so a name in another script is not compared at all:
    // its value is hidden even when the name means nothing secret.
    @Test("hides the value of a name written in another script", arguments: [
        ("\u{0442}\u{043E}\u{043A}\u{0435}\u{043D}: \u{043D}\u{0435}\u{0442}", "\u{0442}\u{043E}\u{043A}\u{0435}\u{043D}: [redacted]"),
        ("\u{0441}\u{0442}\u{0430}\u{0442}\u{0443}\u{0441}=ok", "\u{0441}\u{0442}\u{0430}\u{0442}\u{0443}\u{0441}=[redacted]"),
        ("caf\u{00E9}=open", "caf\u{00E9}=[redacted]"),
        ("stra\u{00DF}e=Hauptstra\u{00DF}e 1", "stra\u{00DF}e=[redacted]"),
        ("\u{6CE8}\u{610F}\u{FF1A}\u{8BF7}\u{7A0D}\u{5019}", "\u{6CE8}\u{610F}[redacted]"),
    ])
    func otherScriptNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("text in other scripts without a field stays as it is", arguments: [
        "\u{30D1}\u{30B9}\u{30EF}\u{30FC}\u{30C9}\u{3092}\u{5909}\u{66F4}\u{3057}\u{307E}\u{3057}\u{305F}",
        "Merhaba d\u{00FC}nya status=200",
        "\u{6771}\u{4EAC} 3:00",
        "\u{4F60}\u{597D} \u{4E16}\u{754C}",
        "\u{0E20}\u{0E32}\u{0E29}\u{0E32}\u{0E44}\u{0E17}\u{0E22}\u{0E46}",
    ])
    func otherScriptText(input: String) {
        #expect(redactor.redact(input) == input)
    }

    // Punctuation and symbols outside ASCII, East Asian ones and currency signs included, are
    // outside the safe alphabet: they cut the text, whatever script it is in.
    @Test("punctuation and symbols outside ASCII cut text in any script", arguments: [
        ("\u{4F60}\u{597D}\u{3001}\u{4E16}\u{754C}", "\u{4F60}\u{597D}[redacted]"),
        ("\u{6771}\u{4EAC}\u{30FB}\u{5927}\u{962A}", "\u{6771}\u{4EAC}[redacted]"),
        ("100\u{20AC}/month", "100[redacted]"),
        ("pass\u{30FC}word hunter2", "pass[redacted]"),
    ])
    func otherScriptPunctuation(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("hides the value of a name with invisible characters or marks", arguments: [
        ("pass\u{200B}word=hunter2", "[redacted]"),
        ("pass\u{2060}word=hunter2", "[redacted]"),
        ("pass\u{00AD}word=hunter2", "[redacted]"),
        ("pa\u{FE0F}ssword=hunter2", "pa[redacted]"),
        ("pa\u{0301}ssword=hunter2", "pa\u{0301}ssword=[redacted]"),
        ("\u{202E}drowssap=hunter2", "[redacted]"),
        ("pass\u{E0061}word=hunter2", "[redacted]"),
        ("password \u{200B}= hunter2", "password [redacted]"),
        ("password=\u{0301}hunter2", "password=[redacted]"),
    ])
    func invisibleCharacters(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("hides the value of a name with escapes", arguments: [
        ("pass%77ord=hunter2", "[redacted]"),
        ("%70%61%73%73%77%6F%72%64=hunter2", "[redacted]"),
        ("p&#97;ssword=hunter2", "[redacted]"),
        ("p&#x61;ssword=hunter2", "[redacted]"),
        ("&quot;password&quot;:&quot;hunter2&quot;", "[redacted]"),
        ("{\"pass\\u0077ord\":\"hunter2\"}", "{[redacted]"),
        ("log {\"pass\\u0077ord\":\"hunter2\"}", "log {[redacted]"),
        ("password=abc&#100;ef next=1", "password=[redacted]"),
        ("password=hunter%32 next=1", "password=[redacted]"),
    ])
    func escapedNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // An escape is never decoded in free text: the word it is in cuts the text.
    @Test("= and : written as escapes cut the text at the word they are in", arguments: [
        ("password&#61;hunter2", "[redacted]"),
        ("password&equals;hunter2", "password[redacted]"),
        ("password&colon;hunter2", "password[redacted]"),
        ("password\\u003Ahunter2", "[redacted]"),
        ("password\\x3Dhunter2", "[redacted]"),
        ("password%253Dhunter2", "[redacted]"),
        ("password%25253Ahunter2", "[redacted]"),
        ("user&Colon;bob", "[redacted]"),
        ("user&coloneq;bob", "[redacted]"),
        ("user&amp;equals;bob", "[redacted]"),
        ("mail alice&commat;example.com", "mail [redacted]"),
        ("user\\075bob", "[redacted]"),
        ("user\\072bob", "[redacted]"),
        ("user\\N{COLON}bob", "[redacted]"),
        ("user\\U0000003Dbob", "[redacted]"),
        ("status=200&count=3", "status=200&count=3"),
    ])
    func escapedSeparators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("escapes of characters that end a value are not decoded")
    func escapedTerminators() {
        #expect(redactor.redact("password=a%26b%20c next=1") == "password=[redacted]")
        #expect(redactor.redact("count=50% of %ZZ & more") == "count=50% of %ZZ & more")
        #expect(redactor.redact("count=50%25 of %ZZ & more") == "count=[redacted]")
    }

    @Test("folds . like _ and - and still finds the secret word", arguments: [
        ("pass.word=hunter2", "pass.word=[redacted]"),
        ("api.key=hunter2", "api.key=[redacted]"),
        ("client.secret=hunter2", "client.secret=[redacted]"),
        ("user.session=abc", "user.session=[redacted]"),
        ("{\"api key\":\"hunter2\"}", "{[redacted]"),
    ])
    func foldedNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // Punctuation outside ASCII may be a separator: the value is hidden from there.
    @Test("hides the value of a name with punctuation other than _, -, . and spaces", arguments: [
        ("pass/word=hunter2", "pass/word=[redacted]"),
        ("pass#word=hunter2", "pass#word=[redacted]"),
        ("pass\u{00B7}word=hunter2", "pass[redacted]"),
        ("pass\"word\"=hunter2", "pass\"[redacted]"),
        ("\"pass\"word: hunter2", "\"pass\"[redacted]"),
    ])
    func punctuationInNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // `pass` is a secret word of its own; split names are read with the next word.
    @Test("reads a secret word split by whitespace", arguments: [
        ("pass word=hunter2", "pass [redacted]"),
        ("pass  word=hunter2", "pass  [redacted]"),
        ("pass\tword=hunter2", "pass\t[redacted]"),
        // U+00A0 is outside the safe alphabet, so the text is cut there, before the cut that the
        // split name makes after it.
        ("pass\u{00A0}word=hunter2", "pass[redacted]"),
        ("p a s s w o r d=hunter2", "p a s s w o r d=[redacted]"),
        ("pa.ss word=hunter2", "pa.ss [redacted]"),
        ("API key: hunter2", "API key: [redacted]"),
        ("Session ID: abc123", "Session [redacted]"),
        ("to ken hunter2", "to ken [redacted]"),
        ("my pa ssword hunter2", "my pa ssword [redacted]"),
        ("c|vv | 123", "c|vv [redacted]"),
        ("verification code 123456", "verification code [redacted]"),
    ])
    func splitNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret word split by whitespace inside a longer name", arguments: [
        ("mypa ssword=hunter2", "mypa ssword=[redacted]"),
        ("myto ken=hunter2", "myto ken=[redacted]"),
        ("mysec ret=hunter2", "mysec ret=[redacted]"),
        ("myapi Key: hunter2", "myapi Key: [redacted]"),
        ("dbp wd=hunter2", "dbp wd=[redacted]"),
        ("mypa* ss=hunter2", "mypa* ss=[redacted]"),
        ("mypa ssword hunter2", "mypa ssword [redacted]"),
    ])
    func splitInsideLongerName(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a word that cannot be read hides the rest of its line", arguments: [
        ("p\u{0430}ss word=hunter2", "[redacted]"),
        ("login pa\u{115F}ssword hunter2 ok", "login [redacted]"),
        ("login pa\u{7F}ssword hunter2 ok", "login [redacted]"),
        ("got Bearer\u{3164}abc123", "got [redacted]"),
        ("mail alice\u{115F}smith@example.com", "mail [redacted]"),
        // A letter without an ASCII form may stand for any letter of a secret word.
        ("login Authoriz\u{0251}tion hunter2", "login Authoriz\u{0251}tion [redacted]"),
    ])
    func unreadableWords(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret word hides the rest of its line, also before a pair", arguments: [
        ("pass rate=0.9", "pass [redacted]"),
        ("the token count: 5", "the token [redacted]"),
        ("a long bypassword x=1", "a long bypassword [redacted]"),
        ("Authorization failed for user=bob", "Authorization [redacted]"),
        ("p%61ss word=hunter2", "[redacted]"),
    ])
    func secretWordsBeforePairs(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("words that only hold the letters of a secret word are left alone", arguments: [
        "compass heading north", "user id 42", "v1.2 status=5", "GET /api/v1 status=7", "keyboard layout changed",
        "Kullan\u{0131}c\u{0131} giri\u{015F} yapt\u{0131}",
    ])
    func wordsWithoutSecrets(input: String) {
        #expect(redactor.redact(input) == input)
    }
}
