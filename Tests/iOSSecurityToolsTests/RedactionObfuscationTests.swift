import Testing
@testable import iOSSecurityTools

/// Field names and separators written to get past the redactor: look-alike letters, styled
/// letters, invisible characters, escapes, punctuation and unusual whitespace.
@Suite("SensitiveDataRedactor obfuscated names")
struct RedactionObfuscationTests {
    let redactor = SensitiveDataRedactor()

    @Test("hides the value of a name with letters outside ASCII", arguments: [
        ("p\u{0430}ssword=hunter2", "p\u{0430}ssword=[redacted]"),
        ("\u{0440}assword=hunter2", "\u{0440}assword=[redacted]"),
        ("{\"p\u{0430}ssword\":\"hunter2\"}", "{\"p\u{0430}ssword\":\"[redacted]\"}"),
        ("\u{0420}\u{0410}SSWORD=hunter2", "\u{0420}\u{0410}SSWORD=[redacted]"),
        ("t\u{03BF}ken=hunter2", "t\u{03BF}ken=[redacted]"),
        ("t\u{0254}ken=hunter2", "t\u{0254}ken=[redacted]"),
        ("\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=hunter2",
         "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=[redacted]"),
        ("\u{24DF}assword=hunter2", "\u{24DF}assword=[redacted]"),
        ("\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}=hunter2", "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}=[redacted]"),
        ("p\u{00E1}ssword=hunter2", "p\u{00E1}ssword=[redacted]"),
        ("pa\u{00DF}word=hunter2", "pa\u{00DF}word=[redacted]"),
        ("user_\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}: hunter2", "user_\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}: [redacted]"),
        ("<passw\u{0434}rd>hunter2</passw\u{0434}rd>", "<passw\u{0434}rd>[redacted]</passw\u{0434}rd>"),
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
        ("stra\u{00DF}e=Hauptstra\u{00DF}e 1", "stra\u{00DF}e=[redacted] 1"),
        ("\u{6CE8}\u{610F}\u{FF1A}\u{8BF7}\u{7A0D}\u{5019}", "\u{6CE8}\u{610F}\u{FF1A}[redacted]"),
    ])
    func otherScriptNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("text in other scripts without a field stays as it is", arguments: [
        "\u{30D1}\u{30B9}\u{30EF}\u{30FC}\u{30C9}\u{3092}\u{5909}\u{66F4}\u{3057}\u{307E}\u{3057}\u{305F}",
        "Merhaba d\u{00FC}nya user=bob",
        "\u{6771}\u{4EAC} 3:00",
        "\u{4F60}\u{597D}\u{3001}\u{4E16}\u{754C}",
        "user=\u{0430}\u{043B}\u{0438}\u{0441}\u{0430}",
    ])
    func otherScriptText(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("hides the value of a name with invisible characters or marks", arguments: [
        ("pass\u{200B}word=hunter2", "pass\u{200B}word=[redacted]"),
        ("pass\u{2060}word=hunter2", "pass\u{2060}word=[redacted]"),
        ("pass\u{00AD}word=hunter2", "pass\u{00AD}word=[redacted]"),
        ("pa\u{FE0F}ssword=hunter2", "pa\u{FE0F}ssword=[redacted]"),
        ("pa\u{0301}ssword=hunter2", "pa\u{0301}ssword=[redacted]"),
        ("\u{202E}drowssap=hunter2", "\u{202E}drowssap=[redacted]"),
        ("pass\u{E0061}word=hunter2", "pass\u{E0061}word=[redacted]"),
        ("password \u{200B}= hunter2", "password \u{200B}= [redacted]"),
        ("password=\u{0301}hunter2", "password=[redacted]"),
    ])
    func invisibleCharacters(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("hides the value of a name with escapes", arguments: [
        ("pass%77ord=hunter2", "pass%77ord=[redacted]"),
        ("%70%61%73%73%77%6F%72%64=hunter2", "%70%61%73%73%77%6F%72%64=[redacted]"),
        ("p&#97;ssword=hunter2", "p&#97;ssword=[redacted]"),
        ("p&#x61;ssword=hunter2", "p&#x61;ssword=[redacted]"),
        ("&quot;password&quot;:&quot;hunter2&quot;", "&quot;password&quot;:[redacted]"),
        ("{\"pass\\u0077ord\":\"hunter2\"}", "{\"pass\\u0077ord\":\"[redacted]\"}"),
        ("log {\"pass\\u0077ord\":\"hunter2\"}", "log {\"pass\\u0077ord\":\"[redacted]\"}"),
        ("password=abc&#100;ef next", "password=[redacted] next"),
        ("password=hunter%32 next", "password=[redacted] next"),
    ])
    func escapedNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("reads = and : written as escapes", arguments: [
        ("password&#61;hunter2", "password&#61;[redacted]"),
        ("password&equals;hunter2", "password&equals;[redacted]"),
        ("password&colon;hunter2", "password&colon;[redacted]"),
        ("password\\u003Ahunter2", "password\\u003A[redacted]"),
        ("password\\x3Dhunter2", "password\\x3D[redacted]"),
        ("password%253Dhunter2", "password%253D[redacted]"),
        ("password%25253Ahunter2", "password%25253A[redacted]"),
    ])
    func escapedSeparators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("escapes of characters that end a value are not decoded")
    func escapedTerminators() {
        #expect(redactor.redact("password=a%26b%20c next") == "password=[redacted] next")
        #expect(redactor.redact("note=50%25 of %ZZ & more") == "note=50%25 of %ZZ & more")
    }

    @Test("hides the value of a name with punctuation other than _ and -", arguments: [
        ("pass.word=hunter2", "pass.word=[redacted]"),
        ("api.key=hunter2", "api.key=[redacted]"),
        ("client.secret=hunter2", "client.secret=[redacted]"),
        ("user.session=abc", "user.session=[redacted]"),
        ("token.type=Bearer", "token.type=[redacted]"),
        ("password.length=12", "password.length=[redacted]"),
        ("pass/word=hunter2", "pass/word=[redacted]"),
        ("pass#word=hunter2", "pass#word=[redacted]"),
        ("pass\u{00B7}word=hunter2", "pass\u{00B7}[redacted]"),
        ("{\"api key\":\"hunter2\"}", "{\"api key\":\"[redacted]\"}"),
        ("pass\"word\"=hunter2", "pass\"word\"=[redacted]"),
        ("\"pass\"word: hunter2", "\"pass\"word: [redacted]"),
    ])
    func punctuationInNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("reads a secret word split by whitespace", arguments: [
        ("pass word=hunter2", "pass word=[redacted]"),
        ("pass  word=hunter2", "pass  word=[redacted]"),
        ("pass\tword=hunter2", "pass\tword=[redacted]"),
        ("pass\u{00A0}word=hunter2", "pass\u{00A0}word=[redacted]"),
        ("p a s s w o r d=hunter2", "p a s s w o r d=[redacted]"),
        ("pa.ss word=hunter2", "pa.ss word=[redacted]"),
        ("API key: hunter2", "API key: [redacted]"),
        ("Session ID: abc123", "Session ID: [redacted]"),
        ("INFO user=bob pass word=hunter2", "INFO user=bob pass word=[redacted]"),
    ])
    func splitNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // A word before the name that is not plain ASCII could spell the start of a secret word.
    @Test("a word before a name that cannot be read could start a secret word", arguments: [
        ("p\u{0430}ss word=hunter2", "p\u{0430}ss word=[redacted]"),
        ("\u{0440}\u{0430}\u{0455}\u{0455} word=hunter2", "\u{0440}\u{0430}\u{0455}\u{0455} word=[redacted]"),
        ("p%61ss word=hunter2", "p%61ss word=[redacted]"),
        ("\u{041F}\u{043E}\u{043B}\u{044C}\u{0437}\u{043E}\u{0432}\u{0430}\u{0442}\u{0435}\u{043B}\u{044C} id=42", "\u{041F}\u{043E}\u{043B}\u{044C}\u{0437}\u{043E}\u{0432}\u{0430}\u{0442}\u{0435}\u{043B}\u{044C} id=[redacted]"),
    ])
    func unreadableWordsBefore(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("words before a name that cannot start its secret word are not read with it", arguments: [
        "pass rate=0.9",
        "the token count: 5",
        "a long bypassword x=1",
        "compass heading=north",
        "user id=42",
        "v1.2 id=5",
        "GET /api/v1 id=7",
        "Authorization failed for user=bob",
    ])
    func wordsBefore(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("punctuation outside ASCII after a secret name is a separator", arguments: [
        ("password\u{A789}hunter2", "password\u{A789}[redacted]"),
        ("password \u{A789} hunter2", "password \u{A789} [redacted]"),
        ("password\u{02F8}hunter2", "password\u{02F8}[redacted]"),
        ("password\u{0589}hunter2", "password\u{0589}[redacted]"),
        ("token\u{2192}hunter2", "token\u{2192}[redacted]"),
        ("\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}\u{A789}hunter2",
         "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}\u{A789}[redacted]"),
        ("pass\u{200B}word\u{A789}hunter2", "pass\u{200B}word\u{A789}[redacted]"),
        ("password\u{FE13}hunter2", "password\u{FE13}[redacted]"),
    ])
    func lookAlikeSeparators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // The look-alike separator may sit inside the name, so where the name and the value end
    // cannot be told: the rest of the line goes, and the next line too when the line ends with a
    // separator.
    @Test("a look-alike separator after a secret name hides the rest of the line", arguments: [
        ("pass\u{00B7}word='hunter2' next", "pass\u{00B7}[redacted]"),
        ("pass\u{2027}wd: hunter2", "pass\u{2027}[redacted]"),
        ("SECRET_K\u{2010}EY=hunter2\nnext", "SECRET_K\u{2010}[redacted]\nnext"),
        ("pa\u{00AD}ss\u{00B7}word :\n  <hunter2> next", "pa\u{00AD}ss\u{00B7}[redacted]"),
        ("DB_SECRET_KE\u{2010}Y\n=\n<hunter2>", "DB_SECRET_KE\u{2010}[redacted]\n=\n[redacted]"),
    ])
    func lookAlikeSeparatorInName(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a value that ends in a separator does not hide what follows", arguments: [
        ("pass:word: hunter2", "pass:[redacted]: [redacted]"),
        ("pass:word='hunter2' next", "pass:[redacted] next"),
        ("password=x\"hunter2\" next", "password=[redacted] next"),
        ("token=YWJj== user=bob", "token=[redacted] user=bob"),
        ("<password:>hunter2</password:>", "<password:>[redacted]</password:>"),
        ("password=)hunter2 next", "password=)[redacted] next"),
    ])
    func valuesEndingInSeparators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a secret word split by whitespace inside a longer name", arguments: [
        ("mypa ssword=hunter2", "mypa ssword=[redacted]"),
        ("myto ken=hunter2", "myto ken=[redacted]"),
        ("mysec ret=hunter2", "mysec ret=[redacted]"),
        ("myapi Key: hunter2", "myapi Key: [redacted]"),
        ("dbp wd=hunter2", "dbp wd=[redacted]"),
        ("mypa* ss=hunter2", "mypa* ss=[redacted]"),
    ])
    func splitInsideLongerName(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("punctuation outside ASCII after other names is left alone", arguments: [
        "Tokyo\u{00B7}Osaka\u{00B7}Kyoto",
        "\u{6771}\u{4EAC}\u{30FB}\u{5927}\u{962A}",
        "100\u{20AC}/month",
        "user\u{2192}bob",
    ])
    func otherPunctuation(input: String) {
        #expect(redactor.redact(input) == input)
    }

    @Test("a value spelled with letters that expand keeps whole characters")
    func expandedLetters() {
        #expect(redactor.redact("password=stra\u{00DF}e next") == "password=[redacted] next")
        #expect(redactor.redact("token=\u{FB01}le next") == "token=[redacted] next")
    }

    @Test("hides an array or object value whole", arguments: [
        ("{\"password\":[\"hunter2\"]}", "{\"password\":\"[redacted]\"}"),
        ("{\"password\":{\"v\":\"hunter2\"}}", "{\"password\":\"[redacted]\"}"),
        ("{\"token\":[\"a]\",{\"b\":[\"hunter2\"]}],\"user\":\"bob\"}", "{\"token\":\"[redacted]\",\"user\":\"bob\"}"),
        ("{\"password\": [\n  \"hunter2\"\n], \"user\": \"bob\"}", "{\"password\": \"[redacted]\", \"user\": \"bob\"}"),
        ("log {\"password\":[\"hunter2\"]}", "log {\"password\":[redacted]}"),
        ("password=[hunter2] next", "password=[redacted] next"),
        ("password={hunter2} next", "password=[redacted] next"),
        ("password=(hunter2) next", "password=[redacted] next"),
        ("{\\\"password\\\":[\\\"hunter2\\\"]}", "{\\\"password\\\":[redacted]}"),
        ("password=[redacted] next", "password=[redacted] next"),
    ])
    func structuredValues(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("an array or object that is never closed is hidden to the end of the text")
    func unclosedStructuredValue() {
        #expect(redactor.redact("{\"password\":[\"hunter2\",\n\"more\"") == "{\"password\":[redacted]")
    }

    @Test("a quoted value glued to more text is hidden with it")
    func gluedQuotedValue() {
        #expect(redactor.redact("password=\"hun\"\u{0301}ter2\" next") == "password=\"[redacted] next")
    }

    @Test("hides a value after line breaks and other whitespace", arguments: [
        ("log {\"password\":\n\"hunter2\"}", "log {\"password\":\n\"[redacted]\"}"),
        ("log {\"password\"\n:\n\"hunter2\"}", "log {\"password\"\n:\n\"[redacted]\"}"),
        ("password:\n  hunter2", "password:\n  [redacted]"),
        ("password\n= hunter2", "password\n= [redacted]"),
        ("password\u{2028}=hunter2", "password\u{2028}=[redacted]"),
        ("password\u{0085}=hunter2", "password\u{0085}=[redacted]"),
        ("password\u{000B}=hunter2", "password\u{000B}=[redacted]"),
        ("password\u{000C}=hunter2", "password\u{000C}=[redacted]"),
        ("password=hunter2\u{2028}next", "password=[redacted]\u{2028}next"),
    ])
    func lineBreaks(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("hides YAML block scalars and tagged values", arguments: [
        ("password: |\n  hunter2\n  more\nuser: bob", "password: [redacted]\nuser: bob"),
        ("password: >-\n  hunter2\n\n  more\nuser: bob", "password: [redacted]\nuser: bob"),
        ("password: !!binary aHVudGVyMg== next", "password: [redacted] next"),
        ("password: >hunter2", "password: >[redacted]"),
    ])
    func yamlValues(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a separator with no name hides the rest of its line", arguments: [
        ("=hunter2 x\nnext", "=[redacted]\nnext"),
        ("user=bob, =hunter2 x", "user=bob, =[redacted]"),
        ("<:password>b", "<:[redacted]"),
        ("=\n  hunter2\nnext", "=\n  [redacted]\nnext"),
        ("=====\nHeader\n=====", "=====\n[redacted]\n====="),
    ])
    func missingNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a name that ends in a bracket keeps its brackets and is not plain", arguments: [
        ("f(x)=5 next", "f(x)=[redacted] next"),
        ("arr[0]=5 next", "arr[0]=[redacted] next"),
        ("user=bob (pass)=hunter2 x", "user=bob (pass)=[redacted] x"),
    ])
    func bracketNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }
}
