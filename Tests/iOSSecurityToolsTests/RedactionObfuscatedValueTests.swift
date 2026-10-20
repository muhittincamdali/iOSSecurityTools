import Testing
@testable import iOSSecurityTools

/// Separators and values written to get past the redactor: look-alike separators, values glued
/// to quotes and brackets, arrays and objects, values on the lines below.
@Suite("SensitiveDataRedactor obfuscated separators and values")
struct RedactionObfuscatedValueTests {
    let redactor = SensitiveDataRedactor()

    // Punctuation outside ASCII is outside the safe alphabet: the text is cut where it is.
    @Test("punctuation outside ASCII after a secret name cuts the text there", arguments: [
        ("password\u{A789}hunter2", "password[redacted]"),
        ("password \u{A789} hunter2", "password [redacted]"),
        ("password\u{02F8}hunter2", "password[redacted]"),
        ("password\u{0589}hunter2", "password[redacted]"),
        ("token\u{2192}hunter2", "token[redacted]"),
        ("\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}\u{A789}hunter2",
         "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}[redacted]"),
        // The word before the zero-width space holds it, so it cannot be read either.
        ("pass\u{200B}word\u{A789}hunter2", "[redacted]"),
        ("password\u{FE13}hunter2", "password[redacted]"),
        ("password\u{A789} hunter2", "password[redacted]"),
        ("password\u{A789}\nhunter2", "password[redacted]"),
    ])
    func lookAlikeSeparators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // Such punctuation cuts the text whatever comes before it, also after other names and after a
    // boundary or a space, and whatever comes after it.
    @Test("punctuation outside ASCII after other words cuts the text too", arguments: [
        ("Tokyo\u{00B7}Osaka\u{00B7}Kyoto", "Tokyo[redacted]"),
        ("user\u{2192}bob", "user[redacted]"),
        ("my_k$ e%79\u{2254}S3CRETV&b=2", "my_k$ [redacted]"),
        ("a;\u{2254}S3CRETV", "a;[redacted]"),
        ("key \u{2254}S3CRETV", "key [redacted]"),
        ("user\u{A789} S3CRETV", "user[redacted]"),
        ("user \u{A789}\nS3CRETV", "user [redacted]"),
        ("[INFO] user\u{A789} S3CRETV done", "[INFO] user[redacted]"),
        ("status\u{A789} S3CRETV", "status[redacted]"),
    ])
    func lookAlikeSeparatorsAfterOtherWords(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // The look-alike separator may sit inside the name, so where the name and the value end
    // cannot be told: everything after it goes.
    @Test("a look-alike separator inside a name hides everything after it", arguments: [
        ("pass\u{00B7}word='hunter2' next", "pass[redacted]"),
        ("pass\u{2027}wd: hunter2", "pass[redacted]"),
        ("SECRET_K\u{2010}EY=hunter2\nnext", "SECRET[redacted]"),
        ("pa\u{00AD}ss\u{00B7}word :\n  <hunter2> next", "[redacted]"),
        ("DB_SECRET_KE\u{2010}Y\n=\n<hunter2>", "DB_SECRET[redacted]"),
        ("pass\u{2027}word\nS3CRETV", "pass[redacted]"),
        ("- p\u{2027}in :\n  (S3CRETV)", "- p[redacted]"),
    ])
    func lookAlikeSeparatorInName(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a value glued to separators, quotes and brackets is hidden with them", arguments: [
        ("pass:word: hunter2", "pass:[redacted]"),
        ("pass:word='hunter2' next", "pass:[redacted]"),
        ("password=x\"hunter2\" next", "password=[redacted]"),
        ("token=YWJj== user=bob", "token=[redacted]"),
        ("<password:>hunter2</password:>", "<password:[redacted]"),
        ("password=)hunter2 next", "password=[redacted]"),
    ])
    func valuesEndingInSeparators(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a value spelled with letters that expand keeps whole characters")
    func expandedLetters() {
        #expect(redactor.redact("password=stra\u{00DF}e next=1") == "password=[redacted]")
        #expect(redactor.redact("token=\u{FB01}le next=1") == "token=[redacted]")
        #expect(redactor.redact("status=\u{FB01}le password=x") == "status=\u{FB01}le password=[redacted]")
    }

    @Test("hides an array or object value whole", arguments: [
        ("{\"password\":[\"hunter2\"]}", "{[redacted]"),
        ("{\"password\":{\"v\":\"hunter2\"}}", "{[redacted]"),
        ("{\"token\":[\"a]\",{\"b\":[\"hunter2\"]}],\"user\":\"bob\"}", "{[redacted]"),
        ("{\"password\": [\n  \"hunter2\"\n], \"user\": \"bob\"}", "{[redacted]"),
        ("log {\"password\":[\"hunter2\"]}", "log {[redacted]"),
        ("password=[hunter2] next", "password=[redacted]"),
        ("password={hunter2} next", "password=[redacted]"),
        ("password=(hunter2) next", "password=[redacted]"),
        ("{\\\"password\\\":[\\\"hunter2\\\"]}", "{[redacted]"),
        ("password=[redacted] next", "password=[redacted]"),
    ])
    func structuredValues(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("an array or object that is never closed is hidden to the end of the text")
    func unclosedStructuredValue() {
        #expect(redactor.redact("{\"password\":[\"hunter2\",\n\"more\"") == "[redacted]")
    }

    @Test("a quoted value glued to more text is hidden with it")
    func gluedQuotedValue() {
        #expect(redactor.redact("password=\"hun\"\u{0301}ter2\" next") == "password=[redacted]")
        // The quote that seemed to close the value may have opened another one.
        #expect(redactor.redact("msg=\"a=\"b\nS3CRETV\"\"\nstatus=2") == "msg=[redacted]")
    }

    @Test("hides a value after line breaks and other whitespace", arguments: [
        ("log {\"password\":\n\"hunter2\"}", "log {[redacted]"),
        ("log {\"password\"\n:\n\"hunter2\"}", "log {[redacted]"),
        ("password:\n  hunter2", "password:[redacted]"),
        ("password\n= hunter2", "password\n= [redacted]"),
        ("password\u{2028}=hunter2", "password[redacted]"),
        ("password\u{0085}=hunter2", "password[redacted]"),
        ("password\u{000B}=hunter2", "password[redacted]"),
        ("password\u{000C}=hunter2", "password[redacted]"),
        ("password=hunter2\u{2028}next", "password=[redacted]"),
        ("p\u{0430}ssword\nS3CRETV", "[redacted]"),
        ("<key>p\u{0430}ssword</key>\n<string>S3CRETV</string>", "<key>[redacted]"),
    ])
    func lineBreaks(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    // A line that ends open (`(`, `[`, `=`, `"""`) passes its value on to the next line; one that
    // ends with a letter, a closing quote or bracket or a full stop does not.
    @Test("a value hidden to the end of its line goes on below only when the line ends open", arguments: [
        ("user=bob msg=\"hi\"\nstatus=200", "user=[redacted]"),
        ("user=bob.\nstatus=200", "user=[redacted]"),
        ("password=(\nS3CRETV)", "password=[redacted]"),
        ("token=[\n\"S3CRETV\"\n]", "token=[redacted]"),
        // Which of the quotes in `"""` closes the value cannot be told: the lines after it go too.
        ("key=\"\"\"\nS3CRETV\n\"\"\"\nstatus=200", "key=[redacted]"),
        ("x\"y \u{2254}\"\"\"\nS3CRETV\n\"\"\"", "x\"[redacted]"),
    ])
    func openLineEnds(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("hides YAML block scalars and tagged values", arguments: [
        ("password: |\n  hunter2\n  more\nstatus: 200", "password: [redacted]"),
        ("password: >-\n  hunter2\n\n  more\nstatus: 200", "password: [redacted]"),
        ("password: |2\n   hunter2\nstatus: 200", "password: [redacted]"),
        ("password: !!binary aHVudGVyMg== next", "password: [redacted]"),
        ("password: >hunter2", "password: [redacted]"),
    ])
    func yamlValues(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a separator with no name hides the rest of its line", arguments: [
        ("=hunter2 x\nnext", "=[redacted]"),
        ("status=200, =hunter2 x", "status=200, =[redacted]"),
        ("<:password>b", "<:[redacted]"),
        ("=\n  hunter2\nnext", "=[redacted]"),
        ("=====\nHeader\n=====", "=====[redacted]"),
    ])
    func missingNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }

    @Test("a name that ends in a bracket keeps its brackets and is not plain", arguments: [
        ("f(x)=5 next=1", "f(x)=[redacted]"),
        ("arr[0]=5 next=1", "arr[0]=[redacted]"),
        ("status=200 (pass)=hunter2 x=1", "status=200 (pass)=[redacted]"),
    ])
    func bracketNames(input: String, expected: String) {
        #expect(redactor.redact(input) == expected)
    }
}
