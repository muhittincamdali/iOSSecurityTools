import Foundation
import Testing
@testable import iOSSecurityTools

/// The fifteenth correctness review's generated inputs and its usefulness check.
///
/// Letters, marks and numbers whose compatibility form holds ASCII punctuation or a space (`⑴` is
/// `(1)`, `🄁` is `0,`, `ͺ` is a space and a mark) are read as one character outside ASCII, never
/// as that punctuation: the scanning copy split `🄁user=…` at the comma, and the free-text rule
/// read `user` as an allowed key where the text holds `🄁user`. Since the twenty-first review they
/// are outside the safe alphabet as well, so free text is cut where they stand.
/// Letters and marks that look like separators (`ǂ`, `ꞌ`, `ः`) are letters and marks, so a name
/// before them has no separator; a modifier letter that looks like one (`ː`) cuts the text after
/// ASCII.
@Suite("SensitiveDataRedactor fifteenth review generated inputs")
struct RedactionFifteenthReviewGeneratedTests {
    static let secret = "Qz9Wk7rX"

    /// The letters, marks and numbers outside ASCII whose compatibility form holds ASCII that is
    /// not a letter or digit.
    static let punctuatedScalars: [Unicode.Scalar] = (0x80...0x1FFFF).compactMap { value in
        guard let scalar = Unicode.Scalar(UInt32(value)), ScalarClass.isLetterOrNumber(scalar), !ScalarClass.isInvisible(scalar),
              !scalar.properties.isDefaultIgnorableCodePoint
        else { return nil }
        let form = String(scalar).decomposedStringWithCompatibilityMapping.unicodeScalars
        return form.contains { $0.isASCII && !ASCII.isAlphanumeric(UInt8($0.value)) } ? scalar : nil
    }

    @Test("a letter, mark or number is never read as punctuation or a space, and is outside the safe alphabet")
    func readings() {
        #expect(Self.punctuatedScalars.count > 60)
        let compatibility = CompatibilityText()
        for scalar in Self.punctuatedScalars {
            #expect(Array(compatibility.reading(scalar).bytes) == [CompatibilityText.unreadable], "\(String(format: "%04X", scalar.value))")
            #expect(compatibility.reading(scalar).alphabet == .unsafe, "\(String(format: "%04X", scalar.value))")
        }
        // Punctuation outside the safe alphabet keeps its reading, which the value detectors use.
        #expect(Array(compatibility.reading("\u{FF20}").bytes) == Array("@".utf8))
        #expect(Array(compatibility.reading("\u{FF1D}").bytes) == Array("=".utf8))
    }

    /// The review's templates whose trigger comes before the value: a key that is not plain
    /// ASCII or not allowed, a secret name, an open bracket, a tag, a URL that is not clean.
    static let triggering: [@Sendable (String) -> String] = [
        { "\($0)user=\(secret)" }, { "user\($0)=\(secret)" }, { "note=a\($0)password \(secret)" }, { "note=(\($0) password=\(secret)" },
        { "<a\($0)password>\(secret)</a>" }, { "\"user\($0)\": \"\(secret)\"" }, { "https://x.example/a\($0)?token=\(secret)" },
        { "https://x.example/a\($0)b/\(secret) tail" }, { "note=\($0)pass word \(secret)" }, { "x=\($0)\(secret)" },
    ]

    @Test("no value after a trigger shows, whatever such a scalar stands next to")
    func triggersHide() {
        let redactors = [SensitiveDataRedactor(), SensitiveDataRedactor(allowedTextKeys: ["note", "user"])]
        for scalar in Self.punctuatedScalars {
            for template in Self.triggering {
                let input = template(String(scalar))
                for redactor in redactors {
                    let output = redactor.redact(input)
                    #expect(!output.contains(Self.secret), "\(input.debugDescription) -> \(output.debugDescription)")
                }
            }
        }
    }

    static let lookalikes = ["\u{02D0}", "\u{02D1}", "\u{A4FD}", "\u{01C2}", "\u{A60C}", "\u{0903}", "\u{02BA}", "\u{02F8}", "\u{1D3A}", "\u{0C83}",
                             "\u{05C3}", "\u{0F0D}", "\u{30FC}", "\u{A78C}", "\u{02B9}", "\u{02EE}", "\u{1427}", "\u{16EB}", "\u{0589}"]
    static let names = ["пароль", "密码", "パスワード", "비밀번호", "şifre", "contraseña", "kennwort", "user", "x", "токен", "κωδικός", "סיסמה", "كلمة"]

    @Test("a look-alike separator after a key that is not allowed hides the value, and one outside the alphabet always does")
    func lookalikes() {
        let redactor = SensitiveDataRedactor()
        for separator in Self.lookalikes {
            for name in Self.names {
                // Outside the alphabet where it stands: a modifier letter after ASCII, punctuation.
                let isOutside = FreeTextScanner.firstUnsafeOffset(in: Array((name + separator).unicodeScalars)) != nil
                for gap in ["", " "] {
                    #expect(!redactor.redact("note=ok " + name + separator + gap + Self.secret).contains(Self.secret))
                    if isOutside {
                        #expect(!redactor.redact(name + separator + gap + Self.secret).contains(Self.secret), "\(name)\(separator)")
                    }
                }
            }
        }
        // A letter or mark that looks like a separator is a letter or mark: `user` before it has no
        // separator, as in `user hunter2`, and names no secret.
        for separator in ["\u{01C2}", "\u{A78C}", "\u{0903}"] {
            #expect(redactor.redact("user" + separator + " " + Self.secret) == "user" + separator + " " + Self.secret)
        }
    }

    @Test("ordinary log lines and bodies stay useful", arguments: [
        ("status=200 method=GET path=/v1/items duration_ms=12 count=3", "status=200 method=GET path=/v1/items duration_ms=12 count=3"),
        ("status=200 user_id=42 region=eu-west-1", "status=200 user_id=42 region=eu-west-1"),
        ("request finished in 12 ms", "request finished in 12 ms"),
        ("GET https://api.example/v1/items status=200", "GET https://api.example/v1/items status=200"),
        ("GET https://api.example/v1/items?page=2 status=200", "GET [redacted]"),
        ("started at 12:30:45 on 2026-10-19T12:30:45Z from 10.0.0.1:8080", "started at 12:30:45 on 2026-10-19T12:30:45Z from 10.0.0.1:8080"),
        ("Kullanıcı girişi başarılı oldu", "Kullanıcı girişi başarılı oldu"),
        ("ユーザーがログインしました", "ユーザーがログインしました"),
        ("user logged in: alice", "user logged in: [redacted]"),
        ("{\"status\":200,\"count\":3}", "{\"status\":200,\"count\":3}"),
    ])
    func usefulText(input: String, expected: String) {
        let redactor = SensitiveDataRedactor(allowedTextKeys: ["user_id", "region"], allowedQueryParameters: ["page"])
        #expect(redactor.redact(input) == expected)
    }
}
