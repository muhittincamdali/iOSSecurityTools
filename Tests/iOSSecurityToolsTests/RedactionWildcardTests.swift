import Foundation
import Testing
import iOSSecurityTools

/// The one wildcard rule: a letter, mark or number outside ASCII that has no ASCII form, inside
/// an ASCII word, counts as nothing or as any one letter (see ``LooseReading``).
///
/// The twenty-second review put a combining Latin small letter (U+0363 to U+036F, a mark: `ͦ` is
/// a small `o` written above the letter before it) in place of one letter of a secret name:
/// `login tͦken X`, `pͥn X`, `passwͦrd X`. Without a separator the name was not found in free
/// text, in a JSON string, a multipart text part, a text/plain body, after `status=200` and in a
/// URL path segment: the mark was left out like any mark, so the skeleton was the name with a
/// letter missing where no letter was left out. The twenty-third round documented it as a limit;
/// a mark now counts where it stands, as a letter without an ASCII form does, and so does a number
/// without one (`passw〇rd`). Every probe is hidden.
@Suite("SensitiveDataRedactor one wildcard for a letter, mark or number outside ASCII")
struct RedactionWildcardTests {
    enum Path: Sendable {
        case text
        case url
        case body(String)
    }

    struct Probe: Sendable, CustomTestStringConvertible {
        let id: Int
        let path: Path
        let input: String

        var value: String { "Qz\(String(format: "%03d", id))Wk5m" }
        var testDescription: String { "\(id) \(input.debugDescription)" }

        func redacted(by redactor: SensitiveDataRedactor) -> String {
            switch path {
            case .text: redactor.redact(input)
            case .url: URL(string: input).map(redactor.redact(url:)) ?? "<no URL>"
            case .body(let type): redactor.redact(body: Data(input.utf8), contentType: type)
            }
        }
    }

    /// The review's probes 332 to 336 and 652 to 737.
    static let probes: [Probe] = [
        Probe(id: 332, path: .text, input: "login passw\u{366}rd Qz332Wk5m"),
        Probe(id: 333, path: .text, input: "login t\u{366}ken Qz333Wk5m"),
        Probe(id: 334, path: .text, input: "login p\u{365}n Qz334Wk5m"),
        Probe(id: 335, path: .text, input: "login s\u{364}cret Qz335Wk5m"),
        Probe(id: 336, path: .text, input: "login \u{366}tp Qz336Wk5m"),
        Probe(id: 652, path: .text, input: "login p\u{363}ssword Qz652Wk5m"),
        Probe(id: 653, path: .text, input: "login passw\u{366}rd Qz653Wk5m"),
        Probe(id: 654, path: .text, input: "login passwo\u{36C}d Qz654Wk5m"),
        Probe(id: 655, path: .text, input: "login passwor\u{369} Qz655Wk5m"),
        Probe(id: 656, path: .text, input: "login \u{36D}oken Qz656Wk5m"),
        Probe(id: 657, path: .text, input: "login t\u{366}ken Qz657Wk5m"),
        Probe(id: 658, path: .text, input: "login tok\u{364}n Qz658Wk5m"),
        Probe(id: 659, path: .text, input: "login s\u{364}cret Qz659Wk5m"),
        Probe(id: 660, path: .text, input: "login se\u{368}ret Qz660Wk5m"),
        Probe(id: 661, path: .text, input: "login sec\u{36C}et Qz661Wk5m"),
        Probe(id: 662, path: .text, input: "login secr\u{364}t Qz662Wk5m"),
        Probe(id: 663, path: .text, input: "login secre\u{36D} Qz663Wk5m"),
        Probe(id: 664, path: .text, input: "login p\u{365}n Qz664Wk5m"),
        Probe(id: 665, path: .text, input: "login \u{366}tp Qz665Wk5m"),
        Probe(id: 666, path: .text, input: "login o\u{36D}p Qz666Wk5m"),
        Probe(id: 667, path: .text, input: "login \u{368}vv Qz667Wk5m"),
        Probe(id: 668, path: .text, input: "login c\u{36E}v Qz668Wk5m"),
        Probe(id: 669, path: .text, input: "login cv\u{36E} Qz669Wk5m"),
        Probe(id: 670, path: .text, input: "login \u{363}pikey Qz670Wk5m"),
        Probe(id: 671, path: .text, input: "login ap\u{365}key Qz671Wk5m"),
        Probe(id: 672, path: .text, input: "login apik\u{364}y Qz672Wk5m"),
        Probe(id: 673, path: .text, input: "login p\u{363}sscode Qz673Wk5m"),
        Probe(id: 674, path: .text, input: "login pass\u{368}ode Qz674Wk5m"),
        Probe(id: 675, path: .text, input: "login passc\u{366}de Qz675Wk5m"),
        Probe(id: 676, path: .text, input: "login passco\u{369}e Qz676Wk5m"),
        Probe(id: 677, path: .text, input: "login passcod\u{364} Qz677Wk5m"),
        Probe(id: 678, path: .text, input: "login \u{368}ookie Qz678Wk5m"),
        Probe(id: 679, path: .text, input: "login c\u{366}okie Qz679Wk5m"),
        Probe(id: 680, path: .text, input: "login co\u{366}kie Qz680Wk5m"),
        Probe(id: 681, path: .text, input: "login cook\u{365}e Qz681Wk5m"),
        Probe(id: 682, path: .text, input: "login cooki\u{364} Qz682Wk5m"),
        Probe(id: 683, path: .text, input: "login \u{368}redential Qz683Wk5m"),
        Probe(id: 684, path: .text, input: "login c\u{36C}edential Qz684Wk5m"),
        Probe(id: 685, path: .text, input: "login cr\u{364}dential Qz685Wk5m"),
        Probe(id: 686, path: .text, input: "login cre\u{369}ential Qz686Wk5m"),
        Probe(id: 687, path: .text, input: "login cred\u{364}ntial Qz687Wk5m"),
        Probe(id: 688, path: .text, input: "login creden\u{36D}ial Qz688Wk5m"),
        Probe(id: 689, path: .text, input: "login credent\u{365}al Qz689Wk5m"),
        Probe(id: 690, path: .text, input: "login credenti\u{363}l Qz690Wk5m"),
        Probe(id: 691, path: .text, input: "login s\u{365}gnature Qz691Wk5m"),
        Probe(id: 692, path: .text, input: "login sign\u{363}ture Qz692Wk5m"),
        Probe(id: 693, path: .text, input: "login signa\u{36D}ure Qz693Wk5m"),
        Probe(id: 694, path: .text, input: "login signat\u{367}re Qz694Wk5m"),
        Probe(id: 695, path: .text, input: "login signatu\u{36C}e Qz695Wk5m"),
        Probe(id: 696, path: .text, input: "login signatur\u{364} Qz696Wk5m"),
        Probe(id: 697, path: .text, input: "login \u{363}uthorization Qz697Wk5m"),
        Probe(id: 698, path: .text, input: "login a\u{367}thorization Qz698Wk5m"),
        Probe(id: 699, path: .text, input: "login au\u{36D}horization Qz699Wk5m"),
        Probe(id: 700, path: .text, input: "login aut\u{36A}orization Qz700Wk5m"),
        Probe(id: 701, path: .text, input: "login auth\u{366}rization Qz701Wk5m"),
        Probe(id: 702, path: .text, input: "login autho\u{36C}ization Qz702Wk5m"),
        Probe(id: 703, path: .text, input: "login author\u{365}zation Qz703Wk5m"),
        Probe(id: 704, path: .text, input: "login authoriz\u{363}tion Qz704Wk5m"),
        Probe(id: 705, path: .text, input: "login authoriza\u{36D}ion Qz705Wk5m"),
        Probe(id: 706, path: .text, input: "login authorizat\u{365}on Qz706Wk5m"),
        Probe(id: 707, path: .text, input: "login authorizati\u{366}n Qz707Wk5m"),
        Probe(id: 708, path: .body("application/json"), input: "{\"note\":\"t\u{366}ken Qz708Wk5m\"}"),
        Probe(id: 709, path: .body("application/x-www-form-urlencoded"), input: "note=t\u{366}ken+Qz709Wk5m"),
        Probe(id: 710, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nt\u{366}ken Qz710Wk5m\r\n--B0und--"),
        Probe(id: 711, path: .body("text/plain"), input: "t\u{366}ken Qz711Wk5m"),
        Probe(id: 712, path: .text, input: "status=200 t\u{366}ken Qz712Wk5m"),
        Probe(id: 713, path: .url, input: "https://x.example/t%CD%A6ken/Qz713Wk5m"),
        Probe(id: 714, path: .body("application/json"), input: "{\"name\":\"t\u{366}ken\",\"value\":\"Qz714Wk5m\"}"),
        Probe(id: 715, path: .body("application/json"), input: "[\"t\u{366}ken\",\"Qz715Wk5m\"]"),
        Probe(id: 716, path: .body("application/json"), input: "{\"note\":\"p\u{365}n Qz716Wk5m\"}"),
        Probe(id: 717, path: .body("application/x-www-form-urlencoded"), input: "note=p\u{365}n+Qz717Wk5m"),
        Probe(id: 718, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\np\u{365}n Qz718Wk5m\r\n--B0und--"),
        Probe(id: 719, path: .body("text/plain"), input: "p\u{365}n Qz719Wk5m"),
        Probe(id: 720, path: .text, input: "status=200 p\u{365}n Qz720Wk5m"),
        Probe(id: 721, path: .url, input: "https://x.example/p%CD%A5n/Qz721Wk5m"),
        Probe(id: 722, path: .body("application/json"), input: "{\"name\":\"p\u{365}n\",\"value\":\"Qz722Wk5m\"}"),
        Probe(id: 723, path: .body("application/json"), input: "[\"p\u{365}n\",\"Qz723Wk5m\"]"),
        Probe(id: 724, path: .body("application/json"), input: "{\"note\":\"passw\u{366}rd Qz724Wk5m\"}"),
        Probe(id: 725, path: .body("application/x-www-form-urlencoded"), input: "note=passw\u{366}rd+Qz725Wk5m"),
        Probe(id: 726, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\npassw\u{366}rd Qz726Wk5m\r\n--B0und--"),
        Probe(id: 727, path: .body("text/plain"), input: "passw\u{366}rd Qz727Wk5m"),
        Probe(id: 728, path: .text, input: "status=200 passw\u{366}rd Qz728Wk5m"),
        Probe(id: 729, path: .url, input: "https://x.example/passw%CD%A6rd/Qz729Wk5m"),
        Probe(id: 730, path: .body("application/json"), input: "{\"name\":\"passw\u{366}rd\",\"value\":\"Qz730Wk5m\"}"),
        Probe(id: 731, path: .body("application/json"), input: "[\"passw\u{366}rd\",\"Qz731Wk5m\"]"),
        Probe(id: 732, path: .body("application/json"), input: "{\"note\":\"s\u{364}cret Qz732Wk5m\"}"),
        Probe(id: 733, path: .body("application/x-www-form-urlencoded"), input: "note=s\u{364}cret+Qz733Wk5m"),
        Probe(id: 734, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\ns\u{364}cret Qz734Wk5m\r\n--B0und--"),
        Probe(id: 735, path: .body("text/plain"), input: "s\u{364}cret Qz735Wk5m"),
        Probe(id: 736, path: .text, input: "status=200 s\u{364}cret Qz736Wk5m"),
        Probe(id: 737, path: .url, input: "https://x.example/s%CD%A4cret/Qz737Wk5m"),
    ]

    @Test("each probe hides its value, with or without a separator", arguments: probes)
    func probe(_ probe: Probe) {
        let output = probe.redacted(by: SensitiveDataRedactor())
        #expect(!output.contains(probe.value), "\(output)")
    }

    /// The names of the free-text probes, written with a separator.
    @Test("a name with a combining mark in place of a letter is hidden when a separator follows it")
    func separatorsHideTheValue() {
        let redactor = SensitiveDataRedactor()
        var shown: [String] = []
        for probe in Self.probes {
            guard case .text = probe.path, probe.input.hasPrefix("login ") else { continue }
            let name = probe.input.dropFirst("login ".count).split(separator: " ")[0]
            for separator in ["=", ": ", " = ", ":"] {
                let text = "login \(name)\(separator)\(probe.value)"
                if redactor.redact(text).contains(probe.value) { shown.append(text) }
            }
            let pair = #"{"name":"\#(name)","value":"\#(probe.value)"}"#
            if redactor.redact(body: Data(pair.utf8), contentType: "application/json").contains(probe.value) { shown.append(pair) }
        }
        #expect(shown.isEmpty, "\(shown.prefix(10))")
    }

    @Test("a letter, a mark or a number in place of a letter of the name is found")
    func lettersMarksAndNumbers() {
        let redactor = SensitiveDataRedactor()
        // A letter without an ASCII form (L*) in place of one letter.
        #expect(redactor.redact("login tøken Qx1hunter") == "login tøken [redacted]")
        #expect(redactor.redact("login pɑssword Qx1hunter") == "login pɑssword [redacted]")
        // A mark (Mn) added to a letter.
        #expect(redactor.redact("login to\u{0301}ken Qx1hunter") == "login to\u{0301}ken [redacted]")
        // A mark (Mn) in place of a letter, also at the start and at the end of the name.
        #expect(redactor.redact("login t\u{0366}ken Qx1hunter") == "login t\u{0366}ken [redacted]")
        #expect(redactor.redact("login \u{0366}tp Qx1hunter") == "login \u{0366}tp [redacted]")
        #expect(redactor.redact("login passwor\u{0369} Qx1hunter") == "login passwor\u{0369} [redacted]")
        // A number without an ASCII form (N*) in place of a letter, and a letter put in.
        #expect(redactor.redact("login passw\u{3007}rd Qx1hunter") == "login passw\u{3007}rd [redacted]")
        #expect(redactor.redact("login pi\u{A78F}n Qx1hunter") == "login pi\u{A78F}n [redacted]")
        // Two letters replaced is deliberate disguise, the documented limit.
        #expect(redactor.redact("login p\u{0251}sswo\u{0280}d Qx1hunter") == "login p\u{0251}sswo\u{0280}d Qx1hunter")
    }

    /// Letters, marks and numbers outside ASCII without an ASCII form, of every kind the rule
    /// names: letters (Ll, Lo, Lm), marks (Mn, Mc, Me) and numbers (Nl, No).
    static let wildcards: [Unicode.Scalar] = [
        "\u{0251}", "\u{0131}", "\u{00F8}", "\u{A78F}", "\u{0280}", "\u{5F20}", "\u{0366}", "\u{0363}", "\u{036F}", "\u{0308}",
        "\u{20DD}", "\u{0903}", "\u{3007}", "\u{2185}", "\u{3021}", "\u{1D2E}",
    ]

    @Test("every secret name with one wildcard put in or put in place of any letter hides what follows, on every free-text path")
    func everyNameWithOneWildcard() {
        var random = SeededRandom(seed: 25)
        var shown: [String] = []
        for name in ["password", "token", "secret", "pin", "otp", "cvv", "apikey", "cookie", "passcode", "signature", "authorization"] {
            let letters = Array(name.unicodeScalars)
            for position in 0..<letters.count {
                let wildcard = Self.wildcards.randomElement(using: &random)!
                var replaced = letters
                replaced[position] = wildcard
                var inserted = letters
                inserted.insert(Self.wildcards.randomElement(using: &random)!, at: position + 1)
                for spelled in [replaced, inserted] {
                    let word = String(String.UnicodeScalarView(spelled))
                    let line = "login \(word) Qx9hunter"
                    for (path, output) in RedactionCutRuleTests.everyPath(line) where output.contains("Qx9hunter") {
                        shown.append("\(path): \(line.debugDescription) -> \(output.debugDescription)")
                    }
                }
            }
        }
        #expect(shown.isEmpty, "\(shown.count): \(shown.prefix(10))")
    }

    @Test("words with marks and letters outside ASCII that name no secret are kept")
    func usefulness() {
        let redactor = SensitiveDataRedactor()
        for text in ["cafe\u{0301} au lait", "Kullanıcı giriş yaptı", "naïve résumé", "bjørn logged in", "tokyo\u{3007} ok", "pinto beans"] {
            #expect(redactor.redact(text) == text)
        }
    }
}
