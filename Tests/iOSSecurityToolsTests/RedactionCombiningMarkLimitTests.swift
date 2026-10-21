import Foundation
import Testing
import iOSSecurityTools

/// The twenty-second review put a combining Latin small letter (U+0363 to U+036F, a mark: `ͦ` is
/// a small `o` written above the letter before it) in place of one letter of a secret name:
/// `login tͦken X`, `pͥn X`, `passwͦrd X`. Without a separator the name was not found in free
/// text, in a JSON string, a multipart text part, a text/plain body, after `status=200` and in a
/// URL path segment, while with a separator, as a name and value pair and in a two-element array
/// it was hidden. A mark is left out of the ASCII skeleton like any mark (`pässword` is
/// `password`), so the skeleton is the name with a letter missing where no letter was left out.
///
/// This is a documented limit (threat model class D): one letter (L*) put in place of a letter of
/// a name is found; a combining mark (Mn) put in place of a letter hides the name on purpose and is
/// not guaranteed to be found. These tests keep the review's probes as they read today, so a
/// change in either direction is seen and the documentation follows it.
@Suite("SensitiveDataRedactor combining marks in place of a letter")
struct RedactionCombiningMarkLimitTests {
    enum Path: Sendable {
        case text
        case url
        case body(String)
    }

    struct Probe: Sendable, CustomTestStringConvertible {
        let id: Int
        let path: Path
        let input: String
        /// Whether the value shows: the documented limit.
        let shows: Bool

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
        Probe(id: 332, path: .text, input: "login passw\u{366}rd Qz332Wk5m", shows: true),
        Probe(id: 333, path: .text, input: "login t\u{366}ken Qz333Wk5m", shows: true),
        Probe(id: 334, path: .text, input: "login p\u{365}n Qz334Wk5m", shows: true),
        Probe(id: 335, path: .text, input: "login s\u{364}cret Qz335Wk5m", shows: true),
        Probe(id: 336, path: .text, input: "login \u{366}tp Qz336Wk5m", shows: true),
        Probe(id: 652, path: .text, input: "login p\u{363}ssword Qz652Wk5m", shows: true),
        Probe(id: 653, path: .text, input: "login passw\u{366}rd Qz653Wk5m", shows: true),
        Probe(id: 654, path: .text, input: "login passwo\u{36C}d Qz654Wk5m", shows: true),
        Probe(id: 655, path: .text, input: "login passwor\u{369} Qz655Wk5m", shows: true),
        Probe(id: 656, path: .text, input: "login \u{36D}oken Qz656Wk5m", shows: true),
        Probe(id: 657, path: .text, input: "login t\u{366}ken Qz657Wk5m", shows: true),
        Probe(id: 658, path: .text, input: "login tok\u{364}n Qz658Wk5m", shows: true),
        Probe(id: 659, path: .text, input: "login s\u{364}cret Qz659Wk5m", shows: true),
        Probe(id: 660, path: .text, input: "login se\u{368}ret Qz660Wk5m", shows: true),
        Probe(id: 661, path: .text, input: "login sec\u{36C}et Qz661Wk5m", shows: true),
        Probe(id: 662, path: .text, input: "login secr\u{364}t Qz662Wk5m", shows: true),
        Probe(id: 663, path: .text, input: "login secre\u{36D} Qz663Wk5m", shows: true),
        Probe(id: 664, path: .text, input: "login p\u{365}n Qz664Wk5m", shows: true),
        Probe(id: 665, path: .text, input: "login \u{366}tp Qz665Wk5m", shows: true),
        Probe(id: 666, path: .text, input: "login o\u{36D}p Qz666Wk5m", shows: true),
        Probe(id: 667, path: .text, input: "login \u{368}vv Qz667Wk5m", shows: true),
        Probe(id: 668, path: .text, input: "login c\u{36E}v Qz668Wk5m", shows: true),
        Probe(id: 669, path: .text, input: "login cv\u{36E} Qz669Wk5m", shows: true),
        Probe(id: 670, path: .text, input: "login \u{363}pikey Qz670Wk5m", shows: false),
        Probe(id: 671, path: .text, input: "login ap\u{365}key Qz671Wk5m", shows: false),
        Probe(id: 672, path: .text, input: "login apik\u{364}y Qz672Wk5m", shows: true),
        Probe(id: 673, path: .text, input: "login p\u{363}sscode Qz673Wk5m", shows: true),
        Probe(id: 674, path: .text, input: "login pass\u{368}ode Qz674Wk5m", shows: true),
        Probe(id: 675, path: .text, input: "login passc\u{366}de Qz675Wk5m", shows: true),
        Probe(id: 676, path: .text, input: "login passco\u{369}e Qz676Wk5m", shows: true),
        Probe(id: 677, path: .text, input: "login passcod\u{364} Qz677Wk5m", shows: true),
        Probe(id: 678, path: .text, input: "login \u{368}ookie Qz678Wk5m", shows: true),
        Probe(id: 679, path: .text, input: "login c\u{366}okie Qz679Wk5m", shows: true),
        Probe(id: 680, path: .text, input: "login co\u{366}kie Qz680Wk5m", shows: true),
        Probe(id: 681, path: .text, input: "login cook\u{365}e Qz681Wk5m", shows: true),
        Probe(id: 682, path: .text, input: "login cooki\u{364} Qz682Wk5m", shows: true),
        Probe(id: 683, path: .text, input: "login \u{368}redential Qz683Wk5m", shows: true),
        Probe(id: 684, path: .text, input: "login c\u{36C}edential Qz684Wk5m", shows: true),
        Probe(id: 685, path: .text, input: "login cr\u{364}dential Qz685Wk5m", shows: true),
        Probe(id: 686, path: .text, input: "login cre\u{369}ential Qz686Wk5m", shows: true),
        Probe(id: 687, path: .text, input: "login cred\u{364}ntial Qz687Wk5m", shows: true),
        Probe(id: 688, path: .text, input: "login creden\u{36D}ial Qz688Wk5m", shows: true),
        Probe(id: 689, path: .text, input: "login credent\u{365}al Qz689Wk5m", shows: true),
        Probe(id: 690, path: .text, input: "login credenti\u{363}l Qz690Wk5m", shows: true),
        Probe(id: 691, path: .text, input: "login s\u{365}gnature Qz691Wk5m", shows: true),
        Probe(id: 692, path: .text, input: "login sign\u{363}ture Qz692Wk5m", shows: true),
        Probe(id: 693, path: .text, input: "login signa\u{36D}ure Qz693Wk5m", shows: true),
        Probe(id: 694, path: .text, input: "login signat\u{367}re Qz694Wk5m", shows: true),
        Probe(id: 695, path: .text, input: "login signatu\u{36C}e Qz695Wk5m", shows: true),
        Probe(id: 696, path: .text, input: "login signatur\u{364} Qz696Wk5m", shows: true),
        Probe(id: 697, path: .text, input: "login \u{363}uthorization Qz697Wk5m", shows: true),
        Probe(id: 698, path: .text, input: "login a\u{367}thorization Qz698Wk5m", shows: true),
        Probe(id: 699, path: .text, input: "login au\u{36D}horization Qz699Wk5m", shows: true),
        Probe(id: 700, path: .text, input: "login aut\u{36A}orization Qz700Wk5m", shows: true),
        Probe(id: 701, path: .text, input: "login auth\u{366}rization Qz701Wk5m", shows: true),
        Probe(id: 702, path: .text, input: "login autho\u{36C}ization Qz702Wk5m", shows: true),
        Probe(id: 703, path: .text, input: "login author\u{365}zation Qz703Wk5m", shows: true),
        Probe(id: 704, path: .text, input: "login authoriz\u{363}tion Qz704Wk5m", shows: true),
        Probe(id: 705, path: .text, input: "login authoriza\u{36D}ion Qz705Wk5m", shows: true),
        Probe(id: 706, path: .text, input: "login authorizat\u{365}on Qz706Wk5m", shows: true),
        Probe(id: 707, path: .text, input: "login authorizati\u{366}n Qz707Wk5m", shows: true),
        Probe(id: 708, path: .body("application/json"), input: "{\"note\":\"t\u{366}ken Qz708Wk5m\"}", shows: true),
        Probe(id: 709, path: .body("application/x-www-form-urlencoded"), input: "note=t\u{366}ken+Qz709Wk5m", shows: false),
        Probe(id: 710, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nt\u{366}ken Qz710Wk5m\r\n--B0und--", shows: true),
        Probe(id: 711, path: .body("text/plain"), input: "t\u{366}ken Qz711Wk5m", shows: true),
        Probe(id: 712, path: .text, input: "status=200 t\u{366}ken Qz712Wk5m", shows: true),
        Probe(id: 713, path: .url, input: "https://x.example/t%CD%A6ken/Qz713Wk5m", shows: true),
        Probe(id: 714, path: .body("application/json"), input: "{\"name\":\"t\u{366}ken\",\"value\":\"Qz714Wk5m\"}", shows: false),
        Probe(id: 715, path: .body("application/json"), input: "[\"t\u{366}ken\",\"Qz715Wk5m\"]", shows: false),
        Probe(id: 716, path: .body("application/json"), input: "{\"note\":\"p\u{365}n Qz716Wk5m\"}", shows: true),
        Probe(id: 717, path: .body("application/x-www-form-urlencoded"), input: "note=p\u{365}n+Qz717Wk5m", shows: false),
        Probe(id: 718, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\np\u{365}n Qz718Wk5m\r\n--B0und--", shows: true),
        Probe(id: 719, path: .body("text/plain"), input: "p\u{365}n Qz719Wk5m", shows: true),
        Probe(id: 720, path: .text, input: "status=200 p\u{365}n Qz720Wk5m", shows: true),
        Probe(id: 721, path: .url, input: "https://x.example/p%CD%A5n/Qz721Wk5m", shows: true),
        Probe(id: 722, path: .body("application/json"), input: "{\"name\":\"p\u{365}n\",\"value\":\"Qz722Wk5m\"}", shows: false),
        Probe(id: 723, path: .body("application/json"), input: "[\"p\u{365}n\",\"Qz723Wk5m\"]", shows: false),
        Probe(id: 724, path: .body("application/json"), input: "{\"note\":\"passw\u{366}rd Qz724Wk5m\"}", shows: true),
        Probe(id: 725, path: .body("application/x-www-form-urlencoded"), input: "note=passw\u{366}rd+Qz725Wk5m", shows: false),
        Probe(id: 726, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\npassw\u{366}rd Qz726Wk5m\r\n--B0und--", shows: true),
        Probe(id: 727, path: .body("text/plain"), input: "passw\u{366}rd Qz727Wk5m", shows: true),
        Probe(id: 728, path: .text, input: "status=200 passw\u{366}rd Qz728Wk5m", shows: true),
        Probe(id: 729, path: .url, input: "https://x.example/passw%CD%A6rd/Qz729Wk5m", shows: true),
        Probe(id: 730, path: .body("application/json"), input: "{\"name\":\"passw\u{366}rd\",\"value\":\"Qz730Wk5m\"}", shows: false),
        Probe(id: 731, path: .body("application/json"), input: "[\"passw\u{366}rd\",\"Qz731Wk5m\"]", shows: false),
        Probe(id: 732, path: .body("application/json"), input: "{\"note\":\"s\u{364}cret Qz732Wk5m\"}", shows: true),
        Probe(id: 733, path: .body("application/x-www-form-urlencoded"), input: "note=s\u{364}cret+Qz733Wk5m", shows: false),
        Probe(id: 734, path: .body("multipart/form-data; boundary=B0und"), input: "--B0und\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\ns\u{364}cret Qz734Wk5m\r\n--B0und--", shows: true),
        Probe(id: 735, path: .body("text/plain"), input: "s\u{364}cret Qz735Wk5m", shows: true),
        Probe(id: 736, path: .text, input: "status=200 s\u{364}cret Qz736Wk5m", shows: true),
        Probe(id: 737, path: .url, input: "https://x.example/s%CD%A4cret/Qz737Wk5m", shows: true),
    ]

    @Test("each probe reads as documented: shown without a separator, hidden with one or as a pair", arguments: probes)
    func probe(_ probe: Probe) {
        let output = probe.redacted(by: SensitiveDataRedactor())
        #expect(output.contains(probe.value) == probe.shows, "\(output)")
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

    @Test("a letter in place of a letter of the name is found, a mark is the documented limit")
    func lettersAndMarks() {
        let redactor = SensitiveDataRedactor()
        // A letter without an ASCII form (L*) in place of one letter: found.
        #expect(redactor.redact("login tøken Qx1hunter") == "login tøken [redacted]")
        #expect(redactor.redact("login pɑssword Qx1hunter") == "login pɑssword [redacted]")
        // A mark (Mn) added to a letter is left out: found.
        #expect(redactor.redact("login to\u{0301}ken Qx1hunter") == "login to\u{0301}ken [redacted]")
        // A mark (Mn) in place of a letter: the documented limit.
        #expect(redactor.redact("login t\u{0366}ken Qx1hunter") == "login t\u{0366}ken Qx1hunter")
    }
}
