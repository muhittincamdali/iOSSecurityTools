import Foundation
import Testing
@testable import iOSSecurityTools

/// The 51 inputs that got secrets past 2.0.0 and the first fixes for 2.0.1, kept so that none of
/// them can come back. Each one hides `hunter2` behind a different trick.
@Suite("SensitiveDataRedactor bypass probes")
struct RedactionProbeTests {
    let redactor = SensitiveDataRedactor()

    /// Inputs whose output is the input with `hunter2` replaced in place.
    static let replacedInPlace = [
        // Cyrillic and Greek look-alike letters in the name.
        "p\u{0430}ssword=hunter2", "\u{0440}assword=hunter2", "passw\u{043E}rd=hunter2", "{\"p\u{0430}ssword\":\"hunter2\"}",
        "t\u{043E}ken=hunter2", "s\u{0435}cret=hunter2", "\u{0430}pi_key=hunter2",
        // Separators inside the name.
        "pass.word=hunter2", "pass word=hunter2", "PASS-WORD=hunter2", "pass_word=hunter2", "api.key=hunter2",
        "client.secret=hunter2", "access.token: hunter2",
        // Escapes in the name.
        "{\"pass\\u0077ord\":\"hunter2\"}", "pass%77ord=hunter2", "p&#97;ssword=hunter2",
        // Combining marks and format characters.
        "pa\u{0301}ssword=hunter2", "pass\u{200B}word=hunter2", "pass\u{2060}word=hunter2", "pass\u{00AD}word=hunter2",
        "pa\u{FE0F}ssword=hunter2", "password\u{0301}=hunter2",
        // Styled letters that Unicode compatibility normalization maps to ASCII.
        "\u{1D429}\u{1D41A}\u{1D42C}\u{1D42C}\u{1D430}\u{1D428}\u{1D42B}\u{1D41D}=hunter2", "\u{24DF}assword=hunter2",
        // Structure.
        "{\"user\":{\"password\":\"hunter2\"}}", "[{\"password\":\"hunter2\"},{\"password\":\"hunter2\"}]",
        "password=hunter2&password=hunter2", "{\"password\" : \"hunter2\"}", "password: \"hunter2", "{\"password\":\n\"hunter2\"}",
        // Line breaks and look-alike separators.
        "password\u{2028}=hunter2", "password\u{0085}=hunter2", "password\u{000B}=hunter2", "password\u{000C}=hunter2",
        "password\u{FF1D}hunter2", "password\u{FE13}hunter2", "password\u{FF1A}hunter2",
        "password:hunter2", "PASSWORD=hunter2", "\u{FEFF}password=hunter2", "password='hunter2",
    ]

    /// Inputs whose whole value, with its quotes or brackets, is replaced.
    static let replacedWhole: [(String, String)] = [
        ("password=\u{0301}hunter2", "password=[redacted]"),
        ("{\"password\":[\"hunter2\"]}", "{\"password\":\"[redacted]\"}"),
        ("{\"password\":{\"v\":\"hunter2\"}}", "{\"password\":\"[redacted]\"}"),
        ("{\"password\":\"hun\\\"ter2\"}", "{\"password\":\"[redacted]\"}"),
        ("Authorization: Basic aHVudGVyMg==", "Authorization: [redacted]"),
        ("password=`hunter2`", "password=[redacted]"),
        ("password=(hunter2)", "password=[redacted]"),
        ("password={hunter2}", "password=[redacted]"),
        ("password=[hunter2]", "password=[redacted]"),
    ]

    @Test("there are 51 probes")
    func count() {
        #expect(Self.replacedInPlace.count + Self.replacedWhole.count == 51)
    }

    @Test("hides the value in place", arguments: replacedInPlace)
    func inPlace(input: String) {
        let output = redactor.redact(input)
        #expect(output == input.replacingOccurrences(of: "hunter2", with: "[redacted]"))
        #expect(!output.contains("ter2"))
    }

    @Test("hides the whole value", arguments: replacedWhole)
    func whole(input: String, expected: String) {
        let output = redactor.redact(input)
        #expect(output == expected)
        #expect(!output.contains("ter2") && !output.contains("aHVudGVyMg"))
    }
}
