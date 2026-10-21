import Foundation
import Testing
@testable import iOSSecurityTools

/// The scanning copy of free text is made only as far as free text is read: to the end of the
/// line of the first character outside the safe alphabet and through the next line that is not
/// blank (see ``NormalizedText/Extent/scanned``). The scan and the value detectors read past that
/// character only to finish what starts before it, so the findings are the same as on a copy of
/// the whole text: a finding that runs through it (`bob＠example.com`, `4111‐1111‐…`), a quote
/// that closes after it on its line, the blank lines before a separator.
@Suite("SensitiveDataRedactor scanning copy as far as free text is read")
struct RedactionCopyExtentTests {
    /// The findings of free text from a copy of `extent`, written out to compare.
    static func findings(_ text: String, extent: NormalizedText.Extent, redactor: SensitiveDataRedactor) -> [String] {
        let scalars = Array(text.unicodeScalars)
        let compatibility = CompatibilityText()
        let copy = NormalizedText(scalars, compatibility: compatibility, extent: extent)
        let spans = redactor.textSpans(in: scalars, text: copy, compatibility: compatibility, nesting: .text(length: scalars.count))
        return spans.map { "\($0.start)..<\($0.end) \($0.kind.rawValue) \($0.replacement)" }
    }

    static func differs(_ text: String, redactor: SensitiveDataRedactor = SensitiveDataRedactor()) -> Bool {
        findings(text, extent: .scanned, redactor: redactor) != findings(text, extent: .whole, redactor: redactor)
    }

    /// Characters outside the safe alphabet, among them ones read as `@`, `=`, `.`, `-`, a letter,
    /// a space and a line break, which a finding or a separator can run through.
    static let unsafe = [
        "\u{2192}", "\u{FF1D}", "\u{FF20}", "\u{FE6B}", "\u{FF0E}", "\u{2010}", "\u{24B6}", "\u{00A0}", "\u{3000}", "\u{200B}", "\u{0085}",
        "\u{2028}", "\u{2029}", "\u{1F101}", "\u{1F600}", "\u{0007}", "\u{E000}", "\u{FF1A}", "\u{FF02}",
    ]

    /// Lines where the character `{u}` stands inside or right before a finding, a quote, a key, a
    /// separator, JSON, an escape or a URL, and where blank lines come after it.
    static let templates = [
        "mail bob{u}example.com done", "mail bob@exam{u}ple.com done", "mail bob.{u}smith@example.com", "card 4111{u}1111 1111 1111 ok",
        "card 4111 1111{u} 1111 1111", "card 4111-1111-1111-111{u}1", "token eyJhbGciOiJIUzI1NiJ9{u}.eyJzdWIiOiIxIn0.abc",
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0{u}abc", "auth Bearer abc{u}defghijklmnop", "auth bearer{u} abcdefghijklmnop",
        "key 0123456789abcdef{u}0123456789abcdef0123", "iban DE89 3704{u} 0044 0532 0130 00", "status=200 \"note{u}\": 1",
        "\"status\"{u}\n\n: 1", "\"status\" \n{u}\n= 1", "msg \"hello {u} world\" done", "{\"status\":\"{u}\"} more", "id=bob{u} x",
        "pa{u}ss%77ord x", "x{u}\n\n\n  status=200\nnext line password=hunter2", "status=200{u}%41%42", "{u}\n   \n\"user\": 1",
        "user:pw{u}@example.com", "url https://api.example.com/items{u} ok", "a{u}\r\n\r\n{\"user\":\"bob\"}", "status=200 [1, 2{u}] x",
        "(status=200{u}", "status{u}=200", "status ={u}200", "'status'{u}: 200", "`a{u}` b", "x &amp{u}; y", "pa\\{u}x", "a{u}\n\n", "{u}",
        "status=200\n{u}", "status=200 {u}\n\n\n\n", "{u}\n\n x=1\n y=2", "note: {u} 1:2@a.bc", "ok\u{FB01} {u} a@b.cd",
    ]

    @Test("every template with every character outside the alphabet finds the same on both copies")
    func templatesFindTheSame() {
        var differing: [String] = []
        for template in Self.templates {
            for scalar in Self.unsafe {
                let text = template.replacingOccurrences(of: "{u}", with: scalar)
                if Self.differs(text) { differing.append(text.debugDescription) }
            }
        }
        #expect(differing.isEmpty, "\(differing.count) texts: \(differing.prefix(10))")
    }

    @Test("every text probe of the reviews finds the same on both copies")
    func probesFindTheSame() {
        var differing: [String] = []
        for probe in ReviewProbes.all where probe.kind == "text" && !probe.isLarge {
            let redactor = SensitiveDataRedactor(allowedTextKeys: probe.keys ?? [], allowedQueryParameters: probe.queryKeys ?? [])
            if Self.differs(probe.text, redactor: redactor) { differing.append(probe.name) }
        }
        #expect(differing.isEmpty, "\(differing.count) probes: \(differing.prefix(10))")
    }

    /// The pieces random texts are made of: words, findings, keys, separators, quotes, brackets,
    /// escapes, white space and line breaks, and characters outside the alphabet.
    static let pieces = [
        "a", "bob", "status", "user", "password", "=", ":", " ", " ", "\t", "\n", "\n", "\r\n", "\"", "'", "`", "{", "}", "[", "]", "(", ")",
        "@", ".", "-", "_", "%41", "\\", "&amp;", "4111", "1111 ", "example.com", "eyJhbGciOiJIUzI1NiJ9", ".", "Bearer ", "1:2@", "a@b.cd",
        "https://x.example/a", "<b>", "0123456789abcdef", ",", ";", "ı", "\u{FB01}",
    ] + unsafe

    @Test("random texts of words, findings, separators and characters outside the alphabet find the same on both copies")
    func randomTextsFindTheSame() {
        var random = SeededRandom(seed: 22)
        var differing: [String] = []
        for _ in 0..<20_000 {
            let count = Int.random(in: 0...24, using: &random)
            let text = (0..<count).map { _ in Self.pieces.randomElement(using: &random)! }.joined()
            if Self.differs(text) { differing.append(text.debugDescription) }
        }
        #expect(differing.isEmpty, "\(differing.count) texts: \(differing.prefix(10))")
    }

    @Test("the copy ends after the line of the first character outside the alphabet and the next line that is not blank")
    func theCopyEnds() {
        let compatibility = CompatibilityText()
        let text = "ok \u{2192} rest\n\n  \nnext line\nnot read\nnor this"
        let copy = NormalizedText(Array(text.unicodeScalars), compatibility: compatibility, extent: .scanned)
        #expect(copy.string(0..<copy.count).hasSuffix("next line\n"))
        #expect(copy.firstUnsafeOffset == 3)
        let whole = NormalizedText(Array(text.unicodeScalars), compatibility: compatibility)
        #expect(whole.string(0..<whole.count).hasSuffix("nor this"))
        // A text without a character outside the alphabet is copied whole.
        let plain = NormalizedText(Array("a\nb\nc".unicodeScalars), compatibility: compatibility, extent: .scanned)
        #expect(plain.count == 5)
    }
}
