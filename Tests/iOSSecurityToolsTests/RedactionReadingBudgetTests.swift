import Foundation
import Testing
@testable import iOSSecurityTools

/// The reading budget: the documents found inside one input read at most four times its length,
/// all together. Text past the budget is hidden whole, so the work stays a fixed multiple of the
/// input however it nests documents.
@Suite("SensitiveDataRedactor reading budget")
struct RedactionReadingBudgetTests {
    let redactor = SensitiveDataRedactor()

    private func body(_ text: String, _ contentType: String = "application/json") -> String {
        redactor.redact(body: Data(text.utf8), contentType: contentType)
    }

    private static func quoted(_ payload: String, levels: Int) -> String {
        RedactionTimeLimitTests.quoted(payload, levels: levels)
    }

    /// Words of `ı`, each shorter than the longest word free text reads.
    private static let payload = String(repeating: String(repeating: "ı", count: 99) + " ", count: 20)

    @Test("the input is read freely and what is found in it takes four times its length at most")
    func budget() {
        #expect(ReadingBudget.inputMultiple == 4)
        let document = Nesting.document(length: 10)
        #expect(document.reads(1_000))
        #expect(document.lengthLeft == .max)
        let inner = document.enteringDocument()!
        #expect(inner.lengthLeft == 40)
        #expect(inner.reads(30))
        #expect(!inner.reads(11))
        #expect(inner.reads(10))
        #expect(inner.lengthLeft == 0)
        #expect(inner.enteringDocument()!.lengthLeft == 0)
        #expect(Nesting.text(length: 5).enteringDocument()!.lengthLeft == 20)
    }

    @Test("the JSON reader stops where the budget ends")
    func readerStops() throws {
        let scalars = Array("x [1,2,3] y".unicodeScalars)
        let nesting = Nesting.text(length: scalars.count)
        #expect(throws: JSONDocument.ReadError.overBudget) { try JSONDocument(scalars, at: 2, nesting: nesting, lengthLimit: 6) }
        let document = try JSONDocument(scalars, at: 2, nesting: nesting, lengthLimit: 7)
        #expect(document.root.range == 2..<9)
        let invalid = Array("{\"a\" x".unicodeScalars)
        #expect(throws: JSONDocument.ReadError.invalid) { try JSONDocument(invalid, at: 0, nesting: nesting, lengthLimit: 100) }
    }

    // Each level holds the whole payload: the documents found in the body read it about four
    // times by the third level, and the text that would read a fourth document is hidden whole.
    @Test("a long text quoted in JSON twice is read, and three times the innermost string is hidden")
    func longTextInBody() {
        let twice = Self.quoted(Self.payload, levels: 2)
        #expect(body(twice) == twice)
        let thrice = Self.quoted(Self.payload, levels: 3)
        // The innermost string is hidden whole, and the text that holds it is cut there.
        #expect(body(thrice) == #"["[\"[redacted]"]"#)
        let secret = Self.quoted("password=hunter2 " + Self.payload, levels: 3)
        #expect(!body(secret).contains("hunter2"))
    }

    @Test("in a log line the JSON is the first document found")
    func longTextInLine() {
        let once = "log " + Self.quoted(Self.payload, levels: 1)
        #expect(redactor.redact(once) == once)
        #expect(redactor.redact("log " + Self.quoted(Self.payload, levels: 2)) == #"log ["[redacted]"#)
    }

    @Test("many small documents side by side all fit")
    func manySmallDocuments() {
        let element = "\"" + RedactionStackTests.escaped(#"{"status":"ok","count":[1,2]}"#) + "\""
        let array = "[" + Array(repeating: element, count: 500).joined(separator: ",") + "]"
        #expect(body(array) == array)
        let lines = Array(repeating: #"event {"status":"ok","count":[1,2]} done"#, count: 500).joined(separator: "\n")
        #expect(redactor.redact(lines) == lines)
    }

    @Test("small documents quoted four levels deep are read in full")
    func smallDeepDocuments() {
        let innermost = #"{"status":"ok"}"#
        let four = (0..<3).reduce(innermost) { inner, _ in #"{"note":""# + RedactionStackTests.escaped(inner) + #""}"# }
        // `note` is allowed in text, so the text in it reads on into the document it holds.
        let allowing = SensitiveDataRedactor(allowedTextKeys: ["note"])
        #expect(allowing.redact(body: Data(four.utf8), contentType: "application/json") == four)
        #expect(body(four) == #"{"note":"{[redacted]"}"#)
    }

    /// A secret in a text nested in documents of every kind, inside or past the budget, never
    /// shows.
    @Test("a secret nested in any mix of documents never shows", arguments: 0..<6)
    func secretNeverShows(seed: Int) {
        var generator = SeededRandom(seed: UInt64(seed + 1))
        for _ in 0..<40 {
            var text = "password=hunter2 " + String(repeating: ["ı", "a", "ş ", "ɑ"].randomElement(using: &generator)!, count: Int.random(in: 0...3_000, using: &generator))
            for _ in 0..<Int.random(in: 0...6, using: &generator) {
                text = Self.wrap(text, Int.random(in: 0..<4, using: &generator))
            }
            let outputs = [redactor.redact(text), body(text, "text/plain"), body(text), body("note=" + Self.formEncoded(text), "application/x-www-form-urlencoded")]
            for output in outputs {
                #expect(!output.contains("hunter2"), "\(text.prefix(80).debugDescription)")
            }
        }
    }

    private static func wrap(_ text: String, _ kind: Int) -> String {
        let escaped = RedactionStackTests.escaped(text)
        switch kind {
        case 0: return "[\"" + escaped + "\"]"
        case 1: return "{\"note\":\"" + escaped + "\"}"
        case 2: return "log [\"" + escaped + "\"] done"
        default: return "{\"a\":[{\"b\":\"" + escaped + "\"}]}"
        }
    }

    private static func formEncoded(_ text: String) -> String {
        text.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
    }
}
