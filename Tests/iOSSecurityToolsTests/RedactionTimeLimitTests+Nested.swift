import Foundation
import iOSSecurityTools

/// A megabyte of text quoted in JSON one to four times, which the eleventh review timed at 1.1 to
/// 2.6 seconds a megabyte in a release build: every level read what the level around it held
/// once more, and a letter without an ASCII form (`ı`, `ɑ`) made each reading slower. The reading
/// budget bounds the levels and one pass per secret word bounds each reading.
extension RedactionTimeLimitTests {
    private static let redactor = largeBodies

    private static func jsonBody(_ text: String) -> String { redactor.redact(body: Data(text.utf8), contentType: "application/json") }
    private static func plainBody(_ text: String) -> String { redactor.redact(body: Data(text.utf8), contentType: "text/plain") }
    private static func formBody(_ text: String) -> String {
        redactor.redact(body: Data(text.utf8), contentType: "application/x-www-form-urlencoded")
    }

    private static let turkish = "Kullanıcı sisteme başarıyla giriş yaptı ve ayarlarını değiştirdi. "

    /// `payload` in `["…"]`, and that as a string in `["…"]` again `levels` times.
    static func quoted(_ payload: String, levels: Int, open: String = "[\"", close: String = "\"]") -> String {
        var text = open + payload + close
        for _ in 0..<levels { text = open + RedactionStackTests.escaped(text) + close }
        return text
    }

    /// `unit` repeated inside `levels` quotings to about a megabyte in all.
    private static func filled(_ unit: String, levels: Int, open: String = "[\"", close: String = "\"]") -> String {
        let overhead = quoted("", levels: levels, open: open, close: close).utf8.count
        return quoted(String(repeating: unit, count: max(1, (size - overhead) / unit.utf8.count)), levels: levels, open: open, close: close)
    }

    /// An array of strings that each hold `element` quoted, to about a megabyte.
    private static func manyQuoted(_ element: String) -> String {
        let unit = "\"" + RedactionStackTests.escaped(element) + "\""
        return "[" + Array(repeating: unit, count: size / (unit.utf8.count + 1)).joined(separator: ",") + "]"
    }

    static let nestedPayloads: [TimedInput] = (0...4).flatMap { levels in
        [
            TimedInput(testDescription: "Turkish sentences quoted in JSON \(levels) times", make: { filled(turkish, levels: levels) }, redact: jsonBody),
            TimedInput(testDescription: "ı quoted in JSON \(levels) times", make: { filled("ı", levels: levels) }, redact: jsonBody),
        ]
    } + (0...3).map { levels in
        TimedInput(testDescription: "a log line of Turkish sentences quoted in JSON \(levels) times", make: {
            "log " + filled(turkish, levels: levels)
        }, redact: redactor.redact)
    } + [
        TimedInput(testDescription: "ɑ quoted in JSON three times", make: { filled("ɑ", levels: 3) }, redact: jsonBody),
        TimedInput(testDescription: "words of ı quoted in JSON twice", make: { filled("ı ", levels: 2) }, redact: jsonBody),
        TimedInput(testDescription: "words of ıa and sı quoted in JSON three times", make: { filled("ıa sı ", levels: 3) }, redact: jsonBody),
        TimedInput(testDescription: "ı in objects quoted in JSON three times", make: {
            filled("ı", levels: 3, open: "{\"m\":\"", close: "\"}")
        }, redact: jsonBody),
        TimedInput(testDescription: "words of ı under label quoted in JSON three times", make: {
            filled("ı ", levels: 3, open: "{\"label\":\"", close: "\"}")
        }, redact: jsonBody),
        TimedInput(testDescription: "a log line of ı quoted in JSON three times", make: { "log " + filled("ı", levels: 3) }, redact: redactor.redact),
        TimedInput(testDescription: "a text/plain body of ı quoted in JSON three times", make: { filled("ı", levels: 3) }, redact: plainBody),
        TimedInput(testDescription: "a log line with x= and ı quoted in JSON twice", make: { "x=" + filled("ı", levels: 2) }, redact: redactor.redact),
        TimedInput(testDescription: "a form value of JSON with ı", make: {
            let json = "[\"" + String(repeating: "ı", count: (size - 20) / 6) + "\"]"
            return "q=" + json.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        }, redact: formBody),
        TimedInput(testDescription: "an array of strings of 40 ı quoted in JSON three times", make: {
            manyQuoted(quoted(String(repeating: "ı", count: 40), levels: 2))
        }, redact: jsonBody),
        TimedInput(testDescription: "an array of strings of a Turkish sentence quoted in JSON twice", make: {
            manyQuoted(quoted(turkish, levels: 1))
        }, redact: jsonBody),
    ]
}
