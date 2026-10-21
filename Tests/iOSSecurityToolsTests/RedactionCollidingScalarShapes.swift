import Foundation
import iOSSecurityTools

/// Input made of scalars that met in every size of the readings table of the twenty-first fix,
/// timed as the other shapes are. That table doubled whenever two scalars met in a slot, and
/// `丆幛` met in every size from 64 to 4,096 slots, `Âۿ` in every size from 64 to 2,048, so seven
/// of them took each new table to 4,096 slots. The twenty-second review timed, against the
/// release before that fix: a megabyte of log lines `msg ÂۿÂۿÂۿÂ`, each its own `redact` call,
/// at 1.77 s against 0.19 s; a form of 256 KiB of such fields without `=` at 0.94 s/MB against
/// 0.24; `a=x, ÂۿÂۿÂۿÂ` fields at 0.81 against 0.21; a multipart body of 999 such parts at 0.59
/// against 0.12; and a URL of 127 allowed `q` parameters at 0.85 against 0.26. The table now has
/// a size fixed when it is made, in sets of two slots, and one table serves a whole body or URL.
///
/// A shape smaller than a megabyte is repeated to one, each copy redacted on its own.
enum CollidingScalarShapes {
    static let pairs: [(name: String, a: Unicode.Scalar, b: Unicode.Scalar)] = [("Âۿ", "\u{00C2}", "\u{06FF}"), ("丆幛", "\u{4E06}", "\u{5E5B}")]

    /// `count` scalars, `a` and `b` in turn.
    static func alternating(_ a: Unicode.Scalar, _ b: Unicode.Scalar, _ count: Int) -> String {
        String(String.UnicodeScalarView((0..<count).map { $0 % 2 == 0 ? a : b }))
    }

    /// Copies of `unit` joined by `separator`, as many as fit in a megabyte.
    static func megabyte(of unit: String, separator: String) -> String {
        let count = RedactionTimeLimitTests.size / (unit.utf8.count + separator.utf8.count)
        return Array(repeating: unit, count: count).joined(separator: separator)
    }

    /// A form of fields `unit` joined by `&`, about `size` bytes.
    static func fields(_ unit: String, size: Int) -> String {
        Array(repeating: unit, count: size / (unit.utf8.count + 1)).joined(separator: "&")
    }

    static func encoded(_ text: String) -> String {
        text.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    /// Redacts each piece of the text between `separator`s on its own.
    static func eachPiece(separatedBy separator: Character, _ redact: @escaping @Sendable (String) -> String) -> @Sendable (String) -> String {
        { text in text.split(separator: separator).map { redact(String($0)) }.joined(separator: String(separator)) }
    }

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let largeBodies = RedactionTimeLimitTests.largeBodies
        let form: @Sendable (String) -> String = { redactor.redact(body: Data($0.utf8), contentType: "application/x-www-form-urlencoded") }
        let largeForm: @Sendable (String) -> String = { largeBodies.redact(body: Data($0.utf8), contentType: "application/x-www-form-urlencoded") }
        let multipart: @Sendable (String) -> String = { redactor.redact(body: Data($0.utf8), contentType: "multipart/form-data; boundary=XyZ") }
        let allowing = SensitiveDataRedactor(allowedQueryParameters: ["q"])
        let url: @Sendable (String) -> String = { allowing.redact(url: URL(string: $0)!) }
        var shapes: [TimedInput] = []
        for (name, a, b) in pairs {
            let seven = alternating(a, b, 7)
            let quarter = 245_000
            shapes += [
                TimedInput(testDescription: "log lines `msg \(seven)`, each its own call", make: { megabyte(of: "msg " + seven, separator: "\n") },
                           redact: eachPiece(separatedBy: "\n", redactor.redact)),
                TimedInput(testDescription: "log lines of 16 `\(name)`, each its own call", make: { megabyte(of: alternating(a, b, 16), separator: "\n") },
                           redact: eachPiece(separatedBy: "\n", redactor.redact)),
                TimedInput(testDescription: "forms of 245 KB of `\(seven)` fields without `=`", make: {
                    megabyte(of: fields(encoded(seven), size: quarter), separator: "\n")
                }, redact: eachPiece(separatedBy: "\n", form)),
                TimedInput(testDescription: "forms of 245 KB of `a=x, \(seven)`", make: {
                    megabyte(of: fields("a=" + encoded("x, " + seven), size: quarter), separator: "\n")
                }, redact: eachPiece(separatedBy: "\n", form)),
                TimedInput(testDescription: "a form of a megabyte of `\(seven)` fields without `=`", make: {
                    fields(encoded(seven), size: RedactionTimeLimitTests.size)
                }, redact: largeForm),
                TimedInput(testDescription: "multipart bodies of 999 parts `x, \(seven)`", make: {
                    let part = "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx, " + seven + "\r\n"
                    return megabyte(of: String(repeating: part, count: 999) + "--XyZ--\r\n", separator: "\u{1}")
                }, redact: eachPiece(separatedBy: "\u{1}", multipart)),
                TimedInput(testDescription: "URLs of 127 allowed `q=x, \(seven)` parameters", make: {
                    let parameters = Array(repeating: "q=" + encoded("x, " + seven), count: 127).joined(separator: "&")
                    return megabyte(of: "https://x.example/a?" + parameters, separator: "\n")
                }, redact: eachPiece(separatedBy: "\n", url)),
            ]
        }
        return shapes
    }()
}
