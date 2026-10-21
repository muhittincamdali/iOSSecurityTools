import Foundation
import iOSSecurityTools

/// Free text in which almost every scalar is a different one outside ASCII, timed and measured as
/// the other shapes are. The twenty-first review measured 17.08 to 17.39 MiB for a megabyte of
/// about 200,000 different scalars — every scalar from U+30000 on, each with a space after it, or
/// every scalar from U+0080 on — and 68.15 MiB for 4 MB. The reading of each scalar was cached in
/// a dictionary that kept one for every scalar, each reading with an array of its own, and the
/// scanning copy read the whole text, also past a control character that cut it at its start. The
/// cache now keeps at most 4,096 readings, their bytes held in place, and the copy ends after the
/// line of the first character outside the safe alphabet and the next line that is not blank.
enum DistinctScalarShapes {
    /// The value at the end of every shape, after a key that is not allowed.
    static let secret = "Qx7hunter"
    static let tail = " user=\(secret)"

    /// Different scalars from `start` on, `perWord` of them before each space, to `size` bytes of
    /// UTF-8; surrogates and the space are skipped, and after U+10FFFF the scalars go on from
    /// U+0080.
    static func distinct(from start: UInt32, size: Int, perWord: Int = 1) -> String {
        var view = String.UnicodeScalarView()
        var bytes = 0
        var value = start
        while bytes < size {
            for _ in 0..<perWord {
                while Unicode.Scalar(value) == nil || value == 0x20 { value = value >= 0x10FFFF ? 0x80 : value + 1 }
                let scalar = Unicode.Scalar(value)!
                view.append(scalar)
                bytes += UTF8.width(scalar)
                value = value >= 0x10FFFF ? 0x80 : value + 1
            }
            view.append(" ")
            bytes += 1
        }
        return String(view)
    }

    private static let size = RedactionTimeLimitTests.size - tail.utf8.count

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let redact: @Sendable (String) -> String = redactor.redact
        let matches: @Sendable (String) -> String = { "\(redactor.matches(in: $0).count)" }
        let shapes: [(String, @Sendable () -> String, @Sendable (String) -> String)] = [
            ("every scalar from U+30000 on, each and a space", { distinct(from: 0x30000, size: size) + tail }, redact),
            ("every scalar from U+0080 on, each and a space", { distinct(from: 0x80, size: size) + tail }, redact),
            ("every scalar from U+10000 on, each and a space", { distinct(from: 0x10000, size: size) + tail }, redact),
            ("private use scalars, each and a space", { distinct(from: 0xF0000, size: size) + tail }, redact),
            ("every scalar from U+30000 on, no spaces", { distinct(from: 0x30000, size: size, perWord: 50_000) + tail }, redact),
            ("every scalar from U+4E00 on, in words of three", { distinct(from: 0x4E00, size: size, perWord: 3) + tail }, redact),
            ("every scalar from U+0080 on, as matches", { distinct(from: 0x80, size: size) }, matches),
            ("every scalar from U+30000 on, as matches", { distinct(from: 0x30000, size: size) }, matches),
        ]
        return shapes.map { name, make, run in TimedInput(testDescription: name, make: make, redact: run) }
    }()

    /// Four megabytes of different scalars, which may take four times the memory of one.
    static let large = TimedInput(testDescription: "every scalar from U+10000 on, each and a space, 4 MB", make: {
        distinct(from: 0x10000, size: 4 * RedactionTimeLimitTests.size) + tail
    }, redact: SensitiveDataRedactor().redact)

    /// How many times ``RedactionTimeLimitTests/size`` the large shape is.
    static let largeFactor = 4

    /// Bodies just under `size` of different scalars: a JSON string, a JSON array of strings of
    /// one scalar each and a text/plain body.
    static func bodies(size: Int, redactor: SensitiveDataRedactor) -> [TimedInput] {
        let strings: @Sendable () -> String = {
            var parts: [String] = []
            var bytes = 2
            var value: UInt32 = 0x30000
            while bytes < size - 16 {
                let scalar = String(Unicode.Scalar(value)!)
                parts.append("\"" + scalar + "\"")
                bytes += scalar.utf8.count + 3
                value += 1
            }
            return "[" + parts.joined(separator: ",") + "]"
        }
        return [
            TimedInput(testDescription: "a JSON string of different scalars", make: {
                "[\"" + distinct(from: 0x30000, size: size - 8) + "\"]"
            }, redact: { redactor.redact(body: Data($0.utf8), contentType: "application/json") }),
            TimedInput(testDescription: "a JSON array of strings of different scalars", make: strings, redact: {
                redactor.redact(body: Data($0.utf8), contentType: "application/json")
            }),
            TimedInput(testDescription: "a text/plain body of different scalars", make: {
                distinct(from: 0x80, size: size - 16)
            }, redact: { redactor.redact(body: Data($0.utf8), contentType: "text/plain") }),
        ]
    }
}
