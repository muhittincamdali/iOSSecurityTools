import Foundation
import iOSSecurityTools

/// Bodies of 256 KiB of arrays 63 deep, with a `1`, an empty array or an empty string inside: a
/// JSON value for nearly every two bytes, each in an array of its own. The nineteenth review
/// measured 15.65 MiB for them, close to the limit of 16 MiB, when every value of the reader's
/// tree kept its range in two `Int`s and a box of its own, and the body was encoded again for
/// `JSONSerialization`. They are held to ``RedactionPeakMemoryTests/deepArrayLimit``.
enum DeepArrayShapes {
    static func bodies(size: Int, redactor: SensitiveDataRedactor) -> [TimedInput] {
        let insides = [("a 1", "1"), ("an empty array", "[]"), ("an empty string", "\"\"")]
        return insides.map { name, inside in
            TimedInput(testDescription: "body: arrays 63 deep with \(name) inside", make: {
                let element = String(repeating: "[", count: 62) + inside + String(repeating: "]", count: 62)
                let count = (size - 1) / (element.utf8.count + 1)
                return "[" + Array(repeating: element, count: count).joined(separator: ",") + "]"
            }, redact: { redactor.redact(body: Data($0.utf8), contentType: "application/json") })
        }
    }
}
