import Foundation
import iOSSecurityTools

/// The shapes of the twelfth review that made the free text of 2.1.0 before the one cut keep the
/// attribute values of a start tag once for every name in it: a megabyte of attributes followed
/// by 17 secret names, in one start tag, in one tag after a key and in tags of 4 KB on their own
/// lines, and the same as a text/plain body. They are read once, up to the first trigger.
extension RedactionTimeLimitTests {
    private static let cutRedactor = SensitiveDataRedactor()

    /// `unit` repeated to about `total` bytes.
    static func repeated(_ unit: String, to total: Int) -> String {
        String(repeating: unit, count: max(1, total / unit.utf8.count))
    }

    /// The names that followed the attributes in the review.
    static let seventeenNames = String(repeating: " name=\"pin\"", count: 17)

    static let attributeShapes: [TimedInput] = [
        TimedInput(testDescription: "a start tag of a megabyte of attributes after a key, then 17 names", make: {
            "x: <a " + repeated("b=\"1\" ", to: size - 300) + seventeenNames + ">HUNTER2"
        }, redact: cutRedactor.redact),
        TimedInput(testDescription: "a start tag of a megabyte of attributes, then 17 names", make: {
            "<a " + repeated("b=\"1\" ", to: size - 300) + seventeenNames + ">HUNTER2"
        }, redact: cutRedactor.redact),
        TimedInput(testDescription: "lines of 4 KB start tags of attributes, each with 17 names", make: {
            repeated("<a " + repeated("b=\"1\" ", to: 4_000) + seventeenNames + ">HUNTER2\n", to: size)
        }, redact: cutRedactor.redact),
        TimedInput(testDescription: "a text/plain body of a start tag of attributes, then 17 names", make: {
            "<a " + repeated("b=\"1\" ", to: size - 300) + seventeenNames + ">HUNTER2"
        }, redact: { cutRedactor.redact(body: Data($0.utf8), contentType: "text/plain") }),
        TimedInput(testDescription: "prose without a trigger", make: {
            repeated("the quick brown fox jumps over the lazy dog ", to: size)
        }, redact: cutRedactor.redact),
        TimedInput(testDescription: "lines of allowed keys only", make: {
            repeated("status=200 method=GET path=/api/items count=3 duration_ms=12\n", to: size)
        }, redact: cutRedactor.redact),
    ]
}
