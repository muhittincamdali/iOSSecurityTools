import Foundation
import iOSSecurityTools

/// Secret names inside values that are hidden already, which the trigger pass reads a second
/// time: a line of a megabyte after one key, names held by keys on every few characters, part
/// headers of a multipart body written to a log, and JSON after `name=` that never closes.
extension RedactionTimeLimitTests {
    private static let textRedactor = SensitiveDataRedactor()

    /// `unit` repeated to about a megabyte after `prefix`.
    private static func line(_ prefix: String, _ unit: String) -> String {
        prefix + String(repeating: unit, count: (size - prefix.utf8.count) / unit.utf8.count)
    }

    static let namesInHiddenValues: [TimedInput] = [
        TimedInput(testDescription: "a line of a megabyte of names held by keys after a key", make: { line("x: ", "name=\"pin\" ") }, redact: textRedactor.redact),
        TimedInput(testDescription: "a line of a megabyte of unquoted names after a key", make: { line("x: ", "name=password ") }, redact: textRedactor.redact),
        TimedInput(testDescription: "a line of a megabyte of keys", make: { line("", "a: ") }, redact: textRedactor.redact),
        TimedInput(testDescription: "a line of a megabyte of secret words in a start tag after a key", make: {
            line("x: <a b=\"1\" ", "password ")
        }, redact: textRedactor.redact),
        TimedInput(testDescription: "a line of a megabyte of elements named by secret names after a key", make: {
            line("x: ", "<string name=\"api_key\">")
        }, redact: textRedactor.redact),
        TimedInput(testDescription: "a line of a megabyte of quoted values that hold names", make: { line("x: ", "\"a=\\\"b\\\"\" ") }, redact: textRedactor.redact),
        TimedInput(testDescription: "lines of JSON after name= that never closes", make: { line("", "note: name=[\n") }, redact: textRedactor.redact),
        TimedInput(testDescription: "lines of part headers that name secrets", make: {
            line("", "Content-Disposition: form-data; name=\"pin\"\n\nx\n")
        }, redact: textRedactor.redact),
        TimedInput(testDescription: "a multipart body written to a log, of parts that name secrets", make: {
            line("", "--B\r\nContent-Disposition: form-data; name=\"pin\"\r\nContent-Type: text/plain\r\n\r\nx\r\n")
        }, redact: textRedactor.redact),
        TimedInput(testDescription: "a JSON body of strings that hold multipart bodies", make: {
            let element = #""--B\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\nx\r\n--B--","#
            return "[" + String(repeating: element, count: size / element.utf8.count) + "\"\"]"
        }, redact: { textRedactor.redact(body: Data($0.utf8), contentType: "application/json") }),
    ]
}
