import Foundation
import iOSSecurityTools

/// A megabyte of free text dense with findings, timed and measured as the other shapes are. The
/// eighteenth review measured 18.55 MiB for a megabyte of log lines of short addresses with one `ﬁ`
/// each, 17.69 MiB for ``SensitiveDataRedactor/matches(in:)`` on short addresses after a `ﬁ`, and
/// up to 17.6 MiB for short addresses after a zero-width space that hid them all. The scanning copy
/// kept an offset for each byte once one scalar was read as several, each finding took 40 bytes
/// in an array that doubled as it grew, the detectors read past the cut, and `matches(in:)` kept an
/// index for each scalar. Now the offsets are kept as runs, a finding takes 24 bytes in an array
/// of exactly the size it needs, the detectors stop at the cut, and `matches(in:)` finds the index
/// of each start and end in one walk. The shapes after the review's are the densest findings the
/// detectors have: a user info password every four bytes (`1:2@`), an address every seven.
enum DenseFindingShapes {
    private static func lines(_ line: String, size: Int = RedactionTimeLimitTests.size) -> String {
        String(repeating: line, count: max(1, size / line.utf8.count))
    }

    static let text: [TimedInput] = {
        let redactor = SensitiveDataRedactor()
        let redact: @Sendable (String) -> String = redactor.redact
        let matches: @Sendable (String) -> String = { "\(redactor.matches(in: $0).count)" }
        let shapes: [(String, @Sendable () -> String, @Sendable (String) -> String)] = [
            ("short addresses after a ligature", { "\u{FB01} " + lines("a@b.cd ") }, redact),
            ("lines of short addresses, a ligature each", { lines("\u{FB01} a@b.cd a@b.cd a@b.cd a@b.cd\n") }, redact),
            ("short addresses after a zero-width space, all hidden", { "\u{200B}" + lines("a@b.cd ") }, redact),
            ("short addresses after a zero-width space, as matches", { "\u{200B}" + lines("a@b.cd ") }, matches),
            ("short addresses after the letter ĳ", { "\u{0133} " + lines("a@b.cd ") }, redact),
            ("short addresses", { lines("a@b.cd ") }, redact),
            ("short addresses after a ligature, as matches", { "\u{FB01} " + lines("a@b.cd ") }, matches),
            ("short addresses with a ligature each, no space", { lines("\u{FB01}a@b.cd,") }, redact),
            ("addresses after a ligature", { "\u{FB01} " + lines("alice@example.com ") }, redact),
            ("addresses after a ligature, as matches", { "\u{FB01} " + lines("alice@example.com ") }, matches),
            ("card numbers after a ligature", { "\u{FB01} " + lines("4242 4242 4242 4242 ") }, redact),
            ("IBANs after a ligature", { "\u{FB01} " + lines("DE89370400440532013000 ") }, redact),
            ("user info passwords in words of 64", { lines(String(repeating: "1:2@", count: 63) + "1:2 ") }, redact),
            ("user info passwords in words of 64, as matches", { lines(String(repeating: "1:2@", count: 63) + "1:2 ") }, matches),
            ("user info passwords and addresses", { lines("1:2@a.bc ") }, redact),
            ("ASCII prose after an é, as matches", { "\u{E9} " + lines("the quick brown fox ") }, matches),
        ]
        return shapes.map { name, make, run in TimedInput(testDescription: name, make: make, redact: run) }
    }()

    /// Bodies of the review just under the default limit: a text/plain body and a JSON string of
    /// short addresses after a `ﬁ`.
    static func bodies(size: Int, redactor: SensitiveDataRedactor) -> [TimedInput] {
        [
            TimedInput(testDescription: "a text/plain body of short addresses after a ligature", make: {
                "\u{FB01} " + lines("a@b.cd ", size: size - 16)
            }, redact: { redactor.redact(body: Data($0.utf8), contentType: "text/plain") }),
            TimedInput(testDescription: "a JSON string of short addresses after a ligature", make: {
                "{\"note\":\"\u{FB01} " + lines("a@b.cd ", size: size - 32) + "\"}"
            }, redact: { redactor.redact(body: Data($0.utf8), contentType: "application/json") }),
        ]
    }
}
