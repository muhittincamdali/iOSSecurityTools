import Foundation
import Testing
import iOSSecurityTools

/// The shapes of the twenty-fifth correctness review (`c-25`) that read the same bytes again in
/// the value detectors. For every `eyJ` the JSON Web Token detector looked for the next `.` from
/// the start of the candidate, through the rest of the text: a megabyte of `eyJ ` took 46.6 s in a
/// release build, against 0.164 s before, a JSON body of 256 KiB of them 2.0 s and log lines of
/// `cursor eyJpZCI6MTIzfQ` 1.53 s a megabyte. A candidate that was not a token moved on by the
/// characters of its first segment, not the bytes, so the line separators it read across were
/// read again: `eyJ` and 1,000 vertical tabs, repeated, took 1.38 s a megabyte at 64 MB with the
/// token detector alone. The detectors now keep where the payload starts as they read it and move
/// on by bytes. A megabyte of line separators between digits, groups and tokens is timed too, with
/// every kind and with the value detectors alone, which read across the separators everywhere.
enum DetectorScanShapes {
    static let detectorsOnly = SensitiveDataRedactor(kinds: SensitiveDataRedactor.Kinds.all.subtracting(.secretFields))
    static let tokensOnly = SensitiveDataRedactor(kinds: [.jsonWebTokens])

    /// `unit` repeated to about `total` bytes.
    static func repeated(_ unit: String, to total: Int) -> String {
        String(repeating: unit, count: max(1, total / unit.utf8.count))
    }

    /// `eyJ` and `breaks` vertical tabs.
    static func tokenStart(breaks: Int) -> String { "eyJ" + String(repeating: "\u{0B}", count: breaks) }

    static let separatorUnits = [
        "1\u{0B}", "4242\u{2028}", "1\u{2028}2\u{85}3\u{0C}4\u{0B}5 ", "4242\u{0B}\u{0B}\u{0B}", "DE89\u{2028}3704\u{2028}", "a@b\u{2028}",
        "@\u{0B}", "bearer\u{0B}", "eyJ\u{2028}", "eyJa.\u{2028}", "eyJabcd.eyJ\u{0B}", "a1\u{0B}", String(repeating: "a1", count: 16) + "\u{0B}",
    ]

    static func shapes(size: Int, bodies: SensitiveDataRedactor) -> [TimedInput] {
        let redactor = SensitiveDataRedactor()
        var shapes = [
            TimedInput(testDescription: "a megabyte of eyJ and a space", make: { repeated("eyJ ", to: size) }, redact: redactor.redact),
            TimedInput(testDescription: "a megabyte of eyJ and a line feed", make: { repeated("eyJ\n", to: size) }, redact: redactor.redact),
            TimedInput(testDescription: "log lines of a cursor that starts like a token", make: {
                repeated("cursor eyJpZCI6MTIzfQ\n", to: size)
            }, redact: redactor.redact),
            TimedInput(testDescription: "a text/plain body of eyJ and a space", make: { repeated("eyJ ", to: size) }, redact: {
                bodies.redact(body: Data($0.utf8), contentType: "text/plain")
            }),
            TimedInput(testDescription: "a JSON string of eyJ and a space", make: { "{\"note\":\"" + repeated("eyJ ", to: size - 12) + "\"}" }, redact: {
                bodies.redact(body: Data($0.utf8), contentType: "application/json")
            }),
            TimedInput(testDescription: "the matches in a megabyte of eyJ and a space", make: { repeated("eyJ ", to: size) }, redact: {
                String(redactor.matches(in: $0).count)
            }),
            TimedInput(testDescription: "eyJ and 1,000 vertical tabs, the token detector alone", make: {
                repeated(tokenStart(breaks: 1_000), to: size)
            }, redact: tokensOnly.redact),
            TimedInput(testDescription: "eyJ and 1,000 vertical tabs, the value detectors alone", make: {
                repeated(tokenStart(breaks: 1_000), to: size)
            }, redact: detectorsOnly.redact),
        ]
        for unit in separatorUnits {
            shapes.append(TimedInput(testDescription: "line separators: \(unit.debugDescription)", make: { repeated(unit, to: size) }, redact: redactor.redact))
            shapes.append(TimedInput(testDescription: "line separators, the value detectors alone: \(unit.debugDescription)", make: {
                repeated(unit, to: size)
            }, redact: detectorsOnly.redact))
        }
        return shapes
    }
}

extension RedactionTimeLimitTests {
    @Test("the token detector reads 4 MB of eyJ and vertical tabs in less than a second a megabyte", arguments: [
        ("the token detector alone", DetectorScanShapes.tokensOnly), ("the value detectors alone", DetectorScanShapes.detectorsOnly),
        ("every kind", SensitiveDataRedactor()),
    ])
    func fourMegabytesOfTokenStarts(name: String, redactor: SensitiveDataRedactor) {
        let megabytes = 4
        for breaks in [1_000, 2_000] {
            let text = DetectorScanShapes.repeated(DetectorScanShapes.tokenStart(breaks: breaks), to: megabytes * Self.mebibyte)
            var fastest = Duration.seconds(Int64.max)
            for _ in 0..<3 where fastest >= Self.limit * megabytes {
                let time = onThread(stackSize: RedactionStackTests.threadStack) {
                    let start = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
                    _ = redactor.redact(text)
                    return Duration.nanoseconds(Int64(clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - start))
                }
                fastest = min(fastest, time)
            }
            #expect(fastest < Self.limit * megabytes, "\(name), \(breaks) tabs: \(fastest)")
        }
    }
}
