import Darwin
import Foundation
import Testing
import iOSSecurityTools

/// The memory that redacting a megabyte takes: the text, its scalars and its scanning copy, the
/// findings and the output, and nothing that grows with the number of names or keys in it. The
/// twelfth review measured 583 MB for a start tag of a megabyte of attributes followed by 17
/// secret names, which the free text of 2.1.0 kept once for every name.
@Suite("SensitiveDataRedactor peak memory", .serialized)
struct RedactionPeakMemoryTests {
    static let limit = 16 * 1_048_576
    private static let redactor = SensitiveDataRedactor()

    static let shapes: [TimedInput] = RedactionTimeLimitTests.attributeShapes + [
        TimedInput(testDescription: "Turkish prose", make: {
            RedactionTimeLimitTests.repeated("Kullanıcı giriş yaptı ve sipariş verdi ", to: RedactionTimeLimitTests.size)
        }, redact: redactor.redact),
        TimedInput(testDescription: "a line of JSON", make: {
            "log {\"status\":[" + RedactionTimeLimitTests.repeated("1,", to: RedactionTimeLimitTests.size - 20) + "1]}"
        }, redact: redactor.redact),
        TimedInput(testDescription: "lines of URLs", make: {
            RedactionTimeLimitTests.repeated("see https://example.com/a/b?status=1\n", to: RedactionTimeLimitTests.size)
        }, redact: redactor.redact),
        TimedInput(testDescription: "lines of addresses", make: {
            RedactionTimeLimitTests.repeated("mail alice@example.com\n", to: RedactionTimeLimitTests.size)
        }, redact: redactor.redact),
    ]

    /// The bytes that malloc holds for the process.
    private static func allocatedBytes() -> Int {
        var statistics = malloc_statistics_t()
        malloc_zone_statistics(nil, &statistics)
        return Int(statistics.size_in_use)
    }

    /// The most bytes malloc held beyond what it held before while `work` ran on a thread with a
    /// 512 KiB stack, sampled every 100 µs.
    static func peakAllocation(_ work: @escaping @Sendable () -> Void) -> Int {
        let base = allocatedBytes()
        var peak = 0
        let finished = DispatchSemaphore(value: 0)
        let thread = Thread {
            work()
            finished.signal()
        }
        thread.stackSize = RedactionStackTests.threadStack
        thread.start()
        while finished.wait(timeout: .now() + .microseconds(100)) == .timedOut {
            peak = max(peak, allocatedBytes() - base)
        }
        return max(peak, allocatedBytes() - base)
    }

    /// The fewest bytes of `attempts` measurements of a shape.
    static func fewestBytes(_ input: TimedInput, attempts: Int) -> Int {
        let text = input.make()
        var fewest = Int.max
        for _ in 0..<attempts where fewest >= limit {
            fewest = min(fewest, peakAllocation { _ = input.redact(text) })
        }
        return fewest
    }

    #if os(macOS) || os(Linux)
    // Other tests allocate while they run beside this one, so the shapes are measured in a process
    // of their own, which runs nothing else and writes one line for each shape.
    @Test("redacting a megabyte takes less than 16 MB more memory")
    func peak() async throws {
        let result = try await #require(processExitsWith: .success, observing: [\.standardOutputContent]) {
            for input in RedactionPeakMemoryTests.shapes {
                print("\(RedactionPeakMemoryTests.fewestBytes(input, attempts: 2))\t\(input.testDescription)")
            }
        }
        let lines = String(decoding: result.standardOutputContent, as: UTF8.self).split(separator: "\n")
        #expect(lines.count == Self.shapes.count)
        for line in lines {
            let fields = line.split(separator: "\t", maxSplits: 1)
            let bytes = Int(fields[0]) ?? .max
            #expect(bytes < Self.limit, "\(fields.last ?? ""): \(bytes / 1_024) KiB")
        }
    }
    #else
    // Without processes of their own, the shapes are measured beside the other tests, and the
    // fewest of ten runs is taken: their allocations can only add to it.
    @Test("redacting a megabyte takes less than 16 MB more memory", arguments: shapes)
    func peak(input: TimedInput) {
        let bytes = Self.fewestBytes(input, attempts: 10)
        #expect(bytes < Self.limit, "\(input.testDescription): \(bytes / 1_048_576) MB")
    }
    #endif

    @Test("the review's start tag of a megabyte of attributes hides the value after the names")
    func attributesHideTheValue() {
        for input in RedactionTimeLimitTests.attributeShapes.prefix(4) {
            #expect(!input.redact(input.make()).contains("HUNTER2"), "\(input.testDescription)")
        }
    }
}
