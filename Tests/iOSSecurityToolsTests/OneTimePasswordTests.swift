import Foundation
import Testing
@testable import iOSSecurityTools

@Suite("HOTP")
struct HOTPTests {
    let rfcSecret = Data("12345678901234567890".utf8)

    @Test("matches RFC 4226 appendix D for counters 0 to 9")
    func rfc4226() throws {
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        let hotp = try HOTP(secret: rfcSecret)
        #expect((0..<10).map { hotp.code(counter: UInt64($0)) } == expected)
    }

    @Test("verify returns the matching counter within the look-ahead")
    func lookAhead() throws {
        let hotp = try HOTP(secret: rfcSecret)
        #expect(try hotp.verify("969429", counter: 0, lookAhead: 5) == 3)
        #expect(try hotp.verify("969429", counter: 0, lookAhead: 2) == nil)
        #expect(try hotp.verify("755224", counter: 1, lookAhead: 5) == nil)
    }

    @Test("verify stops at UInt64.max instead of overflowing")
    func counterOverflow() throws {
        let hotp = try HOTP(secret: rfcSecret)
        let last = hotp.code(counter: .max)
        #expect(try hotp.verify(last, counter: .max - 1, lookAhead: HOTP.maximumLookAhead) == .max)
        let other = hotp.code(counter: 0)
        #expect(other != last)
        #expect(try hotp.verify(other, counter: .max, lookAhead: 3) == nil)
    }

    @Test("codes that are not exactly the right number of ASCII digits fail", arguments: ["", "75522", "7552240", " 755224", "755224 ", "75522a", "７５５２２４", "-55224", "+55224"])
    func malformedCodes(code: String) throws {
        #expect(try HOTP(secret: rfcSecret).verify(code, counter: 0, lookAhead: 10) == nil)
    }

    @Test("rejects secrets, digit counts and look-aheads outside their ranges")
    func ranges() throws {
        #expect(throws: OTPError.invalidSecret) { try HOTP(secret: Data(count: 9)) }
        #expect(throws: OTPError.invalidSecret) { try HOTP(secret: Data(count: 1025)) }
        for digits in [Int.min, 0, 5, 9, Int.max] {
            #expect(throws: OTPError.invalidDigits(digits)) { try HOTP(secret: rfcSecret, digits: digits) }
        }
        let hotp = try HOTP(secret: rfcSecret)
        for lookAhead in [-1, HOTP.maximumLookAhead + 1, Int.max] {
            #expect(throws: OTPError.invalidWindow(lookAhead)) { try hotp.verify("755224", counter: 0, lookAhead: lookAhead) }
        }
    }

    @Test("pads codes with leading zeros")
    func leadingZeros() throws {
        // RFC 6238 vector: SHA-1, 8 digits, T = 1111111109 gives 07081804.
        let hotp = try HOTP(secret: rfcSecret, digits: 8)
        #expect(hotp.code(counter: 1_111_111_109 / 30) == "07081804")
    }
}

@Suite("TOTP")
struct TOTPTests {
    static let secrets: [OTPAlgorithm: Data] = [
        .sha1: Data("12345678901234567890".utf8),
        .sha256: Data("12345678901234567890123456789012".utf8),
        .sha512: Data("1234567890123456789012345678901234567890123456789012345678901234".utf8),
    ]

    // RFC 6238 appendix B.
    static let vectors: [(TimeInterval, String, String, String)] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ]

    @Test("matches RFC 6238 appendix B for SHA-1, SHA-256 and SHA-512", arguments: vectors)
    func rfc6238(vector: (TimeInterval, String, String, String)) throws {
        let date = Date(timeIntervalSince1970: vector.0)
        let expected: [OTPAlgorithm: String] = [.sha1: vector.1, .sha256: vector.2, .sha512: vector.3]
        for algorithm in OTPAlgorithm.allCases {
            let totp = try TOTP(secret: Self.secrets[algorithm]!, algorithm: algorithm, digits: 8)
            #expect(try totp.code(at: date) == expected[algorithm])
            #expect(try totp.verify(expected[algorithm]!, at: date, window: 0))
        }
    }

    @Test("accepts codes one period early or late with the default window, not two")
    func window() throws {
        let totp = try TOTP(secret: Self.secrets[.sha1]!)
        let now = Date(timeIntervalSince1970: 1_700_000_015)
        let previous = try totp.code(at: now.addingTimeInterval(-30))
        let next = try totp.code(at: now.addingTimeInterval(30))
        let current = try totp.code(at: now)
        let twoAhead = try totp.code(at: now.addingTimeInterval(60))
        #expect(try totp.verify(previous, at: now))
        #expect(try totp.verify(next, at: now))
        #expect(try !totp.verify(previous, at: now, window: 0))
        // A code two periods ahead is rejected unless it happens to equal an accepted one.
        #expect(![previous, current, next].contains(twoAhead))
        #expect(try !totp.verify(twoAhead, at: now))
    }

    @Test("the window does not go below the first time step")
    func windowAtEpoch() throws {
        let totp = try TOTP(secret: Self.secrets[.sha1]!)
        let epoch = Date(timeIntervalSince1970: 0)
        #expect(try totp.verify(totp.code(at: epoch), at: epoch, window: TOTP.maximumWindow))
    }

    @Test("NaN, infinite, negative and huge times throw instead of trapping", arguments: [
        TimeInterval.nan, .infinity, -.infinity, -1, -0.5, 0x1p63, .greatestFiniteMagnitude,
    ])
    func invalidTimes(seconds: TimeInterval) throws {
        let totp = try TOTP(secret: Self.secrets[.sha1]!)
        let date = Date(timeIntervalSince1970: seconds)
        #expect(throws: OTPError.invalidTime) { try totp.code(at: date) }
        #expect(throws: OTPError.invalidTime) { try totp.verify("123456", at: date) }
        #expect(throws: OTPError.invalidTime) { try totp.secondsRemaining(at: date) }
    }

    @Test("the largest accepted time still produces a code")
    func largestTime() throws {
        let totp = try TOTP(secret: Self.secrets[.sha1]!)
        let date = Date(timeIntervalSince1970: 0x1p63.nextDown)
        #expect(try totp.code(at: date).count == 6)
    }

    @Test("seconds remaining counts down within each period")
    func secondsRemaining() throws {
        let totp = try TOTP(secret: Self.secrets[.sha1]!, period: 30)
        #expect(try totp.secondsRemaining(at: Date(timeIntervalSince1970: 60)) == 30)
        #expect(try totp.secondsRemaining(at: Date(timeIntervalSince1970: 61)) == 29)
        #expect(try totp.secondsRemaining(at: Date(timeIntervalSince1970: 89.9)) == 1)
    }

    @Test("rejects periods and windows outside their ranges")
    func ranges() throws {
        for period in [Int.min, -30, 0, 3601, Int.max] {
            #expect(throws: OTPError.invalidPeriod(period)) { try TOTP(secret: Self.secrets[.sha1]!, period: period) }
        }
        let totp = try TOTP(secret: Self.secrets[.sha1]!)
        for window in [-1, TOTP.maximumWindow + 1, Int.max] {
            #expect(throws: OTPError.invalidWindow(window)) { try totp.verify("123456", window: window) }
        }
    }

    @Test("Base32 secrets ignore case, spaces, hyphens and padding")
    func base32Secret() throws {
        let canonical = try TOTP(base32Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        let typed = try TOTP(base32Secret: "gezd gnbv-gy3t qojq gezd gnbv gy3t qojq====")
        #expect(canonical == typed)
        #expect(canonical.generator.secret == Data("12345678901234567890".utf8))
        for invalid in ["GEZDGNBVGY3TQOJ1", "GEZDGNBV=GY3TQOJQ", "", "GEZDGNB", String(repeating: "A", count: 2049)] {
            #expect(throws: OTPError.invalidSecret) { try TOTP(base32Secret: invalid) }
        }
    }

    @Test("printing a generator does not reveal the secret")
    func descriptionHidesSecret() throws {
        let totp = try TOTP(base32Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        var dumped = ""
        dump(totp, to: &dumped)
        for text in ["\(totp)", String(reflecting: totp), dumped] {
            #expect(!text.contains("GEZDGNBV"))
            #expect(!text.contains("49, 50, 51"))
            #expect(!text.contains("20 bytes"))
            #expect(!text.lowercased().contains("secret"))
        }
        #expect("\(totp)" == "TOTP(SHA1, 6 digits, 30 s)")
    }
}

@Suite("Base32")
struct Base32Tests {
    @Test("matches RFC 4648 section 10", arguments: [
        ("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI"),
    ])
    func rfc4648(plain: String, encoded: String) {
        #expect(Base32.encode(Data(plain.utf8)) == encoded)
        #expect(Base32.decode(encoded) == Data(plain.utf8))
        #expect(Base32.decode(encoded + String(repeating: "=", count: (8 - encoded.count % 8) % 8)) == Data(plain.utf8))
    }

    @Test("round-trips random lengths")
    func roundTrip() throws {
        for length in 1...64 {
            let data = try SecureRandom.bytes(count: length)
            #expect(Base32.decode(Base32.encode(data)) == data)
        }
    }

    @Test("rejects characters outside the alphabet and impossible lengths", arguments: ["M", "MZX", "MZXW6Y", "MZ1", "MZ8", "MZ!", "MZ\u{0}", "ＭＺ"])
    func invalid(text: String) {
        #expect(Base32.decode(text) == nil)
    }
}

@Suite("OTPAuthURI")
struct OTPAuthURITests {
    @Test("parses a TOTP URI with every parameter")
    func parseTOTP() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60")
        #expect(uri.issuer == "ACME Co")
        #expect(uri.account == "john.doe@email.com")
        guard case .totp(let totp) = uri.kind else {
            Issue.record("Expected a TOTP URI")
            return
        }
        #expect(totp.algorithm == .sha256)
        #expect(totp.digits == 8)
        #expect(totp.period == 60)
    }

    @Test("uses defaults and takes the issuer from the label")
    func defaults() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP")
        #expect(uri.issuer == "Example")
        guard case .totp(let totp) = uri.kind else {
            Issue.record("Expected a TOTP URI")
            return
        }
        #expect(totp.algorithm == .sha1 && totp.digits == 6 && totp.period == 30)
    }

    @Test("parses an HOTP URI with its counter")
    func parseHOTP() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3")
        guard case .hotp(let hotp, let counter) = uri.kind else {
            Issue.record("Expected an HOTP URI")
            return
        }
        #expect(counter == 3)
        #expect(hotp.code(counter: counter) == "969429")
        #expect(uri.issuer == nil)
    }

    @Test("round-trips through uriString, including characters that need encoding")
    func roundTrip() throws {
        let totp = try TOTP(secret: Data("12345678901234567890".utf8), algorithm: .sha512, digits: 7, period: 45)
        let original = try OTPAuthURI(kind: .totp(totp), account: "a+b c@example.com", issuer: "Bank & Co")
        let text = original.uriString
        #expect(text.hasPrefix("otpauth://totp/"))
        #expect(!text.contains(" "))
        #expect(try OTPAuthURI(parsing: text) == original)

        let hotp = try OTPAuthURI(kind: .hotp(HOTP(secret: Data(count: 16)), counter: 42), account: "bob")
        #expect(try OTPAuthURI(parsing: hotp.uriString) == hotp)
    }

    @Test("rejects ambiguous, hostile and out-of-range URIs", arguments: [
        "https://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
        "otpauth://sotp/Example:alice?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/Example:alice",
        "otpauth://totp/Example:alice?secret=",
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PX1",
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBVGY3TQOJQ",
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&ISSUER=Example&issuer=Example",
        "otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP&issuer=Evil",
        "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/Example:?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/a:b:c?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=5",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=-6",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=99999999999999999999",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&period=1e3",
        "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP",
        "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=-1",
        "otpauth://totp/alice?secret=MZXW6",
        "not a uri",
        "",
    ])
    func invalid(text: String) {
        #expect(throws: OTPError.self) { try OTPAuthURI(parsing: text) }
    }

    @Test("rejects URIs longer than the limit")
    func tooLong() {
        let text = "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&image=" + String(repeating: "a", count: OTPAuthURI.maximumLength)
        #expect(throws: OTPError.self) { try OTPAuthURI(parsing: text) }
    }

    @Test("rejects colons and empty accounts when building a URI")
    func invalidBuild() throws {
        let totp = try TOTP(secret: Data(count: 20))
        #expect(throws: OTPError.self) { try OTPAuthURI(kind: .totp(totp), account: "") }
        #expect(throws: OTPError.self) { try OTPAuthURI(kind: .totp(totp), account: "a:b") }
        #expect(throws: OTPError.self) { try OTPAuthURI(kind: .totp(totp), account: "a", issuer: "x:y") }
    }

    @Test("printing a URI does not reveal the secret")
    func descriptionHidesSecret() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP")
        var dumped = ""
        dump(uri, to: &dumped)
        for text in ["\(uri)", String(reflecting: uri), dumped] {
            #expect(!text.contains("JBSWY3DP"))
            #expect(!text.contains("bytes"))
        }
        #expect("\(uri)" == "OTPAuthURI(Example: alice, TOTP(SHA1, 6 digits, 30 s))")
    }
}
