import CryptoKit
import Foundation

/// The HMAC hash function of a one-time password.
public enum OTPAlgorithm: String, Sendable, Hashable, CaseIterable {
    /// HMAC-SHA1, the default of RFC 4226 and of most authenticator apps.
    case sha1 = "SHA1"
    /// HMAC-SHA256.
    case sha256 = "SHA256"
    /// HMAC-SHA512.
    case sha512 = "SHA512"
}

/// Counter-based one-time passwords (HOTP, RFC 4226).
///
/// Most apps want time-based codes; see ``TOTP``.
public struct HOTP: Sendable, Hashable {
    /// Accepted secret sizes in bytes. RFC 4226 asks for at least 16 bytes; 10 is accepted
    /// because many services still issue 80-bit secrets.
    public static let secretLengthRange = 10...1024
    /// Accepted code lengths.
    public static let digitRange = 6...8
    /// The largest look-ahead ``verify(_:counter:lookAhead:)`` accepts.
    public static let maximumLookAhead = 100

    /// The hash function.
    public let algorithm: OTPAlgorithm
    /// The number of digits in a code.
    public let digits: Int
    let secret: Data

    /// Creates a generator.
    ///
    /// - Parameters:
    ///   - secret: The shared secret, 10 to 1024 bytes.
    ///   - algorithm: The hash function.
    ///   - digits: The code length, 6 to 8.
    /// - Throws: ``OTPError/invalidSecret`` or ``OTPError/invalidDigits(_:)``.
    public init(secret: Data, algorithm: OTPAlgorithm = .sha1, digits: Int = 6) throws(OTPError) {
        guard Self.secretLengthRange.contains(secret.count) else { throw .invalidSecret }
        guard Self.digitRange.contains(digits) else { throw .invalidDigits(digits) }
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
    }

    /// Returns the code for a counter value, padded with leading zeros to ``digits``.
    public func code(counter: UInt64) -> String {
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: [UInt8] = switch algorithm {
        case .sha1: Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        // Dynamic truncation, RFC 4226 section 5.3.
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (UInt32(mac[offset] & 0x7F) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let value = String(binary % modulus)
        return String(repeating: "0", count: digits - value.count) + value
    }

    /// Checks a code against the counters from `counter` to `counter + lookAhead`.
    ///
    /// - Parameters:
    ///   - code: The code the user entered. Anything other than exactly ``digits`` ASCII digits
    ///     fails.
    ///   - counter: The next counter the server expects.
    ///   - lookAhead: How many counters past `counter` to accept, 0 to ``maximumLookAhead``, for
    ///     codes generated but not used.
    /// - Returns: The counter that matched, or `nil`. Store the result plus one as the next
    ///   expected counter so the code cannot be used twice.
    /// - Throws: ``OTPError/invalidWindow(_:)`` for a look-ahead outside its range.
    public func verify(_ code: String, counter: UInt64, lookAhead: Int = 0) throws(OTPError) -> UInt64? {
        guard (0...Self.maximumLookAhead).contains(lookAhead) else { throw .invalidWindow(lookAhead) }
        guard isWellFormed(code) else { return nil }
        var match: UInt64?
        var candidate = counter
        for step in 0...lookAhead {
            if ConstantTime.isEqual(self.code(counter: candidate), code), match == nil {
                match = candidate
            }
            guard step < lookAhead, candidate < UInt64.max else { break }
            candidate += 1
        }
        return match
    }

    func isWellFormed(_ code: String) -> Bool {
        code.utf8.count == digits && code.utf8.allSatisfy { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }
    }
}

/// Time-based one-time passwords (TOTP, RFC 6238), the six-digit codes of authenticator apps.
///
/// ```swift
/// let totp = try TOTP(base32Secret: "JBSWY3DPEHPK3PXP")
/// let code = try totp.code()                    // for example "492039"
/// let isValid = try totp.verify("492039")       // accepts the previous and next period too
/// ```
public struct TOTP: Sendable, Hashable {
    /// Accepted period lengths in seconds.
    public static let periodRange = 1...3600
    /// The largest window ``verify(_:at:window:)`` accepts.
    public static let maximumWindow = 10

    /// The seconds each code is valid for.
    public let period: Int
    let generator: HOTP

    /// The hash function.
    public var algorithm: OTPAlgorithm { generator.algorithm }
    /// The number of digits in a code.
    public var digits: Int { generator.digits }

    /// Creates a generator from secret bytes.
    ///
    /// - Parameters:
    ///   - secret: The shared secret, 10 to 1024 bytes.
    ///   - algorithm: The hash function.
    ///   - digits: The code length, 6 to 8.
    ///   - period: Seconds per code, 1 to 3600; 30 in most apps.
    public init(secret: Data, algorithm: OTPAlgorithm = .sha1, digits: Int = 6, period: Int = 30) throws(OTPError) {
        guard Self.periodRange.contains(period) else { throw .invalidPeriod(period) }
        self.generator = try HOTP(secret: secret, algorithm: algorithm, digits: digits)
        self.period = period
    }

    /// Creates a generator from a Base32 secret, the form shown under a QR code.
    ///
    /// Case, spaces, hyphens and trailing `=` are ignored.
    public init(base32Secret: String, algorithm: OTPAlgorithm = .sha1, digits: Int = 6, period: Int = 30) throws(OTPError) {
        guard base32Secret.utf8.count <= 2048, let secret = Base32.decode(base32Secret) else { throw .invalidSecret }
        try self.init(secret: secret, algorithm: algorithm, digits: digits, period: period)
    }

    /// Returns the time step that contains a date.
    ///
    /// - Throws: ``OTPError/invalidTime`` for a date before 1970, after the year 292 billion,
    ///   or built from a NaN or infinite interval.
    public func counter(at date: Date) throws(OTPError) -> UInt64 {
        let seconds = date.timeIntervalSince1970
        // UInt64(_:) traps on NaN, infinity and values out of range, so check before converting.
        guard seconds.isFinite, seconds >= 0, seconds < 0x1p63 else { throw .invalidTime }
        return UInt64(seconds) / UInt64(period)
    }

    /// Returns the code for a date.
    public func code(at date: Date = Date()) throws(OTPError) -> String {
        generator.code(counter: try counter(at: date))
    }

    /// Returns how many seconds the code of `date` stays valid, from 1 to ``period``.
    public func secondsRemaining(at date: Date = Date()) throws(OTPError) -> Int {
        _ = try counter(at: date)
        let elapsed = Int(UInt64(date.timeIntervalSince1970) % UInt64(period))
        return period - elapsed
    }

    /// Checks a code, accepting the periods around `date` to allow for clock drift.
    ///
    /// - Parameters:
    ///   - code: The code the user entered. Anything other than exactly ``digits`` ASCII digits
    ///     fails.
    ///   - date: The time of the check.
    ///   - window: How many periods before and after `date` to accept, 0 to ``maximumWindow``.
    ///     The default, 1, accepts codes up to one period early or late.
    /// - Returns: Whether the code matches. All candidate codes are compared in constant time.
    /// - Throws: ``OTPError/invalidWindow(_:)`` or ``OTPError/invalidTime``.
    public func verify(_ code: String, at date: Date = Date(), window: Int = 1) throws(OTPError) -> Bool {
        guard (0...Self.maximumWindow).contains(window) else { throw .invalidWindow(window) }
        let current = try counter(at: date)
        let first = current >= UInt64(window) ? current - UInt64(window) : 0
        return try generator.verify(code, counter: first, lookAhead: Int(current - first) + window) != nil
    }
}

/// An error from ``HOTP``, ``TOTP`` or ``OTPAuthURI``.
public enum OTPError: Error, Hashable, Sendable, LocalizedError {
    /// The secret is not valid Base32 or not 10 to 1024 bytes long.
    case invalidSecret
    /// The code length is outside 6...8.
    case invalidDigits(Int)
    /// The period is outside 1...3600 seconds.
    case invalidPeriod(Int)
    /// The verification window or look-ahead is outside its range.
    case invalidWindow(Int)
    /// The date cannot be turned into a time step.
    case invalidTime
    /// The `otpauth://` URI cannot be used.
    case invalidURI(String)

    public var errorDescription: String? {
        switch self {
        case .invalidSecret: "The secret is not valid Base32 of 10 to 1024 bytes."
        case .invalidDigits(let digits): "Codes must have 6 to 8 digits, not \(digits)."
        case .invalidPeriod(let period): "The period must be 1 to 3600 seconds, not \(period)."
        case .invalidWindow(let window): "The verification window \(window) is out of range."
        case .invalidTime: "The date is before 1970 or not a finite time."
        case .invalidURI(let reason): "The otpauth URI is not valid. \(reason)"
        }
    }
}
