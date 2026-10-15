import Foundation
import Security

/// Random bytes and tokens from the system's cryptographically secure generator.
///
/// Everything here reads from `SecRandomCopyBytes`, the generator Apple documents for keys,
/// nonces and session tokens. Use it instead of `UInt8.random(in:)` or `arc4random` when the
/// value must be unpredictable to an attacker.
///
/// ```swift
/// let salt = try SecureRandom.bytes(count: 16)
/// let sessionID = try SecureRandom.token()          // 43 base64url characters, 256 bits
/// ```
public enum SecureRandom {
    /// The largest number of bytes one call returns (1 MiB).
    ///
    /// The limit keeps a byte count that comes from outside the app (a configuration file, a
    /// server response) from allocating an arbitrary amount of memory.
    public static let maximumByteCount = 1 << 20

    /// Returns `count` random bytes.
    ///
    /// - Parameter count: The number of bytes, from 1 to ``maximumByteCount``.
    /// - Throws: ``SecureRandomError/invalidByteCount(_:)`` for a count outside that range, or
    ///   ``SecureRandomError/generationFailed(_:)`` if the system generator reports an error.
    public static func bytes(count: Int) throws(SecureRandomError) -> Data {
        guard (1...maximumByteCount).contains(count) else {
            throw .invalidByteCount(count)
        }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw .generationFailed(status)
        }
        return data
    }

    /// Returns a random token as text, for session identifiers, CSRF tokens or file names.
    ///
    /// - Parameters:
    ///   - byteCount: The number of random bytes behind the token, from 16 to 1024. The default,
    ///     32 bytes, is 256 bits of entropy.
    ///   - encoding: How the bytes are written. ``TokenEncoding/base64URL`` (the default) is safe
    ///     in URLs and file names.
    /// - Throws: ``SecureRandomError/invalidByteCount(_:)`` for a count outside 16...1024.
    public static func token(byteCount: Int = 32, encoding: TokenEncoding = .base64URL) throws(SecureRandomError) -> String {
        guard (16...1024).contains(byteCount) else {
            throw .invalidByteCount(byteCount)
        }
        let data = try bytes(count: byteCount)
        switch encoding {
        case .hex:
            return data.map { String(format: "%02x", $0) }.joined()
        case .base64URL:
            return Base64URL.encode(data)
        }
    }
}

/// The text encoding of a token made by ``SecureRandom/token(byteCount:encoding:)``.
public enum TokenEncoding: Sendable, Hashable {
    /// Lowercase hexadecimal, two characters per byte.
    case hex
    /// Base64 with the URL-safe alphabet (`-` and `_`) and no `=` padding (RFC 4648, section 5).
    case base64URL
}

/// An error from ``SecureRandom``.
public enum SecureRandomError: Error, Hashable, Sendable, LocalizedError {
    /// The requested number of bytes is outside the accepted range.
    case invalidByteCount(Int)
    /// `SecRandomCopyBytes` returned this status.
    case generationFailed(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidByteCount(let count):
            "\(count) is not a valid number of random bytes."
        case .generationFailed(let status):
            "The system random number generator failed with status \(status)."
        }
    }
}

/// Base64url without padding (RFC 4648, section 5).
enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String) -> Data? {
        guard text.utf8.allSatisfy({ isAlphabet($0) }) else { return nil }
        var base64 = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    private static func isAlphabet(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"):
            true
        default:
            false
        }
    }
}
