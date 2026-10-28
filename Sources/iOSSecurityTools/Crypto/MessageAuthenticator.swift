import CryptoKit
import Foundation

/// Computes and checks HMAC authentication codes (RFC 2104) with a shared key.
///
/// Use it when both sides hold the same secret: to check a webhook or callback signed by your
/// server, or to detect changes to a file or a cached response that the app wrote itself. The
/// check runs in constant time, so a wrong code does not reveal how many of its bytes matched.
///
/// ```swift
/// let authenticator = try MessageAuthenticator(key: SymmetricKey(data: webhookSecret))
/// guard authenticator.isValid(hexCode: request.signatureHeader, for: request.body) else {
///     throw WebhookError.badSignature
/// }
/// ```
public struct MessageAuthenticator: Sendable {
    /// The hash function of the HMAC.
    public enum Algorithm: Sendable, Hashable, CaseIterable {
        /// HMAC-SHA256, 32-byte codes.
        case sha256
        /// HMAC-SHA384, 48-byte codes.
        case sha384
        /// HMAC-SHA512, 64-byte codes.
        case sha512

        /// The length of a code in bytes.
        public var codeByteCount: Int {
            switch self {
            case .sha256: 32
            case .sha384: 48
            case .sha512: 64
            }
        }
    }

    /// The shortest key accepted, 128 bits. RFC 2104 §3 advises against keys shorter than the
    /// hash output; shorter ones are refused here because they are guessable.
    public static let minimumKeyByteCount = 16

    /// The algorithm of the codes.
    public let algorithm: Algorithm
    private let key: SymmetricKey

    /// Creates an authenticator.
    ///
    /// - Parameters:
    ///   - key: The shared key, at least ``minimumKeyByteCount`` bytes; ``DataCipher/generateKey()``
    ///     makes a suitable one.
    ///   - algorithm: The hash function, SHA-256 by default.
    /// - Throws: ``CipherError/invalidParameter(_:)`` for a key shorter than 128 bits.
    public init(key: SymmetricKey, algorithm: Algorithm = .sha256) throws(CipherError) {
        guard key.bitCount >= Self.minimumKeyByteCount * 8 else {
            throw .invalidParameter("An HMAC key must have at least \(Self.minimumKeyByteCount * 8) bits, not \(key.bitCount).")
        }
        self.key = key
        self.algorithm = algorithm
    }

    /// Returns the authentication code of data.
    public func code(for data: some DataProtocol) -> Data {
        switch algorithm {
        case .sha256: Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
        case .sha384: Data(HMAC<SHA384>.authenticationCode(for: data, using: key))
        case .sha512: Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
        }
    }

    /// Returns the authentication code of data as lowercase hexadecimal text, the form most
    /// webhook signature headers use.
    public func hexCode(for data: some DataProtocol) -> String {
        Hexadecimal.encode(code(for: data))
    }

    /// Returns whether `code` is the authentication code of `data`, comparing in constant time.
    ///
    /// A code of the wrong length returns `false`.
    public func isValid(_ code: some DataProtocol, for data: some DataProtocol) -> Bool {
        guard code.count == algorithm.codeByteCount else { return false }
        return ConstantTime.isEqual(self.code(for: data), code)
    }

    /// Returns whether hexadecimal text, upper or lower case, is the authentication code of
    /// `data`. Text that is not exactly the hexadecimal form of a code of this algorithm, with no
    /// spaces or prefix, returns `false`.
    public func isValid(hexCode: String, for data: some DataProtocol) -> Bool {
        guard hexCode.utf8.count == algorithm.codeByteCount * 2, let code = Hexadecimal.decode(hexCode) else {
            return false
        }
        return isValid(code, for: data)
    }
}

/// Base 16 text with no separators.
enum Hexadecimal {
    private static let digits = Array("0123456789abcdef".utf8)

    static func encode(_ data: some DataProtocol) -> String {
        var scalars: [UInt8] = []
        scalars.reserveCapacity(data.count * 2)
        for byte in data {
            scalars.append(digits[Int(byte >> 4)])
            scalars.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: scalars, as: UTF8.self)
    }

    /// Decodes an even number of hexadecimal digits, either case; nil for anything else.
    static func decode(_ text: String) -> Data? {
        let utf8 = Array(text.utf8)
        guard utf8.count.isMultiple(of: 2) else { return nil }
        var bytes = Data(capacity: utf8.count / 2)
        var index = 0
        while index < utf8.count {
            guard let high = value(of: utf8[index]), let low = value(of: utf8[index + 1]) else { return nil }
            bytes.append(high << 4 | low)
            index += 2
        }
        return bytes
    }

    private static func value(of digit: UInt8) -> UInt8? {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): digit - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): digit - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): digit - UInt8(ascii: "A") + 10
        default: nil
        }
    }
}
