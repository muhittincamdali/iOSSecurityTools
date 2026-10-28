import CryptoKit
import Foundation

/// A digital signature algorithm.
public enum SignatureAlgorithm: String, Sendable, Hashable, CaseIterable, Codable {
    /// Ed25519 (RFC 8032): 32-byte keys and 64-byte signatures. The default for new keys.
    case ed25519
    /// ECDSA over the NIST P-256 curve with SHA-256 (the JOSE `ES256` algorithm): 64-byte
    /// signatures, `r` followed by `s`. Use it when the other side requires P-256, for example to
    /// match a ``SecureEnclaveKey``.
    case p256
}

/// A private key that signs data, kept in memory.
///
/// A signature lets anyone with the matching ``VerifyingKey`` check that the data was signed by
/// this key and has not changed since. Sign a request body, a file you export or a message, and
/// send the public key to the other side once.
///
/// ```swift
/// let signingKey = SigningKey()                          // Ed25519
/// let signature = try signingKey.signature(for: Data("transfer 25 EUR".utf8))
///
/// let publicKey = signingKey.publicKey                   // share this one
/// publicKey.isValidSignature(signature, for: Data("transfer 25 EUR".utf8))   // true
/// ```
///
/// The key lives in the app's memory. Store it with ``Keychain/signingKey(forKey:algorithm:)``,
/// which creates it on first use; for a P-256 key that never leaves the hardware, use
/// ``SecureEnclaveKey`` instead. Printing a signing key, with `print`, string interpolation or
/// `dump`, shows its algorithm and never its bytes.
public struct SigningKey: Sendable {
    private enum Storage: Sendable {
        case ed25519(Curve25519.Signing.PrivateKey)
        case p256(P256.Signing.PrivateKey)
    }

    private let storage: Storage

    /// Creates a new random key.
    public init(algorithm: SignatureAlgorithm = .ed25519) {
        switch algorithm {
        case .ed25519: storage = .ed25519(Curve25519.Signing.PrivateKey())
        case .p256: storage = .p256(P256.Signing.PrivateKey())
        }
    }

    /// Reads a key from its ``rawRepresentation``.
    ///
    /// - Throws: ``SignatureError/invalidKey(_:)`` when the bytes are not a key of that algorithm:
    ///   32 bytes for both, and for P-256 a scalar between 1 and the order of the curve.
    public init(rawRepresentation: some ContiguousBytes, algorithm: SignatureAlgorithm) throws(SignatureError) {
        let bytes = rawRepresentation.withUnsafeBytes { Data($0) }
        do {
            switch algorithm {
            case .ed25519: storage = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: bytes))
            case .p256: storage = .p256(try P256.Signing.PrivateKey(rawRepresentation: bytes))
            }
        } catch {
            throw .invalidKey("\(bytes.count) bytes are not a \(algorithm.displayName) private key.")
        }
    }

    /// Wraps a CryptoKit Ed25519 key.
    public init(_ key: Curve25519.Signing.PrivateKey) {
        storage = .ed25519(key)
    }

    /// Wraps a CryptoKit P-256 key.
    public init(_ key: P256.Signing.PrivateKey) {
        storage = .p256(key)
    }

    /// The algorithm of the key.
    public var algorithm: SignatureAlgorithm {
        switch storage {
        case .ed25519: .ed25519
        case .p256: .p256
        }
    }

    /// The 32 private key bytes. Anyone who has them can sign as you: keep them in the keychain.
    public var rawRepresentation: Data {
        switch storage {
        case .ed25519(let key): key.rawRepresentation
        case .p256(let key): key.rawRepresentation
        }
    }

    /// The public key that verifies this key's signatures.
    public var publicKey: VerifyingKey {
        switch storage {
        case .ed25519(let key): VerifyingKey(key.publicKey)
        case .p256(let key): VerifyingKey(key.publicKey)
        }
    }

    /// Signs data.
    ///
    /// Both algorithms add randomness, so two signatures of the same data differ; each one
    /// verifies.
    ///
    /// - Returns: A 64-byte signature. For P-256 this is `r` followed by `s` (the form JOSE and
    ///   WebCrypto use); `P256.Signing.ECDSASignature(rawRepresentation:)` converts it to DER.
    /// - Throws: ``SignatureError/signingFailed(_:)`` when CryptoKit cannot sign.
    public func signature(for data: some DataProtocol) throws(SignatureError) -> Data {
        do {
            switch storage {
            case .ed25519(let key): return try key.signature(for: Data(data))
            case .p256(let key): return try key.signature(for: data).rawRepresentation
            }
        } catch {
            throw .signingFailed(String(describing: error))
        }
    }
}

extension SigningKey: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SigningKey(\(algorithm.rawValue), <redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["algorithm": algorithm], displayStyle: .struct) }
}

/// An error from ``SigningKey`` or ``VerifyingKey``.
public enum SignatureError: Error, Hashable, Sendable, LocalizedError {
    /// The bytes or text are not a key of the expected algorithm.
    case invalidKey(String)
    /// CryptoKit could not sign.
    case signingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKey(let reason): "The key is not valid. \(reason)"
        case .signingFailed(let reason): "Signing failed: \(reason)"
        }
    }
}

extension SignatureAlgorithm {
    var displayName: String {
        switch self {
        case .ed25519: "Ed25519"
        case .p256: "P-256"
        }
    }
}
