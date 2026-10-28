import CryptoKit
import Foundation

/// A public key that checks signatures made by a ``SigningKey``, a ``SecureEnclaveKey`` or any
/// other Ed25519 or ECDSA P-256 implementation.
///
/// Read it from the form the other side gives you — raw bytes, DER or PEM — and keep it: a
/// public key is not a secret.
///
/// ```swift
/// let serverKey = try VerifyingKey(pemRepresentation: """
///     -----BEGIN PUBLIC KEY-----
///     MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
///     -----END PUBLIC KEY-----
///     """)
/// let trusted = serverKey.isValidSignature(signature, for: body)
/// ```
public struct VerifyingKey: Sendable, Hashable {
    private enum Storage: Sendable {
        case ed25519(Curve25519.Signing.PublicKey)
        case p256(P256.Signing.PublicKey)
    }

    /// The longest PEM text read, far above the 160 characters of a P-256 key, so that a value
    /// from a server or file is not decoded without bound.
    public static let maximumPEMLength = 4096

    /// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE, the algorithm
    /// identifier 1.3.101.112, and a BIT STRING of 33 bytes with no unused bits.
    private static let ed25519DERPrefix: [UInt8] = [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]

    private let storage: Storage

    /// Wraps a CryptoKit Ed25519 public key.
    public init(_ key: Curve25519.Signing.PublicKey) {
        storage = .ed25519(key)
    }

    /// Wraps a CryptoKit P-256 public key, such as ``SecureEnclaveKey/publicKey``.
    public init(_ key: P256.Signing.PublicKey) {
        storage = .p256(key)
    }

    /// Reads a key from its ``rawRepresentation``.
    ///
    /// - Throws: ``SignatureError/invalidKey(_:)`` when the bytes are not a public key of that
    ///   algorithm: 32 bytes for Ed25519; for P-256, the 64-byte `x` and `y` of a point on the
    ///   curve.
    public init(rawRepresentation: some ContiguousBytes, algorithm: SignatureAlgorithm) throws(SignatureError) {
        let bytes = rawRepresentation.withUnsafeBytes { Data($0) }
        do {
            switch algorithm {
            case .ed25519: storage = .ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: bytes))
            case .p256:
                // Read through the X9.63 form: CryptoKit's raw initializer accepts 64 bytes that are
                // not a point on the curve, such as all zeros; the X9.63 one checks the point.
                guard bytes.count == 64 else { throw SignatureError.invalidKey("") }
                storage = .p256(try P256.Signing.PublicKey(x963Representation: Data([0x04]) + bytes))
            }
        } catch {
            throw .invalidKey("\(bytes.count) bytes are not a \(algorithm.displayName) public key.")
        }
    }

    /// Reads a DER-encoded SubjectPublicKeyInfo, the form inside a certificate and inside PEM.
    ///
    /// The algorithm comes from the encoding: Ed25519 (RFC 8410) or an EC key on P-256.
    ///
    /// - Throws: ``SignatureError/invalidKey(_:)`` for any other encoding or algorithm.
    public init(derRepresentation: some DataProtocol) throws(SignatureError) {
        let bytes = [UInt8](derRepresentation)
        if bytes.count == Self.ed25519DERPrefix.count + 32, bytes.starts(with: Self.ed25519DERPrefix) {
            try self.init(rawRepresentation: Data(bytes.dropFirst(Self.ed25519DERPrefix.count)), algorithm: .ed25519)
            return
        }
        guard let key = try? P256.Signing.PublicKey(derRepresentation: bytes) else {
            throw .invalidKey("\(bytes.count) bytes are not the DER form of an Ed25519 or P-256 public key.")
        }
        self.init(key)
    }

    /// Reads a PEM `PUBLIC KEY` block, as `openssl pkey -pubout` writes it.
    ///
    /// - Throws: ``SignatureError/invalidKey(_:)`` for text longer than ``maximumPEMLength``,
    ///   another block type, invalid Base64 or a key that ``init(derRepresentation:)`` rejects.
    public init(pemRepresentation: String) throws(SignatureError) {
        guard pemRepresentation.utf8.count <= Self.maximumPEMLength else {
            throw .invalidKey("The PEM text is longer than \(Self.maximumPEMLength) bytes.")
        }
        let header = "-----BEGIN PUBLIC KEY-----"
        let footer = "-----END PUBLIC KEY-----"
        let text = pemRepresentation.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(header), text.hasSuffix(footer), text.count > header.count + footer.count else {
            throw .invalidKey("The text is not a PEM block of type PUBLIC KEY.")
        }
        let body = text.dropFirst(header.count).dropLast(footer.count).filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: String(body)) else {
            throw .invalidKey("The PEM body is not Base64.")
        }
        try self.init(derRepresentation: der)
    }

    /// The algorithm of the key.
    public var algorithm: SignatureAlgorithm {
        switch storage {
        case .ed25519: .ed25519
        case .p256: .p256
        }
    }

    /// The key bytes: 32 for Ed25519; for P-256, `x` followed by `y`, 64 bytes.
    public var rawRepresentation: Data {
        switch storage {
        case .ed25519(let key): key.rawRepresentation
        case .p256(let key): key.rawRepresentation
        }
    }

    /// The DER-encoded SubjectPublicKeyInfo.
    public var derRepresentation: Data {
        switch storage {
        case .ed25519(let key): Data(Self.ed25519DERPrefix) + key.rawRepresentation
        case .p256(let key): key.derRepresentation
        }
    }

    /// The PEM `PUBLIC KEY` block, with 64 characters per line.
    public var pemRepresentation: String {
        let body = derRepresentation.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(body)\n-----END PUBLIC KEY-----"
    }

    /// Returns whether `signature` is a valid signature of `data` by the private key of this key.
    ///
    /// A P-256 signature may be the 64-byte `r` and `s` that ``SigningKey`` writes or the DER form
    /// that ``SecureEnclaveKey`` and the Security framework write. Any other input, including an
    /// empty or truncated signature, returns `false`.
    public func isValidSignature(_ signature: some DataProtocol, for data: some DataProtocol) -> Bool {
        switch storage {
        case .ed25519(let key):
            let bytes = Data(signature)
            return bytes.count == 64 && key.isValidSignature(bytes, for: Data(data))
        case .p256(let key):
            let bytes = Data(signature)
            if bytes.count == 64, let raw = try? P256.Signing.ECDSASignature(rawRepresentation: bytes), key.isValidSignature(raw, for: data) {
                return true
            }
            guard let der = try? P256.Signing.ECDSASignature(derRepresentation: bytes) else { return false }
            return key.isValidSignature(der, for: data)
        }
    }

    public static func == (lhs: VerifyingKey, rhs: VerifyingKey) -> Bool {
        lhs.algorithm == rhs.algorithm && lhs.rawRepresentation == rhs.rawRepresentation
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(algorithm)
        hasher.combine(rawRepresentation)
    }
}
